use std::collections::VecDeque;
use std::time::{Duration, Instant};

use crate::topics::GossipTopic;
use crate::vendor::PeerId;

/// Error type returned when witness gossip payloads cannot be queued.
#[derive(Debug, thiserror::Error)]
pub enum WitnessPipelineError {
    /// The topic is not supported by the witness pipelines.
    #[error("unsupported witness topic: {0:?}")]
    UnsupportedTopic(GossipTopic),
    /// The configured rate limit has been exceeded.
    #[error("witness topic {topic:?} rate limited; retry after {retry_after:?}")]
    RateLimited {
        /// Topic that hit the rate limiter.
        topic: GossipTopic,
        /// Suggested wait time before retrying.
        retry_after: Duration,
    },
}

#[derive(Debug, Clone)]
pub struct WitnessChannelConfig {
    pub capacity: usize,
    pub interval: Duration,
    pub max_messages: u64,
}

impl WitnessChannelConfig {
    pub fn new(capacity: usize, interval: Duration, max_messages: u64) -> Self {
        Self {
            capacity: capacity.max(1),
            interval,
            max_messages: max_messages.max(1),
        }
    }
}

#[derive(Debug, Clone)]
pub struct WitnessPipelineConfig {
    pub proofs: WitnessChannelConfig,
    pub meta: WitnessChannelConfig,
}

impl Default for WitnessPipelineConfig {
    fn default() -> Self {
        Self {
            proofs: WitnessChannelConfig::new(256, Duration::from_millis(250), 128),
            meta: WitnessChannelConfig::new(128, Duration::from_millis(250), 64),
        }
    }
}

#[derive(Debug, Clone)]
pub struct WitnessMessage {
    pub peer: PeerId,
    pub payload: Vec<u8>,
    pub received_at: Instant,
}

#[derive(Debug)]
struct TokenBucket {
    capacity: u64,
    tokens: u64,
    refill_interval: Duration,
    last_refill: Instant,
}

impl TokenBucket {
    fn new(capacity: u64, refill_interval: Duration) -> Self {
        let capacity = capacity.max(1);
        Self {
            capacity,
            tokens: capacity,
            refill_interval,
            last_refill: Instant::now(),
        }
    }

    fn take(&mut self) -> bool {
        self.refill();
        if self.tokens == 0 {
            return false;
        }
        self.tokens -= 1;
        true
    }

    fn refill(&mut self) {
        let elapsed = self.last_refill.elapsed();
        if elapsed < self.refill_interval {
            return;
        }
        let periods = (elapsed.as_nanos() / self.refill_interval.as_nanos()).max(1);
        let restored = periods as u64;
        self.tokens = (self.tokens + restored).min(self.capacity);
        self.last_refill = Instant::now();
    }

    fn retry_after(&self) -> Duration {
        self.refill_interval
            .saturating_sub(self.last_refill.elapsed())
    }
}

#[derive(Debug)]
struct WitnessChannel {
    topic: GossipTopic,
    buffer: VecDeque<WitnessMessage>,
    capacity: usize,
    limiter: TokenBucket,
}

impl WitnessChannel {
    fn new(topic: GossipTopic, config: &WitnessChannelConfig) -> Self {
        Self {
            topic,
            buffer: VecDeque::with_capacity(config.capacity),
            capacity: config.capacity,
            limiter: TokenBucket::new(config.max_messages, config.interval),
        }
    }

    fn ingest(&mut self, peer: PeerId, payload: Vec<u8>) -> Result<(), WitnessPipelineError> {
        if !self.limiter.take() {
            return Err(WitnessPipelineError::RateLimited {
                topic: self.topic,
                retry_after: self.limiter.retry_after(),
            });
        }
        if self.buffer.len() == self.capacity {
            self.buffer.pop_front();
        }
        self.buffer.push_back(WitnessMessage {
            peer,
            payload,
            received_at: Instant::now(),
        });
        Ok(())
    }

    fn pop(&mut self) -> Option<WitnessMessage> {
        self.buffer.pop_front()
    }

    fn len(&self) -> usize {
        self.buffer.len()
    }

    fn is_empty(&self) -> bool {
        self.buffer.is_empty()
    }
}

#[derive(Debug)]
pub struct WitnessGossipPipelines {
    proofs: WitnessChannel,
    meta: WitnessChannel,
}

impl WitnessGossipPipelines {
    pub fn new(config: WitnessPipelineConfig) -> Self {
        Self {
            proofs: WitnessChannel::new(GossipTopic::WitnessProofs, &config.proofs),
            meta: WitnessChannel::new(GossipTopic::WitnessMeta, &config.meta),
        }
    }

    pub fn ingest(
        &mut self,
        topic: GossipTopic,
        peer: PeerId,
        payload: Vec<u8>,
    ) -> Result<(), WitnessPipelineError> {
        match topic {
            GossipTopic::WitnessProofs => self.proofs.ingest(peer, payload),
            GossipTopic::WitnessMeta => self.meta.ingest(peer, payload),
            _ => Err(WitnessPipelineError::UnsupportedTopic(topic)),
        }
    }

    pub fn pop(&mut self, topic: GossipTopic) -> Option<WitnessMessage> {
        match topic {
            GossipTopic::WitnessProofs => self.proofs.pop(),
            GossipTopic::WitnessMeta => self.meta.pop(),
            _ => None,
        }
    }

    pub fn len(&self, topic: GossipTopic) -> usize {
        match topic {
            GossipTopic::WitnessProofs => self.proofs.len(),
            GossipTopic::WitnessMeta => self.meta.len(),
            _ => 0,
        }
    }

    pub fn is_empty(&self, topic: GossipTopic) -> bool {
        match topic {
            GossipTopic::WitnessProofs => self.proofs.is_empty(),
            GossipTopic::WitnessMeta => self.meta.is_empty(),
            _ => true,
        }
    }
}
