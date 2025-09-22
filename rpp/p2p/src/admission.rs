use std::collections::{HashMap, HashSet};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use crate::gossip::GossipTopic;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum TierLevel {
    Observer = 0,
    Tier1 = 1,
    Tier2 = 2,
    Tier3 = 3,
    Tier4 = 4,
}

impl TierLevel {
    pub fn from_score(score: f64) -> TierLevel {
        match score {
            s if s >= 3.5 => TierLevel::Tier4,
            s if s >= 2.5 => TierLevel::Tier3,
            s if s >= 1.5 => TierLevel::Tier2,
            s if s >= 0.5 => TierLevel::Tier1,
            _ => TierLevel::Observer,
        }
    }

    pub fn required_for_topic(topic: GossipTopic) -> TierLevel {
        match topic {
            GossipTopic::Blocks | GossipTopic::Votes => TierLevel::Tier3,
            GossipTopic::Proofs => TierLevel::Tier1,
            GossipTopic::Snapshots => TierLevel::Tier2,
            GossipTopic::Meta => TierLevel::Observer,
        }
    }
}

#[derive(Debug, Clone)]
pub struct PeerReputation {
    pub peer_id: String,
    pub score: f64,
    pub tier: TierLevel,
    pub uptime: Duration,
    pub last_updated: Instant,
}

impl PeerReputation {
    pub fn new(peer_id: impl Into<String>, score: f64, uptime: Duration) -> Self {
        let peer_id = peer_id.into();
        let tier = TierLevel::from_score(score);
        Self {
            peer_id,
            score,
            tier,
            uptime,
            last_updated: Instant::now(),
        }
    }

    pub fn set_score(&mut self, score: f64) {
        self.score = score;
        self.tier = TierLevel::from_score(score);
        self.last_updated = Instant::now();
    }
}

#[derive(Debug, Clone)]
pub struct ReputationEvent {
    pub peer_id: String,
    pub delta: f64,
    pub description: String,
}

impl ReputationEvent {
    pub fn new(peer_id: impl Into<String>, delta: f64, description: impl Into<String>) -> Self {
        Self {
            peer_id: peer_id.into(),
            delta,
            description: description.into(),
        }
    }
}

#[derive(Debug)]
struct TokenBucket {
    capacity: u32,
    tokens: u32,
    refill_interval: Duration,
    last_refill: Instant,
}

impl TokenBucket {
    fn new(capacity: u32, refill_interval: Duration) -> Self {
        Self {
            capacity,
            tokens: capacity,
            refill_interval,
            last_refill: Instant::now(),
        }
    }

    fn consume(&mut self, amount: u32) -> bool {
        self.refill();
        if self.tokens >= amount {
            self.tokens -= amount;
            true
        } else {
            false
        }
    }

    fn refill(&mut self) {
        let now = Instant::now();
        if now.duration_since(self.last_refill) >= self.refill_interval {
            self.tokens = self.capacity;
            self.last_refill = now;
        }
    }
}

#[derive(Debug)]
pub struct AdmissionControl {
    peers: Mutex<HashMap<String, PeerReputation>>,
    quarantine: Mutex<HashSet<String>>,
    rate_limits: Mutex<HashMap<String, TokenBucket>>,
    default_bucket: TokenBucket,
}

impl AdmissionControl {
    pub fn new() -> Self {
        Self {
            peers: Mutex::new(HashMap::new()),
            quarantine: Mutex::new(HashSet::new()),
            rate_limits: Mutex::new(HashMap::new()),
            default_bucket: TokenBucket::new(32, Duration::from_secs(1)),
        }
    }

    pub fn register_peer(&self, peer: PeerReputation) {
        let mut peers = self.peers.lock().expect("peers mutex poisoned");
        peers.insert(peer.peer_id.clone(), peer);
    }

    pub fn record_event(&self, event: ReputationEvent) {
        let mut peers = self.peers.lock().expect("peers mutex poisoned");
        let entry = peers.entry(event.peer_id.clone()).or_insert_with(|| {
            PeerReputation::new(event.peer_id.clone(), 0.0, Duration::from_secs(0))
        });
        let new_score = (entry.score + event.delta).clamp(0.0, 5.0);
        entry.set_score(new_score);
    }

    pub fn reputation(&self, peer_id: &str) -> Option<PeerReputation> {
        self.peers
            .lock()
            .expect("peers mutex poisoned")
            .get(peer_id)
            .cloned()
    }

    pub fn quarantine(&self, peer_id: impl Into<String>) {
        self.quarantine
            .lock()
            .expect("quarantine mutex poisoned")
            .insert(peer_id.into());
    }

    pub fn is_quarantined(&self, peer_id: &str) -> bool {
        self.quarantine
            .lock()
            .expect("quarantine mutex poisoned")
            .contains(peer_id)
    }

    pub fn check_publish(&self, peer_id: &str, topic: GossipTopic) -> bool {
        if self.is_quarantined(peer_id) {
            return false;
        }

        let required_tier = TierLevel::required_for_topic(topic);
        let tier_ok = self
            .peers
            .lock()
            .expect("peers mutex poisoned")
            .get(peer_id)
            .map(|r| r.tier >= required_tier)
            .unwrap_or(false);
        if !tier_ok {
            return false;
        }

        let mut limits = self
            .rate_limits
            .lock()
            .expect("rate limit mutex poisoned");
        let bucket = limits
            .entry(peer_id.to_string())
            .or_insert_with(|| self.default_bucket.clone());
        bucket.consume(1)
    }
}

impl Clone for TokenBucket {
    fn clone(&self) -> Self {
        Self {
            capacity: self.capacity,
            tokens: self.tokens,
            refill_interval: self.refill_interval,
            last_refill: Instant::now(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enforces_tier_requirements() {
        let admission = AdmissionControl::new();
        admission.register_peer(PeerReputation::new("alice", 3.0, Duration::from_secs(10)));
        assert!(admission.check_publish("alice", GossipTopic::Blocks));
        assert!(admission.check_publish("alice", GossipTopic::Votes));
        assert!(admission.check_publish("alice", GossipTopic::Proofs));

        assert!(!admission.check_publish("unknown", GossipTopic::Proofs));
    }

    #[test]
    fn enforces_quarantine() {
        let admission = AdmissionControl::new();
        admission.register_peer(PeerReputation::new("carol", 2.0, Duration::from_secs(5)));
        assert!(admission.check_publish("carol", GossipTopic::Proofs));
        admission.quarantine("carol");
        assert!(!admission.check_publish("carol", GossipTopic::Proofs));
    }
}
