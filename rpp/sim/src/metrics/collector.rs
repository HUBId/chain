use std::cmp::Ordering;
use std::collections::{HashMap, HashSet};
use std::time::Instant;

use rpp_p2p::vendor::gossipsub::types::FailedMessages;
use rpp_p2p::vendor::PeerId;
use serde::{Deserialize, Serialize};

use crate::metrics::reduce::{
    calculate_percentiles, BandwidthMetrics, GossipBackpressureMetrics, RecoveryMetrics,
    SimulationSummary,
};

#[derive(Debug, Clone)]
pub enum SimEvent {
    Publish {
        peer_id: PeerId,
        message_id: String,
        timestamp: Instant,
    },
    Receive {
        peer_id: PeerId,
        propagation_source: PeerId,
        message_id: String,
        timestamp: Instant,
        duplicate: bool,
    },
    MeshChange {
        peer_id: PeerId,
        peer: PeerId,
        topic: String,
        action: MeshAction,
        timestamp: Instant,
    },
    Fault {
        kind: FaultEvent,
        detail: Option<String>,
        timestamp: Instant,
    },
    SlowPeer {
        peer_id: PeerId,
        slow_peer: PeerId,
        failed_messages: FailedMessages,
        timestamp: Instant,
    },
}

#[derive(Debug, Clone, Copy)]
pub enum MeshAction {
    Graft,
    Prune,
    Subscribe,
    Unsubscribe,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct MeshChangeRecord {
    pub node: String,
    pub peer: String,
    pub topic: String,
    pub action: String,
    pub timestamp_ms: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct FaultRecord {
    pub kind: String,
    pub detail: Option<String>,
    pub timestamp_ms: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SlowPeerRecord {
    pub node: String,
    pub peer: String,
    pub publish_failed: usize,
    pub forward_failed: usize,
    pub queue_full: usize,
    pub timeout: usize,
    pub timestamp_ms: f64,
}

pub struct Collector {
    start: Instant,
    publications: HashMap<String, Instant>,
    latencies_ms: Vec<f64>,
    total_publishes: usize,
    total_receives: usize,
    duplicates: usize,
    chunk_retries: usize,
    mesh_changes: Vec<MeshChangeRecord>,
    faults: Vec<FaultRecord>,
    pending_partition_end: Option<Instant>,
    resume_latencies_ms: Vec<f64>,
    slow_peer_records: Vec<SlowPeerRecord>,
    slow_peer_unique: HashSet<String>,
    slow_peer_publish_failures: usize,
    slow_peer_forward_failures: usize,
    slow_peer_queue_full: usize,
    slow_peer_timeouts: usize,
}

impl Collector {
    pub fn new(start: Instant) -> Self {
        Self {
            start,
            publications: HashMap::new(),
            latencies_ms: Vec::new(),
            total_publishes: 0,
            total_receives: 0,
            duplicates: 0,
            chunk_retries: 0,
            mesh_changes: Vec::new(),
            faults: Vec::new(),
            pending_partition_end: None,
            resume_latencies_ms: Vec::new(),
            slow_peer_records: Vec::new(),
            slow_peer_unique: HashSet::new(),
            slow_peer_publish_failures: 0,
            slow_peer_forward_failures: 0,
            slow_peer_queue_full: 0,
            slow_peer_timeouts: 0,
        }
    }

    pub fn ingest(&mut self, event: SimEvent) {
        match event {
            SimEvent::Publish {
                peer_id,
                message_id,
                timestamp,
            } => {
                self.total_publishes += 1;
                self.publications.insert(message_id, timestamp);
                tracing::trace!(target = "rpp::sim::metrics", %peer_id, "publish recorded");
            }
            SimEvent::Receive {
                peer_id,
                message_id,
                timestamp,
                duplicate,
                ..
            } => {
                self.total_receives += 1;
                if duplicate {
                    self.duplicates += 1;
                    self.chunk_retries += 1;
                }
                if let Some(published_at) = self.publications.get(&message_id) {
                    let delta = timestamp.duration_since(*published_at).as_secs_f64() * 1_000.0;
                    self.latencies_ms.push(delta);
                }
                if let Some(partition_end) = self.pending_partition_end.take() {
                    let resume_latency =
                        timestamp.duration_since(partition_end).as_secs_f64() * 1_000.0;
                    self.resume_latencies_ms.push(resume_latency);
                }
                tracing::trace!(target = "rpp::sim::metrics", %peer_id, duplicate, "receive recorded");
            }
            SimEvent::MeshChange {
                peer_id,
                peer,
                topic,
                action,
                timestamp,
            } => {
                let timestamp_ms = timestamp.duration_since(self.start).as_secs_f64() * 1_000.0;
                self.mesh_changes.push(MeshChangeRecord {
                    node: peer_id.to_string(),
                    peer: peer.to_string(),
                    topic,
                    action: mesh_action_label(action).to_string(),
                    timestamp_ms,
                });
            }
            SimEvent::Fault {
                kind,
                detail,
                timestamp,
            } => {
                if matches!(kind, FaultEvent::PartitionStart) {
                    self.pending_partition_end = None;
                }
                if matches!(kind, FaultEvent::PartitionEnd) {
                    self.pending_partition_end = Some(timestamp);
                }
                let timestamp_ms = timestamp.duration_since(self.start).as_secs_f64() * 1_000.0;
                self.faults.push(FaultRecord {
                    kind: fault_event_label(kind).to_string(),
                    detail,
                    timestamp_ms,
                });
            }
            SimEvent::SlowPeer {
                peer_id,
                slow_peer,
                failed_messages,
                timestamp,
            } => {
                let timestamp_ms = timestamp.duration_since(self.start).as_secs_f64() * 1_000.0;
                let queue_full = failed_messages.total_queue_full();
                self.slow_peer_publish_failures = self
                    .slow_peer_publish_failures
                    .saturating_add(failed_messages.publish);
                self.slow_peer_forward_failures = self
                    .slow_peer_forward_failures
                    .saturating_add(failed_messages.forward);
                self.slow_peer_queue_full = self.slow_peer_queue_full.saturating_add(queue_full);
                self.slow_peer_timeouts = self
                    .slow_peer_timeouts
                    .saturating_add(failed_messages.timeout);
                self.slow_peer_unique.insert(slow_peer.to_string());
                self.slow_peer_records.push(SlowPeerRecord {
                    node: peer_id.to_string(),
                    peer: slow_peer.to_string(),
                    publish_failed: failed_messages.publish,
                    forward_failed: failed_messages.forward,
                    queue_full,
                    timeout: failed_messages.timeout,
                    timestamp_ms,
                });
            }
        }
    }

    pub fn finalize(mut self) -> SimulationSummary {
        self.latencies_ms
            .sort_by(|a, b| a.partial_cmp(b).unwrap_or(Ordering::Equal));
        let propagation = calculate_percentiles(&self.latencies_ms);
        let recovery = if !self.resume_latencies_ms.is_empty() || self.chunk_retries > 0 {
            let max_resume_latency =
                self.resume_latencies_ms
                    .iter()
                    .cloned()
                    .fold(None, |acc: Option<f64>, value| match acc {
                        Some(current) => Some(current.max(value)),
                        None => Some(value),
                    });
            let mean_resume_latency = if self.resume_latencies_ms.is_empty() {
                None
            } else {
                Some(
                    self.resume_latencies_ms.iter().sum::<f64>()
                        / self.resume_latencies_ms.len() as f64,
                )
            };
            Some(RecoveryMetrics {
                resume_latencies_ms: self.resume_latencies_ms.clone(),
                max_resume_latency_ms: max_resume_latency,
                mean_resume_latency_ms: mean_resume_latency,
            })
        } else {
            None
        };
        let bandwidth = if self.slow_peer_records.is_empty() {
            None
        } else {
            Some(BandwidthMetrics {
                throttled_peers: self.slow_peer_unique.len(),
                slow_peer_events: self.slow_peer_records.len(),
            })
        };

        let gossip_backpressure = if self.slow_peer_records.is_empty() {
            None
        } else {
            Some(GossipBackpressureMetrics {
                events: self.slow_peer_records.len(),
                unique_peers: self.slow_peer_unique.len(),
                queue_full_messages: self.slow_peer_queue_full,
                publish_failures: self.slow_peer_publish_failures,
                forward_failures: self.slow_peer_forward_failures,
                timeout_failures: self.slow_peer_timeouts,
            })
        };

        SimulationSummary {
            total_publishes: self.total_publishes,
            total_receives: self.total_receives,
            duplicates: self.duplicates,
            chunk_retries: self.chunk_retries,
            propagation,
            mesh_changes: self.mesh_changes,
            faults: self.faults,
            recovery,
            bandwidth,
            gossip_backpressure,
            slow_peer_records: self.slow_peer_records,
            comparison: None,
        }
    }
}

fn mesh_action_label(action: MeshAction) -> &'static str {
    match action {
        MeshAction::Graft => "graft",
        MeshAction::Prune => "prune",
        MeshAction::Subscribe => "subscribe",
        MeshAction::Unsubscribe => "unsubscribe",
    }
}

#[derive(Debug, Clone, Copy)]
pub enum FaultEvent {
    PartitionStart,
    PartitionEnd,
    ChurnDown,
    ChurnUp,
    ByzantineSpam,
}

fn fault_event_label(event: FaultEvent) -> &'static str {
    match event {
        FaultEvent::PartitionStart => "partition_start",
        FaultEvent::PartitionEnd => "partition_end",
        FaultEvent::ChurnDown => "churn_down",
        FaultEvent::ChurnUp => "churn_up",
        FaultEvent::ByzantineSpam => "byzantine_spam",
    }
}
