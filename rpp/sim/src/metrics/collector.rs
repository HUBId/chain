use std::cmp::Ordering;
use std::collections::{HashMap, HashSet};
use std::time::Instant;

use rpp_p2p::vendor::gossipsub::types::FailedMessages;
use rpp_p2p::vendor::PeerId;
use serde::{Deserialize, Serialize};

use crate::metrics::reduce::{
    calculate_percentiles, BandwidthMetrics, GossipBackpressureMetrics, PeerTrafficRecord,
    RecoveryMetrics, ReplayGuardDrops, ReplayGuardMetrics, ReplayWindowFill, ResourceUsageMetrics,
    SimulationSummary,
};
use rpp_p2p::peerstore::peer_class::PeerClass;

#[derive(Debug, Clone)]
pub enum SimEvent {
    Publish {
        peer_id: PeerId,
        message_id: String,
        payload_bytes: usize,
        timestamp: Instant,
    },
    Receive {
        peer_id: PeerId,
        propagation_source: PeerId,
        message_id: String,
        timestamp: Instant,
        duplicate: bool,
        peer_class: rpp_p2p::peerstore::peer_class::PeerClass,
        payload_bytes: usize,
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
    replay_trusted_drops: usize,
    replay_untrusted_drops: usize,
    replay_trusted_receives: usize,
    replay_untrusted_receives: usize,
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
    resource_usage: Option<ResourceUsageMetrics>,
    peer_traffic: HashMap<String, PeerTraffic>,
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
            replay_trusted_drops: 0,
            replay_untrusted_drops: 0,
            replay_trusted_receives: 0,
            replay_untrusted_receives: 0,
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
            resource_usage: None,
            peer_traffic: HashMap::new(),
        }
    }

    pub fn ingest(&mut self, event: SimEvent) {
        match event {
            SimEvent::Publish {
                peer_id,
                message_id,
                payload_bytes,
                timestamp,
            } => {
                self.total_publishes += 1;
                self.publications.insert(message_id, timestamp);
                self.record_outbound(&peer_id, payload_bytes);
                tracing::trace!(target = "rpp::sim::metrics", %peer_id, "publish recorded");
            }
            SimEvent::Receive {
                peer_id,
                message_id,
                payload_bytes,
                timestamp,
                duplicate,
                peer_class,
                ..
            } => {
                self.total_receives += 1;
                match peer_class {
                    rpp_p2p::peerstore::peer_class::PeerClass::Trusted => {
                        self.replay_trusted_receives =
                            self.replay_trusted_receives.saturating_add(1);
                    }
                    rpp_p2p::peerstore::peer_class::PeerClass::Untrusted => {
                        self.replay_untrusted_receives =
                            self.replay_untrusted_receives.saturating_add(1);
                    }
                }
                if duplicate {
                    self.duplicates += 1;
                    self.chunk_retries += 1;
                    match peer_class {
                        rpp_p2p::peerstore::peer_class::PeerClass::Trusted => {
                            self.replay_trusted_drops = self.replay_trusted_drops.saturating_add(1);
                        }
                        rpp_p2p::peerstore::peer_class::PeerClass::Untrusted => {
                            self.replay_untrusted_drops =
                                self.replay_untrusted_drops.saturating_add(1);
                        }
                    }
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
                self.record_inbound(&peer_id, payload_bytes);
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

    pub fn record_resource_usage(&mut self, usage: ResourceUsageMetrics) {
        self.resource_usage = Some(usage);
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

        let replay_guard = {
            let trusted_receives = self.replay_trusted_receives as f64;
            let untrusted_receives = self.replay_untrusted_receives as f64;
            let has_signal = self.replay_trusted_drops > 0
                || self.replay_untrusted_drops > 0
                || trusted_receives > 0.0
                || untrusted_receives > 0.0;

            if has_signal {
                let trusted_ratio = if trusted_receives > 0.0 {
                    self.replay_trusted_drops as f64 / trusted_receives
                } else {
                    0.0
                };
                let untrusted_ratio = if untrusted_receives > 0.0 {
                    self.replay_untrusted_drops as f64 / untrusted_receives
                } else {
                    0.0
                };

                Some(ReplayGuardMetrics {
                    drops_by_class: ReplayGuardDrops {
                        trusted: self.replay_trusted_drops,
                        untrusted: self.replay_untrusted_drops,
                    },
                    window_fill_ratio_by_class: ReplayWindowFill {
                        trusted: trusted_ratio,
                        untrusted: untrusted_ratio,
                    },
                })
            } else {
                None
            }
        };

        let mut peer_traffic: Vec<PeerTrafficRecord> = self
            .peer_traffic
            .iter()
            .map(|(peer_id, traffic)| PeerTrafficRecord {
                peer_id: peer_id.clone(),
                peer_class: peer_class_label(traffic.peer_class).to_string(),
                bytes_in: traffic.bytes_in,
                bytes_out: traffic.bytes_out,
            })
            .collect();
        peer_traffic.sort_by(|a, b| a.peer_id.cmp(&b.peer_id));

        SimulationSummary {
            total_publishes: self.total_publishes,
            total_receives: self.total_receives,
            duplicates: self.duplicates,
            chunk_retries: self.chunk_retries,
            replay_guard,
            propagation,
            mesh_changes: self.mesh_changes,
            faults: self.faults,
            recovery,
            bandwidth,
            gossip_backpressure,
            peer_traffic,
            slow_peer_records: self.slow_peer_records,
            resource_usage: self.resource_usage,
            comparison: None,
        }
    }

    fn traffic_entry(&mut self, peer_id: &PeerId) -> &mut PeerTraffic {
        let key = peer_id.to_string();
        self.peer_traffic
            .entry(key.clone())
            .or_insert_with(|| PeerTraffic {
                peer_class: peer_class_from_id(peer_id),
                ..Default::default()
            })
    }

    fn record_outbound(&mut self, peer_id: &PeerId, payload_bytes: usize) {
        let entry = self.traffic_entry(peer_id);
        entry.bytes_out = entry.bytes_out.saturating_add(payload_bytes as u64);
    }

    fn record_inbound(&mut self, peer_id: &PeerId, payload_bytes: usize) {
        let entry = self.traffic_entry(peer_id);
        entry.bytes_in = entry.bytes_in.saturating_add(payload_bytes as u64);
    }
}

#[derive(Debug, Default)]
struct PeerTraffic {
    peer_class: PeerClass,
    bytes_in: u64,
    bytes_out: u64,
}

fn peer_class_from_id(peer_id: &PeerId) -> PeerClass {
    let bytes = peer_id.to_bytes();
    let last = bytes.last().copied().unwrap_or_default();
    if last % 2 == 0 {
        PeerClass::Trusted
    } else {
        PeerClass::Untrusted
    }
}

fn peer_class_label(class: PeerClass) -> &'static str {
    match class {
        PeerClass::Trusted => "trusted",
        PeerClass::Untrusted => "untrusted",
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
