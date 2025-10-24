use std::cmp::Ordering;
use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};

use rpp_p2p::vendor::PeerId;
use serde::{Deserialize, Serialize};

use crate::metrics::reduce::{calculate_percentiles, SimulationSummary};
use crate::scenario::NodeRole;

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

pub struct Collector {
    start: Instant,
    publications: HashMap<String, PublicationRecord>,
    latencies_ms: Vec<f64>,
    total_publishes: usize,
    total_receives: usize,
    duplicates: usize,
    mesh_changes: Vec<MeshChangeRecord>,
    faults: Vec<FaultRecord>,
    node_metrics: HashMap<PeerId, NodeMetrics>,
    message_receivers: HashMap<String, HashSet<PeerId>>,
    last_event: Option<Instant>,
    simulation_duration: Duration,
    validator_quorum: Option<usize>,
}

impl Collector {
    pub fn new(
        start: Instant,
        node_roles: HashMap<PeerId, NodeRole>,
        simulation_duration: Duration,
        validator_quorum: Option<usize>,
    ) -> Self {
        Self {
            start,
            publications: HashMap::new(),
            latencies_ms: Vec::new(),
            total_publishes: 0,
            total_receives: 0,
            duplicates: 0,
            mesh_changes: Vec::new(),
            faults: Vec::new(),
            node_metrics: node_roles
                .into_iter()
                .map(|(peer_id, role)| (peer_id, NodeMetrics::new(role)))
                .collect(),
            message_receivers: HashMap::new(),
            last_event: None,
            simulation_duration,
            validator_quorum,
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
                self.update_last_event(timestamp);
                self.publications.insert(
                    message_id.clone(),
                    PublicationRecord {
                        timestamp,
                        publisher: peer_id,
                    },
                );
                self.message_receivers
                    .entry(message_id)
                    .or_default()
                    .insert(peer_id);
                self.node_metrics
                    .entry(peer_id)
                    .or_insert_with(|| NodeMetrics::new(NodeRole::Wallet))
                    .publishes += 1;
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
                }
                self.update_last_event(timestamp);
                if let Some(record) = self.publications.get(&message_id) {
                    let delta = timestamp.duration_since(record.timestamp).as_secs_f64() * 1_000.0;
                    self.latencies_ms.push(delta);
                }
                self.message_receivers
                    .entry(message_id)
                    .or_default()
                    .insert(peer_id);
                let metrics = self
                    .node_metrics
                    .entry(peer_id)
                    .or_insert_with(|| NodeMetrics::new(NodeRole::Wallet));
                metrics.receives += 1;
                if duplicate {
                    metrics.duplicates += 1;
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
                self.update_last_event(timestamp);
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
                self.update_last_event(timestamp);
                let timestamp_ms = timestamp.duration_since(self.start).as_secs_f64() * 1_000.0;
                self.faults.push(FaultRecord {
                    kind: fault_event_label(kind).to_string(),
                    detail,
                    timestamp_ms,
                });
            }
        }
    }

    pub fn finalize(mut self) -> SimulationSummary {
        self.latencies_ms
            .sort_by(|a, b| a.partial_cmp(b).unwrap_or(Ordering::Equal));
        let propagation = calculate_percentiles(&self.latencies_ms);
        let node_performance = self.build_node_performance();
        let reputation_drift = calculate_reputation_drift(&node_performance);
        let tier_drift = calculate_tier_drift(&node_performance);
        let proof_latency = calculate_proof_latency(&self.latencies_ms);
        let bft_success = self.validator_quorum.and_then(|quorum| {
            calculate_bft_success(quorum, &self.message_receivers, &self.node_metrics)
        });
        let performance = calculate_performance_kpis(
            self.total_publishes,
            self.total_receives,
            self.duplicates,
            &self.latencies_ms,
            self.start,
            self.last_event,
            self.simulation_duration,
        );
        SimulationSummary {
            total_publishes: self.total_publishes,
            total_receives: self.total_receives,
            duplicates: self.duplicates,
            propagation,
            mesh_changes: self.mesh_changes,
            faults: self.faults,
            reputation_drift,
            tier_drift,
            bft_success,
            proof_latency,
            performance,
            node_performance,
            comparison: None,
        }
    }
}

#[derive(Debug, Clone)]
struct PublicationRecord {
    timestamp: Instant,
    publisher: PeerId,
}

#[derive(Debug, Clone)]
struct NodeMetrics {
    role: NodeRole,
    publishes: usize,
    receives: usize,
    duplicates: usize,
}

impl NodeMetrics {
    fn new(role: NodeRole) -> Self {
        Self {
            role,
            publishes: 0,
            receives: 0,
            duplicates: 0,
        }
    }
}

impl Collector {
    fn update_last_event(&mut self, timestamp: Instant) {
        self.last_event = Some(timestamp);
    }

    fn build_node_performance(&self) -> Vec<crate::metrics::reduce::NodePerformance> {
        let mut entries: Vec<_> = self
            .node_metrics
            .iter()
            .map(
                |(peer_id, metrics)| crate::metrics::reduce::NodePerformance {
                    peer_id: peer_id.to_string(),
                    role: metrics.role,
                    publishes: metrics.publishes,
                    receives: metrics.receives,
                    duplicates: metrics.duplicates,
                },
            )
            .collect();
        entries.sort_by(|a, b| a.peer_id.cmp(&b.peer_id));
        entries
    }
}

fn calculate_reputation_drift(
    nodes: &[crate::metrics::reduce::NodePerformance],
) -> Option<crate::metrics::reduce::ReputationDrift> {
    let validators: Vec<_> = nodes
        .iter()
        .filter(|node| node.role == NodeRole::Validator)
        .collect();
    if validators.is_empty() {
        return None;
    }
    let receives: Vec<f64> = validators.iter().map(|node| node.receives as f64).collect();
    let mean = receives.iter().sum::<f64>() / receives.len() as f64;
    let variance = receives
        .iter()
        .map(|value| {
            let delta = value - mean;
            delta * delta
        })
        .sum::<f64>()
        / receives.len() as f64;
    let std_dev = variance.sqrt();
    let max_receives = validators
        .iter()
        .map(|node| node.receives)
        .max()
        .unwrap_or(0);
    let min_receives = validators
        .iter()
        .map(|node| node.receives)
        .min()
        .unwrap_or(0);
    Some(crate::metrics::reduce::ReputationDrift {
        mean_receives: mean,
        std_dev_receives: std_dev,
        max_receives,
        min_receives,
    })
}

fn calculate_tier_drift(
    nodes: &[crate::metrics::reduce::NodePerformance],
) -> Option<crate::metrics::reduce::TierDrift> {
    let mut validators: Vec<_> = nodes
        .iter()
        .filter(|node| node.role == NodeRole::Validator)
        .collect();
    if validators.is_empty() {
        return None;
    }
    validators.sort_by_key(|node| node.receives);
    let tiers = ["tl1", "tl2", "tl3", "tl4"];
    let bucket_size = ((validators.len() as f64) / tiers.len() as f64).ceil() as usize;
    let expected = validators.len() as f64 / tiers.len() as f64;
    let mut buckets = Vec::new();
    for (idx, tier) in tiers.iter().enumerate() {
        let start = idx * bucket_size;
        if start >= validators.len() {
            break;
        }
        let end = ((idx + 1) * bucket_size).min(validators.len());
        let slice = &validators[start..end];
        let count = slice.len();
        if count == 0 {
            continue;
        }
        let avg_receives =
            slice.iter().map(|node| node.receives as f64).sum::<f64>() / count as f64;
        buckets.push(crate::metrics::reduce::TierBucket {
            tier: (*tier).to_string(),
            count,
            average_receives: avg_receives,
        });
    }
    Some(crate::metrics::reduce::TierDrift {
        expected_per_tier: expected,
        buckets,
    })
}

fn calculate_bft_success(
    quorum: usize,
    message_receivers: &HashMap<String, HashSet<PeerId>>,
    node_metrics: &HashMap<PeerId, NodeMetrics>,
) -> Option<crate::metrics::reduce::BftSuccessSummary> {
    if quorum == 0 || message_receivers.is_empty() {
        return None;
    }
    let mut total_rounds = 0usize;
    let mut successful = 0usize;
    for receivers in message_receivers.values() {
        total_rounds += 1;
        let validator_receivers = receivers
            .iter()
            .filter(|peer_id| {
                node_metrics
                    .get(*peer_id)
                    .map(|metrics| metrics.role == NodeRole::Validator)
                    .unwrap_or(false)
            })
            .count();
        if validator_receivers >= quorum {
            successful += 1;
        }
    }
    if total_rounds == 0 {
        return None;
    }
    Some(crate::metrics::reduce::BftSuccessSummary {
        rounds: total_rounds,
        quorum,
        successes: successful,
        success_rate: successful as f64 / total_rounds as f64,
    })
}

fn calculate_proof_latency(samples: &[f64]) -> Option<crate::metrics::reduce::ProofLatencySummary> {
    if samples.is_empty() {
        return None;
    }
    let p50 = crate::metrics::reduce::percentile(samples, 0.50);
    let p95 = crate::metrics::reduce::percentile(samples, 0.95);
    let p99 = crate::metrics::reduce::percentile(samples, 0.99);
    let max = samples.iter().copied().fold(f64::MIN, f64::max).max(0.0);
    Some(crate::metrics::reduce::ProofLatencySummary {
        p50_ms: p50,
        p95_ms: p95,
        p99_ms: p99,
        max_ms: max,
    })
}

fn calculate_performance_kpis(
    total_publishes: usize,
    total_receives: usize,
    duplicates: usize,
    latencies_ms: &[f64],
    start: Instant,
    last_event: Option<Instant>,
    scheduled: Duration,
) -> Option<crate::metrics::reduce::PerformanceKpi> {
    let observed_duration = last_event.map(|end| end.saturating_duration_since(start));
    let duration = observed_duration.unwrap_or(scheduled);
    if duration.is_zero() {
        return None;
    }
    let duration_secs = duration.as_secs_f64().max(1e-6);
    let publish_rate_per_sec = total_publishes as f64 / duration_secs;
    let receive_rate_per_sec = total_receives as f64 / duration_secs;
    let duplicate_rate = if total_receives == 0 {
        0.0
    } else {
        duplicates as f64 / total_receives as f64
    };
    let mean_latency_ms = if latencies_ms.is_empty() {
        None
    } else {
        Some(latencies_ms.iter().sum::<f64>() / latencies_ms.len() as f64)
    };
    Some(crate::metrics::reduce::PerformanceKpi {
        duration_secs,
        publish_rate_per_sec,
        receive_rate_per_sec,
        duplicate_rate,
        mean_proof_latency_ms: mean_latency_ms,
    })
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
