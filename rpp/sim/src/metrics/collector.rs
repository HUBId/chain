use std::cmp::Ordering;
use std::collections::HashMap;
use std::time::Instant;

use libp2p::PeerId;
use serde::Serialize;

use crate::metrics::reduce::{calculate_percentiles, SimulationSummary};

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
}

#[derive(Debug, Clone, Copy)]
pub enum MeshAction {
    Graft,
    Prune,
    Subscribe,
    Unsubscribe,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct MeshChangeRecord {
    pub node: String,
    pub peer: String,
    pub topic: String,
    pub action: String,
    pub timestamp_ms: f64,
}

pub struct Collector {
    start: Instant,
    publications: HashMap<String, Instant>,
    latencies_ms: Vec<f64>,
    total_publishes: usize,
    total_receives: usize,
    duplicates: usize,
    mesh_changes: Vec<MeshChangeRecord>,
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
            mesh_changes: Vec::new(),
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
                }
                if let Some(published_at) = self.publications.get(&message_id) {
                    let delta = timestamp.duration_since(*published_at).as_secs_f64() * 1_000.0;
                    self.latencies_ms.push(delta);
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
        }
    }

    pub fn finalize(mut self) -> SimulationSummary {
        self.latencies_ms
            .sort_by(|a, b| a.partial_cmp(b).unwrap_or(Ordering::Equal));
        let propagation = calculate_percentiles(&self.latencies_ms);
        SimulationSummary {
            total_publishes: self.total_publishes,
            total_receives: self.total_receives,
            duplicates: self.duplicates,
            propagation,
            mesh_changes: self.mesh_changes,
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
