use rand::prelude::*;

use crate::topics::GossipTopic;
use crate::vendor::gossipsub::TopicMeshConfig;

#[derive(Debug, Clone)]
pub struct SimulationReport {
    pub avg_latency_ms: f64,
    pub mesh_stability: f64,
    pub reputation_drift: f64,
    pub rounds: u32,
    pub peers: usize,
    pub avg_score: f64,
    pub mesh_health: Vec<(GossipTopic, f64)>,
}

impl SimulationReport {
    pub fn summary(&self) -> String {
        let mesh_snapshot = self
            .mesh_health
            .iter()
            .map(|(topic, health)| format!("{}:{:.2}", topic, health))
            .collect::<Vec<_>>()
            .join(",");
        format!(
            "peers={} rounds={} avg_latency_ms={:.2} mesh_stability={:.3} reputation_drift={:.4} avg_score={:.3} mesh_health=[{}]",
            self.peers,
            self.rounds,
            self.avg_latency_ms,
            self.mesh_stability,
            self.reputation_drift,
            self.avg_score,
            mesh_snapshot
        )
    }
}

#[derive(Debug, Clone)]
pub struct NetworkSimulation {
    peers: usize,
    rounds: u32,
    seed: u64,
}

impl NetworkSimulation {
    pub fn new(peers: usize, rounds: u32) -> Self {
        Self::with_seed(peers, rounds, 0xfeed_cafe)
    }

    pub fn with_seed(peers: usize, rounds: u32, seed: u64) -> Self {
        Self {
            peers: peers.max(1),
            rounds: rounds.max(1),
            seed,
        }
    }

    pub fn run(&self) -> SimulationReport {
        let mut rng = StdRng::seed_from_u64(self.seed);
        let mut latency_total = 0.0;
        let mut samples = 0u64;
        let mut mesh_changes = 0u64;
        let mut reputation_delta = 0.0;

        for _round in 0..self.rounds {
            for _peer in 0..self.peers {
                let latency = rng.gen_range(20.0..300.0);
                latency_total += latency;
                samples += 1;

                if rng.gen_bool(0.08) {
                    mesh_changes += 1;
                }

                reputation_delta += rng.gen_range(-0.05..0.12);
            }
        }

        let avg_latency = if samples == 0 {
            0.0
        } else {
            latency_total / samples as f64
        };
        let mesh_total = (self.rounds as f64 * self.peers as f64).max(1.0);
        let stability = (1.0 - (mesh_changes as f64 / mesh_total)).clamp(0.0, 1.0);
        let drift = reputation_delta / self.peers as f64;
        let avg_score = if samples == 0 {
            0.0
        } else {
            (reputation_delta / samples as f64).clamp(-5.0, 5.0)
        };

        let mesh_health = GossipTopic::all()
            .into_iter()
            .map(|topic| {
                let config = match topic {
                    GossipTopic::Blocks | GossipTopic::Votes => TopicMeshConfig {
                        mesh_n: 10,
                        mesh_n_low: 8,
                        mesh_n_high: 16,
                        mesh_outbound_min: 4,
                    },
                    GossipTopic::Proofs | GossipTopic::WitnessProofs => TopicMeshConfig {
                        mesh_n: 8,
                        mesh_n_low: 6,
                        mesh_n_high: 12,
                        mesh_outbound_min: 3,
                    },
                    GossipTopic::Snapshots | GossipTopic::Meta | GossipTopic::WitnessMeta => {
                        TopicMeshConfig {
                            mesh_n: 6,
                            mesh_n_low: 4,
                            mesh_n_high: 10,
                            mesh_outbound_min: 2,
                        }
                    }
                };
                let balance =
                    (config.mesh_n_low as f64 / config.mesh_n_high as f64).clamp(0.0, 1.0);
                let jitter = rng.gen_range(0.0..0.1);
                let health = ((stability * balance) + jitter).clamp(0.0, 1.0);
                (topic, health)
            })
            .collect();

        SimulationReport {
            avg_latency_ms: avg_latency,
            mesh_stability: stability,
            reputation_drift: drift,
            rounds: self.rounds,
            peers: self.peers,
            avg_score,
            mesh_health,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn produces_consistent_report() {
        let simulation = NetworkSimulation::with_seed(32, 20, 42);
        let report = simulation.run();
        assert_eq!(report.peers, 32);
        assert_eq!(report.rounds, 20);
        assert!(report.avg_latency_ms > 0.0);
        assert!(report.mesh_stability <= 1.0);
        assert!(!report.mesh_health.is_empty());
        assert!(report.summary().contains("avg_score"));
    }
}
