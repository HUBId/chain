use rand::prelude::*;

#[derive(Debug, Clone)]
pub struct SimulationReport {
    pub avg_latency_ms: f64,
    pub mesh_stability: f64,
    pub reputation_drift: f64,
    pub rounds: u32,
    pub peers: usize,
}

impl SimulationReport {
    pub fn summary(&self) -> String {
        format!(
            "peers={} rounds={} avg_latency_ms={:.2} mesh_stability={:.3} reputation_drift={:.4}",
            self.peers, self.rounds, self.avg_latency_ms, self.mesh_stability, self.reputation_drift
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
        Self { peers: peers.max(1), rounds: rounds.max(1), seed }
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

        SimulationReport {
            avg_latency_ms: avg_latency,
            mesh_stability: stability,
            reputation_drift: drift,
            rounds: self.rounds,
            peers: self.peers,
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
        assert!(report.summary().contains("peers=32"));
    }
}
