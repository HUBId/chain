use std::time::Duration;

use anyhow::{anyhow, Result};
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};

#[derive(Debug, Clone)]
pub struct PoissonTraffic {
    rate_per_ms: f64,
    rng: StdRng,
}

impl PoissonTraffic {
    pub fn new(lambda_per_sec: f64, seed: u64) -> Result<Self> {
        if lambda_per_sec <= 0.0 {
            return Err(anyhow!("lambda must be positive"));
        }
        let rate_per_ms = lambda_per_sec / 1_000.0;
        Ok(Self {
            rate_per_ms,
            rng: StdRng::seed_from_u64(seed),
        })
    }

    pub fn next_arrival(&mut self) -> Duration {
        let u = self.rng.gen::<f64>().clamp(f64::MIN_POSITIVE, 1.0);
        let delta_ms = -u.ln() / self.rate_per_ms;
        Duration::from_secs_f64(delta_ms / 1_000.0)
    }

    pub fn pick_publisher(&mut self, n: usize) -> usize {
        if n == 0 {
            return 0;
        }
        self.rng.gen_range(0, n)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deterministic_sequence() {
        let mut a = PoissonTraffic::new(5.0, 7).unwrap();
        let mut b = PoissonTraffic::new(5.0, 7).unwrap();
        for _ in 0..10 {
            assert_eq!(a.next_arrival(), b.next_arrival());
            assert_eq!(a.pick_publisher(5), b.pick_publisher(5));
        }
    }
}
