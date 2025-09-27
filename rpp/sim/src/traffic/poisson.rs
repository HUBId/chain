use std::time::Duration;

use anyhow::{anyhow, Result};
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};

use super::TrafficStep;

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

    pub fn next_step(&mut self) -> TrafficStep {
        let wait = sample_exponential(self.rate_per_ms, &mut self.rng);
        TrafficStep {
            wait,
            publish: true,
        }
    }
}

pub(crate) fn sample_exponential(rate_per_ms: f64, rng: &mut StdRng) -> Duration {
    let u = rng
        .gen::<f64>()
        .clamp(f64::MIN_POSITIVE, 1.0 - f64::EPSILON);
    let delta_ms = -u.ln() / rate_per_ms;
    let nanos = (delta_ms * 1_000_000.0).max(1.0);
    Duration::from_nanos(nanos as u64)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deterministic_sequence() {
        let mut a = PoissonTraffic::new(5.0, 7).unwrap();
        let mut b = PoissonTraffic::new(5.0, 7).unwrap();
        for _ in 0..10 {
            assert_eq!(a.next_step(), b.next_step());
        }
    }
}
