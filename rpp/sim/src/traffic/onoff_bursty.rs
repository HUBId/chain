use std::time::Duration;

use anyhow::{anyhow, Result};
use rand::rngs::StdRng;
use rand::SeedableRng;

use super::{poisson::sample_exponential, TrafficStep};

#[derive(Debug, Clone)]
pub struct OnOffBursty {
    on_rate_per_ms: f64,
    on_duration: Duration,
    off_duration: Duration,
    rng: StdRng,
    state: State,
}

#[derive(Debug, Clone)]
enum State {
    On { remaining: Duration },
    Off { remaining: Duration },
}

impl OnOffBursty {
    pub fn new(
        on_lambda_per_sec: f64,
        on_duration_ms: u64,
        off_duration_ms: u64,
        seed: u64,
    ) -> Result<Self> {
        if on_lambda_per_sec <= 0.0 {
            return Err(anyhow!("on_lambda_per_sec must be positive"));
        }
        if on_duration_ms == 0 {
            return Err(anyhow!("on_duration_ms must be positive"));
        }
        if off_duration_ms == 0 {
            return Err(anyhow!("off_duration_ms must be positive"));
        }
        let on_rate_per_ms = on_lambda_per_sec / 1_000.0;
        Ok(Self {
            on_rate_per_ms,
            on_duration: Duration::from_millis(on_duration_ms),
            off_duration: Duration::from_millis(off_duration_ms),
            rng: StdRng::seed_from_u64(seed),
            state: State::On {
                remaining: Duration::from_millis(on_duration_ms),
            },
        })
    }

    pub fn next_step(&mut self) -> TrafficStep {
        match &mut self.state {
            State::On { remaining } => {
                if remaining.is_zero() {
                    self.state = State::Off {
                        remaining: self.off_duration,
                    };
                    return TrafficStep {
                        wait: Duration::ZERO,
                        publish: false,
                    };
                }
                let wait = sample_exponential(self.on_rate_per_ms, &mut self.rng);
                if wait <= *remaining {
                    *remaining -= wait;
                    if remaining.is_zero() {
                        self.state = State::Off {
                            remaining: self.off_duration,
                        };
                    }
                    TrafficStep {
                        wait,
                        publish: true,
                    }
                } else {
                    let wait = *remaining;
                    self.state = State::Off {
                        remaining: self.off_duration,
                    };
                    TrafficStep {
                        wait,
                        publish: false,
                    }
                }
            }
            State::Off { remaining } => {
                let wait = *remaining;
                self.state = State::On {
                    remaining: self.on_duration,
                };
                TrafficStep {
                    wait,
                    publish: false,
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ks_statistic(samples: &[f64], lambda: f64) -> f64 {
        let mut sorted = samples.to_vec();
        sorted.sort_by(|a, b| a.partial_cmp(b).unwrap());
        let n = sorted.len() as f64;
        let mut max_diff = 0.0;
        for (idx, &value) in sorted.iter().enumerate() {
            let empirical = (idx + 1) as f64 / n;
            let theoretical = 1.0 - (-lambda * value).exp();
            let diff = (empirical - theoretical).abs();
            if diff > max_diff {
                max_diff = diff;
            }
        }
        max_diff
    }

    #[test]
    fn inter_arrivals_follow_exponential_during_on_phase() {
        let lambda = 20.0;
        let mut model = OnOffBursty::new(lambda, 20_000, 1_000, 42).unwrap();
        let mut samples = Vec::new();
        while samples.len() < 2_000 {
            let step = model.next_step();
            if step.publish {
                samples.push(step.wait.as_secs_f64());
            }
        }
        // Allow the first few samples to stabilize.
        samples.drain(0..10);
        let ks = ks_statistic(&samples, lambda);
        assert!(ks < 0.05, "ks={ks}");
    }
}
