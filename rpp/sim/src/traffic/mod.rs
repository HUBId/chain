mod onoff_bursty;
pub mod poisson;
mod zipf;

use std::time::Duration;

use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};

use crate::metrics::PropagationProbeKind;

pub use onoff_bursty::OnOffBursty;
pub use poisson::PoissonTraffic;
pub use zipf::{PublisherSelector, PublisherSelectorBuilder};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TrafficStep {
    pub wait: Duration,
    pub publish: bool,
}

#[derive(Debug)]
pub(crate) enum TrafficModelState {
    Poisson(PoissonTraffic),
    OnOff(OnOffBursty),
}

impl TrafficModelState {
    pub fn next_step(&mut self) -> TrafficStep {
        match self {
            TrafficModelState::Poisson(model) => model.next_step(),
            TrafficModelState::OnOff(model) => model.next_step(),
        }
    }
}

#[derive(Debug)]
pub(crate) struct TrafficPhaseConfig {
    pub name: Option<String>,
    pub duration: Duration,
    pub model: TrafficModelState,
}

#[derive(Debug)]
struct PhaseState {
    #[allow(dead_code)]
    name: Option<String>,
    remaining: Duration,
    model: TrafficModelState,
}

impl From<TrafficPhaseConfig> for PhaseState {
    fn from(value: TrafficPhaseConfig) -> Self {
        PhaseState {
            name: value.name,
            remaining: value.duration,
            model: value.model,
        }
    }
}

pub struct TrafficProgram {
    phases: Vec<PhaseState>,
    current: usize,
    publisher: PublisherSelector,
}

impl TrafficProgram {
    pub(crate) fn new(phases: Vec<TrafficPhaseConfig>, publisher: PublisherSelector) -> Self {
        let phases = phases.into_iter().map(Into::into).collect();
        Self {
            phases,
            current: 0,
            publisher,
        }
    }

    pub fn next_step(&mut self) -> Option<TrafficStep> {
        loop {
            let phase = self.phases.get_mut(self.current)?;
            if phase.remaining.is_zero() {
                self.current += 1;
                continue;
            }
            let mut step = phase.model.next_step();
            if step.wait > phase.remaining {
                let wait = phase.remaining;
                phase.remaining = Duration::ZERO;
                step.wait = wait;
                step.publish = false;
                self.current += 1;
                if wait.is_zero() {
                    continue;
                }
                return Some(step);
            }
            phase.remaining -= step.wait;
            if phase.remaining.is_zero() {
                self.current += 1;
            }
            if step.wait.is_zero() && !step.publish {
                continue;
            }
            return Some(step);
        }
    }

    pub fn pick_publisher(&mut self, n: usize) -> Option<usize> {
        self.publisher.pick(n)
    }
}

#[derive(Debug, Clone)]
pub struct PayloadGenerator {
    rng: StdRng,
    min_bytes: usize,
    max_bytes: usize,
}

impl PayloadGenerator {
    pub fn new(min_bytes: usize, max_bytes: usize, seed: u64) -> Self {
        Self {
            rng: StdRng::seed_from_u64(seed),
            min_bytes,
            max_bytes: max_bytes.max(min_bytes),
        }
    }

    pub fn next_payload(&mut self, message_counter: u64) -> Vec<u8> {
        let base = format!("{{\"message\":{message_counter}}}").into_bytes();
        let base_len = base.len();
        let target_len = if self.min_bytes == self.max_bytes {
            self.min_bytes.max(base_len)
        } else {
            self.rng
                .gen_range(self.min_bytes..=self.max_bytes)
                .max(base_len)
        };

        let mut payload = base;
        if payload.len() < target_len {
            let original_len = payload.len();
            payload.resize(target_len, 0);
            self.rng.fill(&mut payload[original_len..]);
        }

        payload
    }

    pub fn probe_payload(&mut self, probe_kind: PropagationProbeKind, sequence: u64) -> Vec<u8> {
        let base = format!(
            "{{\"probe\":\"{}\",\"sequence\":{sequence}}}",
            probe_kind.as_str()
        )
        .into_bytes();
        let base_len = base.len();
        let target_len = if self.min_bytes == self.max_bytes {
            self.min_bytes.max(base_len)
        } else {
            self.rng
                .gen_range(self.min_bytes..=self.max_bytes)
                .max(base_len)
        };

        let mut payload = base;
        if payload.len() < target_len {
            let original_len = payload.len();
            payload.resize(target_len, 0);
            self.rng.fill(&mut payload[original_len..]);
        }

        payload
    }
}

#[cfg(test)]
mod tests {
    use super::PayloadGenerator;

    #[test]
    fn payload_generator_respects_bounds_and_seed() {
        let mut generator = PayloadGenerator::new(16, 32, 0xfeed_beef);

        let first = generator.next_payload(1);
        let second = generator.next_payload(2);

        assert!(first.len() >= 16 && first.len() <= 32);
        assert!(second.len() >= 16 && second.len() <= 32);
        assert_ne!(first, second, "rng should influence padding");
    }

    #[test]
    fn payload_generator_never_truncates_counter() {
        let mut generator = PayloadGenerator::new(1, 1, 42);

        let payload = generator.next_payload(12345);

        let body = String::from_utf8(payload).expect("payload remains utf-8");
        assert!(
            body.contains("12345"),
            "counter should survive padding logic"
        );
    }
}
