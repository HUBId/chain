mod onoff_bursty;
pub mod poisson;
mod zipf;

use std::time::Duration;

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
