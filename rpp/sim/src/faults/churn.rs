use std::time::Duration;

#[derive(Debug, Clone)]
pub struct ChurnFault {
    pub start: Duration,
    pub rate_per_min: f64,
    pub restart_after: Duration,
}

impl ChurnFault {
    pub fn new(start: Duration, rate_per_min: f64, restart_after: Duration) -> Self {
        Self {
            start,
            rate_per_min,
            restart_after,
        }
    }

    pub fn interval(&self) -> Option<Duration> {
        if self.rate_per_min <= 0.0 {
            return None;
        }
        let interval_ms = (60_000.0 / self.rate_per_min).max(1.0);
        Some(Duration::from_millis(interval_ms as u64))
    }
}
