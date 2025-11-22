use std::cmp::{max, min};
use std::time::Duration;

/// Strategy that adapts snapshot chunk sizes based on recent throughput and RTT
/// telemetry while keeping requests inside configured bounds.
#[derive(Debug, Clone)]
pub struct ChunkSizingStrategy {
    min: usize,
    max: usize,
    current: usize,
    /// Exponentially weighted moving average of bytes/second throughput.
    ema_throughput: f64,
    /// Weighting factor for newly observed samples.
    smoothing: f64,
    /// Target RTT window used to derive the next candidate chunk size.
    target_rtt: Duration,
    /// Fractional deviation that must be exceeded before the current chunk size
    /// is adjusted. This prevents oscillation on noisy telemetry.
    adjustment_threshold: f64,
}

impl ChunkSizingStrategy {
    pub fn new(min: usize, max: usize, initial: usize, target_rtt: Duration) -> Self {
        let bounded_min = min.max(1);
        let bounded_max = max(max, bounded_min);
        let bounded_initial = min(max(initial, bounded_min), bounded_max);
        Self {
            min: bounded_min,
            max: bounded_max,
            current: bounded_initial,
            ema_throughput: 0.0,
            smoothing: 0.25,
            target_rtt,
            adjustment_threshold: 0.1,
        }
    }

    pub fn bounds(&self) -> (usize, usize) {
        (self.min, self.max)
    }

    pub fn current(&self) -> usize {
        self.current
    }

    pub fn record_sample(&mut self, bytes: usize, rtt: Duration) {
        if rtt.is_zero() {
            return;
        }
        let throughput = bytes as f64 / rtt.as_secs_f64();
        if self.ema_throughput == 0.0 {
            self.ema_throughput = throughput;
        } else {
            self.ema_throughput =
                self.ema_throughput * (1.0 - self.smoothing) + throughput * self.smoothing;
        }
    }

    pub fn next_chunk_size(&mut self) -> usize {
        let desired = if self.ema_throughput == 0.0 {
            self.current
        } else {
            (self.ema_throughput * self.target_rtt.as_secs_f64()) as usize
        };

        let bounded_desired = min(max(desired, self.min), self.max);
        let lower = (self.current as f64 * (1.0 - self.adjustment_threshold)) as usize;
        let upper = (self.current as f64 * (1.0 + self.adjustment_threshold)) as usize;

        if bounded_desired >= lower && bounded_desired <= upper {
            return self.current;
        }

        self.current = bounded_desired;
        self.current
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn respects_bounds() {
        let mut strategy = ChunkSizingStrategy::new(64, 512, 128, Duration::from_millis(500));
        strategy.record_sample(10_000, Duration::from_millis(10));
        let size = strategy.next_chunk_size();
        assert!(size <= 512);
        assert!(size >= 64);

        strategy.record_sample(1, Duration::from_secs(10));
        let size = strategy.next_chunk_size();
        assert_eq!(size, 64);
    }

    #[test]
    fn grows_and_shrinks_with_telemetry() {
        let mut strategy = ChunkSizingStrategy::new(64, 4096, 256, Duration::from_millis(500));

        strategy.record_sample(4096, Duration::from_millis(50));
        let grown = strategy.next_chunk_size();
        assert!(grown > 256);

        strategy.record_sample(128, Duration::from_secs(1));
        let shrunk = strategy.next_chunk_size();
        assert!(shrunk < grown);
        assert!(shrunk >= 64);
    }

    #[test]
    fn stable_under_noise() {
        let mut strategy = ChunkSizingStrategy::new(256, 2048, 512, Duration::from_millis(500));

        strategy.record_sample(1024, Duration::from_millis(100));
        let baseline = strategy.next_chunk_size();

        // Noisy measurement should not trigger oscillation.
        for _ in 0..5 {
            strategy.record_sample(100, Duration::from_millis(10));
            let size = strategy.next_chunk_size();
            assert_eq!(size, baseline);
        }
    }
}
