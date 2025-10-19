use std::collections::{HashMap, HashSet, VecDeque};
use std::time::{Duration, Instant};

use blake3::Hash;
use crate::vendor::PeerId;

#[derive(Debug)]
pub struct ReplayProtector {
    capacity: usize,
    queue: VecDeque<Hash>,
    seen: HashSet<Hash>,
}

impl ReplayProtector {
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            capacity: capacity.max(128),
            queue: VecDeque::new(),
            seen: HashSet::new(),
        }
    }

    pub fn preload(&mut self, digests: impl IntoIterator<Item = Hash>) {
        for digest in digests {
            self.observe(digest);
        }
    }

    pub fn observe(&mut self, digest: Hash) -> bool {
        if self.seen.contains(&digest) {
            return false;
        }
        self.seen.insert(digest);
        self.queue.push_back(digest);
        if self.queue.len() > self.capacity {
            if let Some(old) = self.queue.pop_front() {
                self.seen.remove(&old);
            }
        }
        true
    }
}

#[derive(Debug, Clone)]
struct RateWindow {
    last_reset: Instant,
    count: u64,
}

impl RateWindow {
    fn new() -> Self {
        Self {
            last_reset: Instant::now(),
            count: 0,
        }
    }

    fn increment(&mut self) {
        self.count += 1;
    }

    fn reset(&mut self) {
        self.count = 0;
        self.last_reset = Instant::now();
    }
}

#[derive(Debug)]
pub struct RateLimiter {
    windows: HashMap<PeerId, RateWindow>,
    interval: Duration,
    max_messages: u64,
}

impl RateLimiter {
    pub fn new(interval: Duration, max_messages: u64) -> Self {
        Self {
            windows: HashMap::new(),
            interval,
            max_messages: max_messages.max(1),
        }
    }

    pub fn allow(&mut self, peer: PeerId) -> bool {
        let window = self.windows.entry(peer).or_insert_with(RateWindow::new);
        if window.last_reset.elapsed() > self.interval {
            window.reset();
        }
        if window.count >= self.max_messages {
            return false;
        }
        window.increment();
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use std::thread;

    #[test]
    fn replay_detector_rejects_duplicates() {
        let mut protector = ReplayProtector::with_capacity(4);
        let digest = blake3::hash(b"payload");
        assert!(protector.observe(digest));
        assert!(!protector.observe(digest));
    }

    #[test]
    fn rate_limiter_enforces_limits() {
        let mut limiter = RateLimiter::new(Duration::from_millis(50), 2);
        let peer = PeerId::random();
        assert!(limiter.allow(peer));
        assert!(limiter.allow(peer));
        assert!(!limiter.allow(peer));
        thread::sleep(Duration::from_millis(60));
        assert!(limiter.allow(peer));
    }

    proptest! {
        #[test]
        fn replay_window_evicts_old_entries(window in 1usize..64, overflow in 1usize..16) {
            let mut protector = ReplayProtector::with_capacity(window);
            let effective = protector.capacity;
            let total = effective + overflow;
            for index in 0..total {
                let digest = blake3::hash(&index.to_le_bytes());
                prop_assert!(protector.observe(digest));
            }
            for index in 0..overflow {
                let digest = blake3::hash(&index.to_le_bytes());
                prop_assert!(protector.observe(digest));
            }
        }

        #[test]
        fn rate_limiter_bounds_messages(limit in 1u64..8) {
            let mut limiter = RateLimiter::new(Duration::from_millis(20), limit);
            let peer = PeerId::random();
            for _ in 0..limit {
                prop_assert!(limiter.allow(peer));
            }
            prop_assert!(!limiter.allow(peer));
            thread::sleep(Duration::from_millis(25));
            prop_assert!(limiter.allow(peer));
        }
    }
}
