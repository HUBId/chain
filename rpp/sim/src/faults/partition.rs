use std::time::Duration;

#[derive(Debug, Clone)]
pub struct PartitionFault {
    pub start: Duration,
    pub duration: Duration,
    pub group_a: String,
    pub group_b: String,
}

impl PartitionFault {
    pub fn new(start: Duration, duration: Duration, group_a: String, group_b: String) -> Self {
        Self {
            start,
            duration,
            group_a,
            group_b,
        }
    }

    pub fn end(&self) -> Duration {
        self.start + self.duration
    }

    pub fn affects(&self, region_a: &str, region_b: &str) -> bool {
        let matches_ab = (region_a == self.group_a && region_b == self.group_b)
            || (region_a == self.group_b && region_b == self.group_a);
        matches_ab
    }
}
