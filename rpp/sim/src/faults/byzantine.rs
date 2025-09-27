use std::time::Duration;

#[derive(Debug, Clone)]
pub struct ByzantineFault {
    pub start: Duration,
    pub spam_factor: u64,
    pub publishers: Vec<usize>,
}

impl ByzantineFault {
    pub fn new(start: Duration, spam_factor: u64, publishers: Vec<usize>) -> Self {
        Self {
            start,
            spam_factor: spam_factor.max(1),
            publishers,
        }
    }

    pub fn is_publisher(&self, idx: usize) -> bool {
        self.publishers.contains(&idx)
    }
}
