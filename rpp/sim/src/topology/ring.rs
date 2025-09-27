use std::collections::BTreeSet;

use anyhow::{anyhow, Result};

#[derive(Debug, Clone, Copy)]
pub struct RingTopology {
    degree: usize,
}

impl RingTopology {
    pub fn new(degree: usize) -> Result<Self> {
        if degree == 0 || degree % 2 != 0 {
            return Err(anyhow!("ring topology requires a non-zero even degree"));
        }
        Ok(Self { degree })
    }

    pub fn build(&self, n: usize) -> Vec<(usize, usize)> {
        if n < 2 {
            return Vec::new();
        }
        let half = self.degree / 2;
        let mut edges = BTreeSet::new();
        for node in 0..n {
            for offset in 1..=half {
                let neighbour = (node + offset) % n;
                let edge = if node < neighbour {
                    (node, neighbour)
                } else {
                    (neighbour, node)
                };
                edges.insert(edge);
            }
        }
        edges.into_iter().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ring_edges_cover_neighbours() {
        let topo = RingTopology::new(2).expect("ring");
        let edges = topo.build(5);
        assert!(edges.contains(&(0, 1)));
        assert!(edges.contains(&(1, 2)));
        assert!(edges.contains(&(0, 4)));
    }
}
