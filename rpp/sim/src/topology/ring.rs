use std::collections::BTreeSet;

use anyhow::{anyhow, Result};

use super::Topology;

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

    pub fn degree(&self) -> usize {
        self.degree
    }
}

impl Topology for RingTopology {
    fn build(&self, n: usize, _rng: &mut impl rand::Rng) -> Result<Vec<(usize, usize)>> {
        if n < 2 {
            return Ok(Vec::new());
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
        Ok(edges.into_iter().collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::SeedableRng;

    #[test]
    fn ring_edges_cover_neighbours() {
        let topo = RingTopology::new(2).expect("ring");
        let mut rng = rand::rngs::StdRng::seed_from_u64(7);
        let edges = topo.build(5, &mut rng).expect("ring");
        assert!(edges.contains(&(0, 1)));
        assert!(edges.contains(&(1, 2)));
        assert!(edges.contains(&(0, 4)));
    }
}
