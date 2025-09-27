use std::collections::BTreeSet;

use anyhow::{anyhow, Result};
use rand::seq::SliceRandom;
use rand::Rng;

use super::{ensure_degree, Topology};

#[derive(Debug, Clone, Copy)]
pub struct KRegularTopology {
    degree: usize,
}

impl KRegularTopology {
    pub fn new(degree: usize) -> Result<Self> {
        if degree == 0 {
            return Err(anyhow!("k-regular degree must be non-zero"));
        }
        Ok(Self { degree })
    }
}

impl Topology for KRegularTopology {
    fn build(&self, n: usize, rng: &mut impl Rng) -> Result<Vec<(usize, usize)>> {
        if n == 0 {
            return Ok(Vec::new());
        }
        if self.degree >= n {
            return Err(anyhow!("degree must be smaller than number of nodes"));
        }
        if (n * self.degree) % 2 != 0 {
            return Err(anyhow!("n * k must be even for k-regular graph"));
        }

        let mut permutation: Vec<usize> = (0..n).collect();
        permutation.shuffle(rng);

        let mut edges = BTreeSet::new();
        let half = self.degree / 2;
        for idx in 0..n {
            let node = permutation[idx];
            for offset in 1..=half {
                let neighbour_idx = (idx + offset) % n;
                let neighbour = permutation[neighbour_idx];
                let edge = if node < neighbour {
                    (node, neighbour)
                } else {
                    (neighbour, node)
                };
                edges.insert(edge);
            }
        }
        if self.degree % 2 == 1 {
            for idx in 0..(n / 2) {
                let a = permutation[idx];
                let b = permutation[(idx + n / 2) % n];
                let edge = if a < b { (a, b) } else { (b, a) };
                edges.insert(edge);
            }
        }

        let result: Vec<_> = edges.into_iter().collect();
        let degrees = ensure_degree(n, &result);
        if degrees.iter().all(|&d| d == self.degree) {
            Ok(result)
        } else {
            Err(anyhow!(
                "constructed graph does not meet degree requirements"
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use rand::rngs::StdRng;
    use rand::SeedableRng;

    use super::*;
    use crate::topology::{ensure_degree, largest_component_size};

    #[test]
    fn generates_k_regular_graph() {
        let topo = KRegularTopology::new(4).unwrap();
        let mut rng = StdRng::seed_from_u64(19);
        let edges = topo.build(20, &mut rng).unwrap();
        let degrees = ensure_degree(20, &edges);
        assert!(degrees.iter().all(|&deg| deg == 4));
        assert_eq!(largest_component_size(20, &edges), 20);
    }
}
