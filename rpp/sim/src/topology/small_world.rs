use std::collections::BTreeSet;

use anyhow::{anyhow, Result};
use rand::Rng;

use super::{RingTopology, Topology};

#[derive(Debug, Clone, Copy)]
pub struct SmallWorldTopology {
    degree: usize,
    rewire_p: f64,
}

impl SmallWorldTopology {
    pub fn new(degree: usize, rewire_p: f64) -> Result<Self> {
        if degree == 0 || degree % 2 != 0 {
            return Err(anyhow!("small-world requires non-zero even degree"));
        }
        if !(0.0..=1.0).contains(&rewire_p) {
            return Err(anyhow!("rewire probability must be between 0 and 1"));
        }
        Ok(Self { degree, rewire_p })
    }
}

impl Topology for SmallWorldTopology {
    fn build(&self, n: usize, rng: &mut impl Rng) -> Result<Vec<(usize, usize)>> {
        if n < 2 {
            return Ok(Vec::new());
        }
        let base = RingTopology::new(self.degree)?.build(n, rng)?;
        if self.rewire_p == 0.0 {
            return Ok(base);
        }
        let mut edges: BTreeSet<_> = base.into_iter().collect();
        let half = self.degree / 2;
        for node in 0..n {
            for offset in 1..=half {
                let neighbour = (node + offset) % n;
                if node > neighbour {
                    continue;
                }
                if rng.gen::<f64>() > self.rewire_p {
                    continue;
                }
                edges.remove(&(node, neighbour));
                let mut attempts = 0;
                let mut rewired = false;
                while attempts < n * 2 {
                    attempts += 1;
                    let candidate = rng.gen_range(0, n);
                    if candidate == node {
                        continue;
                    }
                    let edge = if node < candidate {
                        (node, candidate)
                    } else {
                        (candidate, node)
                    };
                    if edges.contains(&edge) {
                        continue;
                    }
                    edges.insert(edge);
                    rewired = true;
                    break;
                }
                if !rewired {
                    edges.insert((node, neighbour));
                }
            }
        }
        Ok(edges.into_iter().collect())
    }
}

#[cfg(test)]
mod tests {
    use rand::rngs::StdRng;
    use rand::SeedableRng;

    use super::*;
    use crate::topology::{ensure_degree, largest_component_size};

    #[test]
    fn preserves_degree_count() {
        let topo = SmallWorldTopology::new(4, 0.2).unwrap();
        let mut rng = StdRng::seed_from_u64(23);
        let edges = topo.build(30, &mut rng).unwrap();
        let degrees = ensure_degree(30, &edges);
        assert_eq!(degrees.iter().sum::<usize>(), 30 * 4);
        assert!(degrees.iter().all(|&d| d >= 2));
        assert_eq!(largest_component_size(30, &edges), 30);
    }
}
