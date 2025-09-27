use std::collections::{BTreeSet, HashSet};

use anyhow::Result;
use rand::Rng;

use super::Topology;

#[derive(Debug, Clone, Copy)]
pub struct ScaleFreeTopology {
    m0: usize,
    m: usize,
}

impl ScaleFreeTopology {
    pub fn new(target_degree: usize) -> Result<Self> {
        let m = target_degree.max(1) / 2 + target_degree.max(1) % 2;
        let m0 = (m + 1).max(2);
        Ok(Self { m0, m })
    }
}

impl Topology for ScaleFreeTopology {
    fn build(&self, n: usize, rng: &mut impl Rng) -> Result<Vec<(usize, usize)>> {
        if n < 2 {
            return Ok(Vec::new());
        }
        let initial = self.m0.min(n);
        let mut edges = BTreeSet::new();
        let mut degrees = vec![0usize; n];

        for i in 0..initial {
            for j in (i + 1)..initial {
                edges.insert((i, j));
                degrees[i] += 1;
                degrees[j] += 1;
            }
        }

        let mut targets = Vec::new();
        for node in 0..initial {
            for _ in 0..degrees[node] {
                targets.push(node);
            }
        }

        for node in initial..n {
            let mut connected = HashSet::new();
            while connected.len() < self.m && !targets.is_empty() {
                let idx = rng.gen_range(0, targets.len());
                let candidate = targets[idx];
                if candidate == node {
                    continue;
                }
                connected.insert(candidate);
            }
            while connected.len() < self.m {
                let candidate = rng.gen_range(0, node);
                if candidate == node {
                    continue;
                }
                connected.insert(candidate);
            }
            for &target in &connected {
                let edge = if node < target {
                    (node, target)
                } else {
                    (target, node)
                };
                if edges.insert(edge) {
                    degrees[node] += 1;
                    degrees[target] += 1;
                    targets.push(target);
                }
            }
            for _ in 0..degrees[node] {
                targets.push(node);
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
    fn produces_connected_graph() {
        let topo = ScaleFreeTopology::new(4).unwrap();
        let mut rng = StdRng::seed_from_u64(31);
        let edges = topo.build(25, &mut rng).unwrap();
        assert_eq!(largest_component_size(25, &edges), 25);
        let degrees = ensure_degree(25, &edges);
        assert!(degrees.iter().all(|&d| d > 0));
    }
}
