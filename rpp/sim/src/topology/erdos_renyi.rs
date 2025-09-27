use std::collections::BTreeSet;

use anyhow::{anyhow, Result};
use rand::Rng;

use super::Topology;

#[derive(Debug, Clone, Copy)]
pub struct ErdosRenyiTopology {
    pub probability: f64,
}

impl ErdosRenyiTopology {
    pub fn new(probability: f64) -> Result<Self> {
        if !(0.0..=1.0).contains(&probability) {
            return Err(anyhow!("erdos-renyi probability must be between 0 and 1"));
        }
        Ok(Self { probability })
    }
}

impl Topology for ErdosRenyiTopology {
    fn build(&self, n: usize, rng: &mut impl Rng) -> Result<Vec<(usize, usize)>> {
        if n < 2 {
            return Ok(Vec::new());
        }
        let mut edges = BTreeSet::new();
        for i in 0..n {
            for j in (i + 1)..n {
                if rng.gen::<f64>() <= self.probability {
                    edges.insert((i, j));
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
    fn full_graph_with_probability_one() {
        let topo = ErdosRenyiTopology::new(1.0).unwrap();
        let mut rng = StdRng::seed_from_u64(11);
        let edges = topo.build(4, &mut rng).unwrap();
        let degrees = ensure_degree(4, &edges);
        assert!(degrees.iter().all(|&d| d == 3));
        assert_eq!(largest_component_size(4, &edges), 4);
    }
}
