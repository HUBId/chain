use anyhow::{anyhow, Result};
use rand::distributions::{Distribution, WeightedIndex};
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};

#[derive(Debug)]
pub struct PublisherSelectorBuilder;

impl PublisherSelectorBuilder {
    pub fn uniform(seed: u64) -> PublisherSelector {
        PublisherSelector::Uniform(StdRng::seed_from_u64(seed))
    }

    pub fn zipf(seed: u64, s: f64) -> Result<PublisherSelector> {
        if s <= 0.0 {
            return Err(anyhow!("zipf s parameter must be positive"));
        }
        Ok(PublisherSelector::Zipf {
            rng: StdRng::seed_from_u64(seed),
            s,
        })
    }
}

#[derive(Debug)]
pub enum PublisherSelector {
    Uniform(StdRng),
    Zipf { rng: StdRng, s: f64 },
}

impl PublisherSelector {
    pub fn pick(&mut self, n: usize) -> Option<usize> {
        match self {
            PublisherSelector::Uniform(rng) => {
                if n == 0 {
                    None
                } else {
                    Some(rng.gen_range(0, n))
                }
            }
            PublisherSelector::Zipf { rng, s } => {
                if n == 0 {
                    return None;
                }
                let weights: Vec<f64> = (1..=n).map(|k| (k as f64).powf(-*s)).collect();
                let dist = WeightedIndex::new(&weights).ok()?;
                Some(dist.sample(rng))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zipf_bias_prefers_low_indices() {
        let mut selector = PublisherSelectorBuilder::zipf(17, 1.2).unwrap();
        let mut counts = vec![0usize; 6];
        for _ in 0..50_000 {
            let idx = selector.pick(6).unwrap();
            counts[idx] += 1;
        }
        assert!(counts[0] > counts[5], "first index should be more frequent");
        let ratio = counts[0] as f64 / counts[5] as f64;
        let expected = (6f64).powf(1.2);
        assert!(ratio > expected * 0.4, "ratio {ratio} expected {expected}");
    }
}
