#[cfg(test)]
use std::collections::VecDeque;

use anyhow::{anyhow, Result};
use rand::Rng;

use crate::scenario::{LinkParams, LinksSection};

pub mod erdos_renyi;
pub mod k_regular;
pub mod ring;
pub mod scale_free;
pub mod small_world;

pub use erdos_renyi::ErdosRenyiTopology;
pub use k_regular::KRegularTopology;
pub use ring::RingTopology;
pub use scale_free::ScaleFreeTopology;
pub use small_world::SmallWorldTopology;

pub trait Topology {
    fn build(&self, n: usize, rng: &mut impl Rng) -> Result<Vec<(usize, usize)>>;
}

#[derive(Debug, Clone)]
pub struct AnnotatedLink {
    pub a: usize,
    pub b: usize,
    pub params: LinkParams,
}

pub fn annotate_links(
    edges: &[(usize, usize)],
    regions: &[String],
    links: &LinksSection,
) -> Result<Vec<AnnotatedLink>> {
    if regions.len() < edges.iter().map(|(a, b)| (*a).max(*b)).max().unwrap_or(0) + 1 {
        return Err(anyhow!("region assignments must cover all nodes"));
    }

    let mut annotated = Vec::with_capacity(edges.len());
    for &(a, b) in edges {
        let region_a = &regions[a];
        let region_b = &regions[b];
        let params = resolve_link_params(region_a, region_b, links).ok_or_else(|| {
            anyhow!("no link parameters configured for regions {region_a:?} and {region_b:?}")
        })?;
        annotated.push(AnnotatedLink {
            a,
            b,
            params: params.clone(),
        });
    }
    Ok(annotated)
}

fn resolve_link_params<'a>(a: &str, b: &str, links: &'a LinksSection) -> Option<&'a LinkParams> {
    if a == b {
        if let Some(params) = links.entries.get(&format!("{a}-{b}")) {
            return Some(params);
        }
        if let Some(params) = links.entries.get("intra") {
            return Some(params);
        }
    } else {
        let key = format!("{a}-{b}");
        if let Some(params) = links.entries.get(&key) {
            return Some(params);
        }
        let alt = format!("{b}-{a}");
        if let Some(params) = links.entries.get(&alt) {
            return Some(params);
        }
    }
    links.entries.get("default")
}

pub(crate) fn ensure_degree(n: usize, edges: &[(usize, usize)]) -> Vec<usize> {
    let mut degrees = vec![0usize; n];
    for &(a, b) in edges {
        degrees[a] += 1;
        degrees[b] += 1;
    }
    degrees
}

#[cfg(test)]
pub(crate) fn largest_component_size(n: usize, edges: &[(usize, usize)]) -> usize {
    let mut adjacency = vec![Vec::new(); n];
    for &(a, b) in edges {
        adjacency[a].push(b);
        adjacency[b].push(a);
    }
    let mut visited = vec![false; n];
    let mut best = 0;
    for start in 0..n {
        if visited[start] {
            continue;
        }
        let mut queue = VecDeque::new();
        queue.push_back(start);
        visited[start] = true;
        let mut size = 0;
        while let Some(node) = queue.pop_front() {
            size += 1;
            for &next in &adjacency[node] {
                if !visited[next] {
                    visited[next] = true;
                    queue.push_back(next);
                }
            }
        }
        best = best.max(size);
    }
    best
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use crate::scenario::{LinkParams, LinksSection};

    use super::*;

    #[test]
    fn annotate_links_uses_region_specific_params() {
        let edges = vec![(0, 1), (1, 2), (0, 2)];
        let regions = vec!["EU".to_string(), "US".to_string(), "EU".to_string()];
        let mut entries = HashMap::new();
        entries.insert(
            "EU-US".to_string(),
            LinkParams {
                delay_ms: 50,
                jitter_ms: 5,
                loss: 0.5,
            },
        );
        entries.insert(
            "intra".to_string(),
            LinkParams {
                delay_ms: 10,
                jitter_ms: 1,
                loss: 0.1,
            },
        );
        let links = LinksSection { entries };
        let annotated = annotate_links(&edges, &regions, &links).expect("annotated");
        assert_eq!(annotated.len(), 3);
        let eu_us = annotated
            .iter()
            .find(|edge| (edge.a, edge.b) == (0, 1))
            .unwrap();
        assert_eq!(eu_us.params.delay_ms, 50);
        let eu_eu = annotated
            .iter()
            .find(|edge| (edge.a, edge.b) == (0, 2))
            .unwrap();
        assert_eq!(eu_eu.params.delay_ms, 10);
    }
}
