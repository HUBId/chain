//! Deterministic FRI-style polynomial commitment scaffolding.
//!
//! This module provides a lightweight polynomial commitment builder that
//! emulates the structure of a FRI prover. While it does not implement the
//! full low-level cryptographic primitives of a production STARK backend, the
//! scaffolding computes deterministic folding challenges, evaluation queries,
//! and Poseidon-backed Merkle commitments so that verifiers can faithfully
//! reproduce the prover's output. The resulting artifacts are embedded in
//! [`StarkProof`](crate::stwo::proof::StarkProof) instances.

use std::collections::HashSet;

use num_bigint::BigUint;
use num_traits::ToPrimitive;

use crate::stwo::circuit::ExecutionTrace;
use crate::stwo::params::{FieldElement, PoseidonHasher, StarkParameters};
use crate::stwo::proof::{FriProof, FriQuery, PolynomialCommitment};

/// Number of queries collected for every column commitment.
const DEFAULT_QUERY_COUNT: usize = 4;

/// Helper encapsulating the deterministic FRI-style commitment process.
pub struct FriProver<'a> {
    parameters: &'a StarkParameters,
    hasher: PoseidonHasher,
    query_count: usize,
}

impl<'a> FriProver<'a> {
    /// Create a prover helper backed by the supplied STARK parameters.
    pub fn new(parameters: &'a StarkParameters) -> Self {
        Self {
            parameters,
            hasher: parameters.poseidon_hasher(),
            query_count: DEFAULT_QUERY_COUNT,
        }
    }

    /// Override the number of queries collected for every column commitment.
    #[allow(dead_code)]
    pub fn with_query_count(mut self, queries: usize) -> Self {
        self.query_count = queries.max(1);
        self
    }

    /// Generate a deterministic FRI-style commitment proof for the supplied
    /// execution trace and public inputs.
    pub fn prove(&self, trace: &ExecutionTrace, public_inputs: &[FieldElement]) -> FriProof {
        let challenges = self.derive_challenges(trace, public_inputs);
        let mut commitments = Vec::new();
        for segment in &trace.segments {
            let domain_size = next_power_of_two(segment.rows.len());
            for (column_index, column_name) in segment.columns.iter().enumerate() {
                let mut evaluations = Vec::with_capacity(domain_size);
                for row in &segment.rows {
                    evaluations.push(row[column_index].clone());
                }
                while evaluations.len() < domain_size {
                    evaluations.push(FieldElement::zero(self.parameters.modulus()));
                }
                let leaf_hashes = self.hash_leaves(&evaluations);
                let tree = build_merkle_tree(&self.hasher, leaf_hashes);
                let root = tree
                    .last()
                    .and_then(|level| level.first())
                    .cloned()
                    .unwrap_or_else(|| FieldElement::zero(self.parameters.modulus()));
                let label = format!("{}::{}", segment.name, column_name);
                let queries = self.build_queries(
                    &label,
                    domain_size,
                    &evaluations,
                    &tree,
                    public_inputs,
                    &challenges,
                );
                commitments.push(PolynomialCommitment {
                    segment: segment.name.clone(),
                    column: column_name.clone(),
                    domain_size,
                    merkle_root: root,
                    queries,
                });
            }
        }
        FriProof {
            commitments,
            challenges,
        }
    }

    fn derive_challenges(
        &self,
        trace: &ExecutionTrace,
        public_inputs: &[FieldElement],
    ) -> Vec<FieldElement> {
        let mut sponge = self.hasher.sponge();
        sponge.absorb_elements(public_inputs);
        for segment in &trace.segments {
            let name_element =
                FieldElement::from_bytes(segment.name.as_bytes(), self.hasher.modulus());
            sponge.absorb_elements(&[name_element]);
            for column in &segment.columns {
                let column_element =
                    FieldElement::from_bytes(column.as_bytes(), self.hasher.modulus());
                sponge.absorb_elements(&[column_element]);
            }
        }
        sponge.finish_absorbing();
        sponge.squeeze_many(2)
    }

    fn build_queries(
        &self,
        label: &str,
        domain_size: usize,
        evaluations: &[FieldElement],
        tree: &[Vec<FieldElement>],
        public_inputs: &[FieldElement],
        challenges: &[FieldElement],
    ) -> Vec<FriQuery> {
        let indices = self.derive_query_indices(label, domain_size, public_inputs, challenges);
        indices
            .into_iter()
            .map(|index| {
                let evaluation = evaluations[index].clone();
                let auth_path = build_authentication_path(tree, index);
                FriQuery {
                    index,
                    evaluation,
                    auth_path,
                }
            })
            .collect()
    }

    fn derive_query_indices(
        &self,
        label: &str,
        domain_size: usize,
        public_inputs: &[FieldElement],
        challenges: &[FieldElement],
    ) -> Vec<usize> {
        if domain_size == 0 {
            return vec![];
        }
        let mut sponge = self.hasher.sponge();
        sponge.absorb_elements(public_inputs);
        sponge.absorb_elements(challenges);
        sponge.absorb_bytes(&[label.as_bytes().to_vec()]);
        sponge.finish_absorbing();
        let modulus = BigUint::from(domain_size);
        let mut indices = Vec::with_capacity(self.query_count);
        let mut seen = HashSet::new();
        while indices.len() < self.query_count {
            let element = sponge.squeeze();
            let value = element.value() % &modulus;
            let index = value
                .to_usize()
                .unwrap_or_else(|| (value % &modulus).to_usize().unwrap_or(0));
            if seen.insert(index) {
                indices.push(index);
            }
        }
        indices.sort_unstable();
        indices
    }

    fn hash_leaves(&self, evaluations: &[FieldElement]) -> Vec<FieldElement> {
        evaluations
            .iter()
            .enumerate()
            .map(|(index, value)| {
                let index_element = FieldElement::from_u64(index as u64, self.parameters.modulus());
                self.hasher.hash(&[value.clone(), index_element])
            })
            .collect()
    }
}

fn next_power_of_two(value: usize) -> usize {
    match value {
        0 => 1,
        1 => 1,
        _ => value.next_power_of_two(),
    }
}

fn build_merkle_tree(hasher: &PoseidonHasher, leaves: Vec<FieldElement>) -> Vec<Vec<FieldElement>> {
    let mut levels = Vec::new();
    if leaves.is_empty() {
        return levels;
    }
    let mut current = leaves;
    levels.push(current.clone());
    while current.len() > 1 {
        if current.len() % 2 == 1 {
            let last = current.last().cloned().unwrap();
            current.push(last);
        }
        let mut next = Vec::with_capacity(current.len() / 2);
        for chunk in current.chunks(2) {
            let left = chunk[0].clone();
            let right = chunk[1].clone();
            next.push(hasher.hash(&[left, right]));
        }
        levels.push(next.clone());
        current = next;
    }
    levels
}

fn build_authentication_path(tree: &[Vec<FieldElement>], mut index: usize) -> Vec<FieldElement> {
    let mut path = Vec::new();
    if tree.is_empty() {
        return path;
    }
    for level in tree.iter() {
        if level.len() == 1 {
            break;
        }
        let sibling_index = if index % 2 == 0 { index + 1 } else { index - 1 };
        let sibling = level
            .get(sibling_index)
            .cloned()
            .unwrap_or_else(|| level[index].clone());
        path.push(sibling);
        index /= 2;
    }
    path
}
