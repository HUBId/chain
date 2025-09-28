//! Deterministic FRI-style polynomial commitment scaffolding.
//!
//! This module provides a lightweight polynomial commitment builder that
//! emulates the structure of a FRI prover. While it does not implement the
//! full low-level cryptographic primitives of a production STARK backend, the
//! scaffolding produces deterministic field-element transcripts that can be
//! wrapped into the official STWO FRI proof structures. The resulting artifacts
//! are embedded in [`StarkProof`](crate::stwo::proof::StarkProof) instances.

use crate::stwo::circuit::ExecutionTrace;
use crate::stwo::params::{FieldElement, PoseidonHasher, StarkParameters};
use crate::stwo::proof::FriProof;

/// Helper encapsulating the deterministic FRI-style commitment process.
pub struct FriProver<'a> {
    parameters: &'a StarkParameters,
    hasher: PoseidonHasher,
}

impl<'a> FriProver<'a> {
    /// Create a prover helper backed by the supplied STARK parameters.
    pub fn new(parameters: &'a StarkParameters) -> Self {
        Self {
            parameters,
            hasher: parameters.poseidon_hasher(),
        }
    }

    /// Generate a deterministic FRI-style commitment proof for the supplied
    /// execution trace and public inputs.
    pub fn prove(&self, trace: &ExecutionTrace, public_inputs: &[FieldElement]) -> FriProof {
        let mut elements = Vec::new();
        elements.extend_from_slice(public_inputs);

        let challenges = self.derive_challenges(trace, public_inputs);
        elements.extend(challenges.iter().cloned());

        for segment in &trace.segments {
            let name_element =
                FieldElement::from_bytes(segment.name.as_bytes(), self.parameters.modulus());
            elements.push(name_element);
            for column in &segment.columns {
                let column_element =
                    FieldElement::from_bytes(column.as_bytes(), self.parameters.modulus());
                elements.push(column_element);
            }
            for row in &segment.rows {
                elements.extend(row.iter().cloned());
            }
        }

        FriProof::from_elements(&elements)
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
}
