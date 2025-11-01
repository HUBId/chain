//! Helpers for validating recursive aggregation inputs in the Plonky3 backend.

use crate::errors::{ChainError, ChainResult};
use crate::types::ChainProof;

use super::circuit::recursive::RecursiveWitness;
use super::crypto;
use super::params::Plonky3Parameters;
use super::proof::Plonky3Proof;
use super::prover::Plonky3Backend;

pub(super) struct RecursiveAggregator {
    backend: Plonky3Backend,
    params: Plonky3Parameters,
}

impl RecursiveAggregator {
    pub fn new(params: Plonky3Parameters, backend: Plonky3Backend) -> Self {
        Self { backend, params }
    }

    fn decode_and_verify(proof: &ChainProof, expected: &str) -> ChainResult<()> {
        let value = match proof {
            ChainProof::Plonky3(value) => value,
            ChainProof::Stwo(_) => {
                return Err(ChainError::Crypto(
                    "cannot aggregate STWO proof inside Plonky3 recursion".into(),
                ));
            }
        };
        let parsed = Plonky3Proof::from_value(value)?;
        if parsed.circuit != expected {
            return Err(ChainError::Crypto(format!(
                "expected {expected} proof inside recursive aggregation, found {}",
                parsed.circuit
            )));
        }
        crypto::verify_proof(&parsed)
    }

    fn validate_group(proofs: &[ChainProof], expected: &str) -> ChainResult<()> {
        for proof in proofs {
            Self::decode_and_verify(proof, expected)?;
        }
        Ok(())
    }

    pub fn finalize(&self, witness: &RecursiveWitness) -> ChainResult<Plonky3Proof> {
        if let Some(previous) = &witness.previous_recursive {
            Self::decode_and_verify(previous, "recursive")?;
        }
        Self::validate_group(&witness.identity_proofs, "identity")?;
        Self::validate_group(&witness.transaction_proofs, "transaction")?;
        Self::validate_group(&witness.uptime_proofs, "uptime")?;
        Self::validate_group(&witness.consensus_proofs, "consensus")?;
        Self::decode_and_verify(&witness.state_proof, "state")?;
        Self::decode_and_verify(&witness.pruning_proof, "pruning")?;
        self.backend.prove(&self.params, witness)
    }
}
