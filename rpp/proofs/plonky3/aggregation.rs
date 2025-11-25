//! Helpers for validating recursive aggregation inputs in the Plonky3 backend.

use crate::errors::{ChainError, ChainResult};
use crate::types::ChainProof;

use serde_json::Value;

use super::circuit::consensus::ConsensusWitness;
use super::circuit::recursive::RecursiveWitness;
use super::crypto;
use super::params::Plonky3Parameters;
use super::proof::Plonky3Proof;
use super::prover::Plonky3Backend;

/// Maximum number of proofs that may be folded into a single recursive batch.
///
/// This bound keeps aggregation witnesses and prover telemetry in a predictable
/// range for CI and wallet workloads.
pub(crate) const MAX_BATCHED_PROOFS: usize = 64;

pub(super) struct RecursiveAggregator {
    backend: Plonky3Backend,
    params: Plonky3Parameters,
}

impl RecursiveAggregator {
    pub fn new(params: Plonky3Parameters, backend: Plonky3Backend) -> Self {
        Self { backend, params }
    }

    fn ensure_batch_size(witness: &RecursiveWitness) -> ChainResult<()> {
        let total = witness.identity_proofs.len()
            + witness.transaction_proofs.len()
            + witness.uptime_proofs.len()
            + witness.consensus_proofs.len()
            + usize::from(witness.previous_recursive.is_some());
        if total > MAX_BATCHED_PROOFS {
            return Err(ChainError::Config(format!(
                "recursive aggregation batch of {total} proofs exceeds limit {MAX_BATCHED_PROOFS}"
            )));
        }
        Ok(())
    }

    fn decode_and_verify(proof: &ChainProof, expected: &str) -> ChainResult<Plonky3Proof> {
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
        crypto::verify_proof(&parsed)?;
        Ok(parsed)
    }

    fn validate_group(proofs: &[ChainProof], expected: &str) -> ChainResult<Vec<Plonky3Proof>> {
        proofs
            .iter()
            .map(|proof| Self::decode_and_verify(proof, expected))
            .collect()
    }

    fn extract_consensus_witness(public_inputs: &Value) -> ChainResult<ConsensusWitness> {
        let witness_value = public_inputs.get("witness").cloned().ok_or_else(|| {
            ChainError::Crypto(
                "consensus proof missing witness payload in Plonky3 public inputs".into(),
            )
        })?;
        serde_json::from_value(witness_value).map_err(|err| {
            ChainError::Crypto(format!(
                "invalid consensus witness payload in Plonky3 proof: {err}"
            ))
        })
    }

    fn ensure_consensus_metadata(proofs: &[Plonky3Proof]) -> ChainResult<()> {
        for proof in proofs {
            let witness = Self::extract_consensus_witness(&proof.public_inputs)?;
            witness.validate_metadata()?;
        }
        Ok(())
    }

    pub fn finalize(&self, witness: &RecursiveWitness) -> ChainResult<Plonky3Proof> {
        Self::ensure_batch_size(witness)?;
        if let Some(previous) = &witness.previous_recursive {
            Self::decode_and_verify(previous, "recursive")?;
        }
        drop(Self::validate_group(&witness.identity_proofs, "identity")?);
        drop(Self::validate_group(
            &witness.transaction_proofs,
            "transaction",
        )?);
        drop(Self::validate_group(&witness.uptime_proofs, "uptime")?);
        let consensus_proofs = Self::validate_group(&witness.consensus_proofs, "consensus")?;
        Self::ensure_consensus_metadata(&consensus_proofs)?;
        Self::decode_and_verify(&witness.state_proof, "state")?;
        Self::decode_and_verify(&witness.pruning_proof, "pruning")?;
        self.backend.prove(&self.params, witness)
    }
}
