//! Node-side verification plumbing for Plonky3 proof artifacts.

use blake3::Hasher;
use serde_json::Value;
use tracing::error;

use crate::errors::{ChainError, ChainResult};
use crate::proof_system::ProofVerifier;
use crate::rpp::ProofSystemKind;
use crate::types::{BlockProofBundle, ChainProof};

use super::crypto;
use super::proof::Plonky3Proof;

#[derive(Clone, Debug, Default)]
pub struct Plonky3Verifier;

impl Plonky3Verifier {
    fn decode_proof(proof: &ChainProof, expected: &str) -> ChainResult<Plonky3Proof> {
        let value = match proof {
            ChainProof::Plonky3(value) => value,
            ChainProof::Stwo(_) => {
                return Err(ChainError::Crypto(
                    "received STWO proof where Plonky3 artifact was required".into(),
                ));
            }
        };
        let parsed = Plonky3Proof::from_value(value)?;
        if parsed.circuit != expected {
            let message = format!("expected {expected} circuit, received {}", parsed.circuit);
            error!("{message}");
            return Err(ChainError::Crypto(message));
        }
        if let Err(err) = crypto::verify_transcript(&parsed) {
            error!("plonky3 transcript verification failed for {expected}: {err}");
            return Err(err);
        }
        Ok(parsed)
    }

    fn check_recursive_inputs(
        proof: &Plonky3Proof,
        expected_commitments: &[String],
        expected_previous: Option<&str>,
    ) -> ChainResult<()> {
        let commitments = proof
            .public_inputs
            .get("commitments")
            .and_then(Value::as_array)
            .ok_or_else(|| {
                ChainError::Crypto("recursive proof missing commitments array".into())
            })?;
        let recorded: Vec<String> = commitments
            .iter()
            .map(|value| {
                value.as_str().map(str::to_owned).ok_or_else(|| {
                    ChainError::Crypto("recursive proof commitments must be hex strings".into())
                })
            })
            .collect::<ChainResult<_>>()?;
        for commitment in expected_commitments {
            if !recorded.iter().any(|value| value == commitment) {
                let message =
                    format!("recursive proof is missing commitment {commitment} from bundle");
                error!("{message}");
                return Err(ChainError::Crypto(message));
            }
        }
        if let Some(previous) = expected_previous {
            if !recorded.iter().any(|value| value == previous) {
                let message =
                    format!("recursive proof does not reference previous accumulator {previous}");
                error!("{message}");
                return Err(ChainError::Crypto(message));
            }
        }
        let accumulator = proof
            .public_inputs
            .get("accumulator")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                ChainError::Crypto("recursive proof missing accumulator field".into())
            })?;
        let mut hasher = Hasher::new();
        for entry in &recorded {
            hasher.update(entry.as_bytes());
        }
        let expected_accumulator = hasher.finalize().to_hex().to_string();
        if accumulator != expected_accumulator {
            let message = format!(
                "recursive proof accumulator mismatch: expected {expected_accumulator}, found {accumulator}"
            );
            error!("{message}");
            return Err(ChainError::Crypto(message));
        }
        Ok(())
    }

    pub fn verify_bundle(
        &self,
        bundle: &BlockProofBundle,
        expected_previous_commitment: Option<&str>,
    ) -> ChainResult<()> {
        let mut commitments = Vec::new();
        for proof in &bundle.transaction_proofs {
            let parsed = Self::decode_proof(proof, "transaction")?;
            commitments.push(parsed.commitment);
        }
        let state = Self::decode_proof(&bundle.state_proof, "state")?;
        commitments.push(state.commitment.clone());
        let pruning = Self::decode_proof(&bundle.pruning_proof, "pruning")?;
        commitments.push(pruning.commitment.clone());
        let recursive = Self::decode_proof(&bundle.recursive_proof, "recursive")?;
        Self::check_recursive_inputs(&recursive, &commitments, expected_previous_commitment)
    }
}

impl ProofVerifier for Plonky3Verifier {
    fn system(&self) -> ProofSystemKind {
        ProofSystemKind::Plonky3
    }

    fn verify_transaction(&self, proof: &ChainProof) -> ChainResult<()> {
        Self::decode_proof(proof, "transaction").map(|_| ())
    }

    fn verify_identity(&self, proof: &ChainProof) -> ChainResult<()> {
        Self::decode_proof(proof, "identity").map(|_| ())
    }

    fn verify_state(&self, proof: &ChainProof) -> ChainResult<()> {
        Self::decode_proof(proof, "state").map(|_| ())
    }

    fn verify_pruning(&self, proof: &ChainProof) -> ChainResult<()> {
        Self::decode_proof(proof, "pruning").map(|_| ())
    }

    fn verify_recursive(&self, proof: &ChainProof) -> ChainResult<()> {
        Self::decode_proof(proof, "recursive").map(|_| ())
    }

    fn verify_uptime(&self, proof: &ChainProof) -> ChainResult<()> {
        Self::decode_proof(proof, "uptime").map(|_| ())
    }

    fn verify_consensus(&self, proof: &ChainProof) -> ChainResult<()> {
        Self::decode_proof(proof, "consensus").map(|_| ())
    }
}
