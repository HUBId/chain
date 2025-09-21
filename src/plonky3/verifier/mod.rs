//! Node-side verification plumbing for Plonky3 proof artifacts.

use crate::errors::{ChainError, ChainResult};
use crate::proof_system::ProofVerifier;
use crate::rpp::ProofSystemKind;
use crate::types::{BlockProofBundle, ChainProof};

/// Deterministic verifier placeholder that only checks circuit tags for now.
#[derive(Clone, Debug, Default)]
pub struct Plonky3Verifier;

impl Plonky3Verifier {
    fn ensure_circuit(proof: &ChainProof, expected: &str) -> ChainResult<()> {
        match proof {
            ChainProof::Plonky3(value) => {
                let circuit = value
                    .get("circuit")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| {
                        ChainError::Crypto(
                            "plonky3 placeholder proof missing circuit identifier".into(),
                        )
                    })?;
                if circuit != expected {
                    return Err(ChainError::Crypto(format!(
                        "expected {expected} circuit, received {circuit}"
                    )));
                }
                Ok(())
            }
            ChainProof::Stwo(_) => Err(ChainError::Crypto(
                "received STWO proof where Plonky3 artifact was required".into(),
            )),
        }
    }

    pub fn verify_bundle(
        &self,
        bundle: &BlockProofBundle,
        _expected_previous_commitment: Option<&str>,
    ) -> ChainResult<()> {
        for proof in &bundle.transaction_proofs {
            Self::ensure_circuit(proof, "transaction")?;
        }
        Self::ensure_circuit(&bundle.state_proof, "state")?;
        Self::ensure_circuit(&bundle.pruning_proof, "pruning")?;
        Self::ensure_circuit(&bundle.recursive_proof, "recursive")?;
        Ok(())
    }
}

impl ProofVerifier for Plonky3Verifier {
    fn system(&self) -> ProofSystemKind {
        ProofSystemKind::Plonky3
    }

    fn verify_transaction(&self, proof: &ChainProof) -> ChainResult<()> {
        Self::ensure_circuit(proof, "transaction")
    }

    fn verify_identity(&self, proof: &ChainProof) -> ChainResult<()> {
        Self::ensure_circuit(proof, "identity")
    }

    fn verify_state(&self, proof: &ChainProof) -> ChainResult<()> {
        Self::ensure_circuit(proof, "state")
    }

    fn verify_pruning(&self, proof: &ChainProof) -> ChainResult<()> {
        Self::ensure_circuit(proof, "pruning")
    }

    fn verify_recursive(&self, proof: &ChainProof) -> ChainResult<()> {
        Self::ensure_circuit(proof, "recursive")
    }

    fn verify_uptime(&self, proof: &ChainProof) -> ChainResult<()> {
        Self::ensure_circuit(proof, "uptime")
    }

    fn verify_consensus(&self, proof: &ChainProof) -> ChainResult<()> {
        Self::ensure_circuit(proof, "consensus")
    }
}
