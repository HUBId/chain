//! Node-side verification plumbing for Plonky3 proof artifacts.

use blake3::Hasher;
use serde_json::Value;
use thiserror::Error;
use tracing::error;

use crate::errors::{ChainError, ChainResult};
use crate::proof_system::ProofVerifier;
use crate::rpp::ProofSystemKind;
use crate::types::{BlockProofBundle, ChainProof};

use super::crypto;
use super::proof::Plonky3Proof;

#[derive(Debug, Error)]
enum Plonky3VerificationError {
    #[error("{message}")]
    Malformed { message: String },
    #[error("{message}")]
    Misconfigured { message: String },
    #[error("{message}")]
    VerificationFailed { message: String },
}

impl Plonky3VerificationError {
    fn malformed(circuit: &str, detail: impl Into<String>) -> Self {
        Self::Malformed {
            message: format!("plonky3 {circuit} proof is malformed: {}", detail.into()),
        }
    }

    fn misconfigured(circuit: &str, detail: impl Into<String>) -> Self {
        Self::Misconfigured {
            message: format!(
                "plonky3 verifier misconfigured for {circuit} circuit: {}",
                detail.into()
            ),
        }
    }

    fn verification(circuit: &str, detail: impl Into<String>) -> Self {
        Self::VerificationFailed {
            message: format!("plonky3 {circuit} proof rejected: {}", detail.into()),
        }
    }
}

impl From<Plonky3VerificationError> for ChainError {
    fn from(err: Plonky3VerificationError) -> Self {
        match err {
            Plonky3VerificationError::Misconfigured { message } => ChainError::Config(message),
            Plonky3VerificationError::Malformed { message }
            | Plonky3VerificationError::VerificationFailed { message } => {
                ChainError::Crypto(message)
            }
        }
    }
}

#[derive(Clone, Debug)]
pub struct Plonky3Verifier;

impl Plonky3Verifier {
    fn decode_chain_value<'a>(
        proof: &'a ChainProof,
        expected: &str,
    ) -> Result<&'a serde_json::Value, Plonky3VerificationError> {
        match proof {
            ChainProof::Plonky3(value) => Ok(value),
            ChainProof::Stwo(_) => {
                let message = "received STWO proof where Plonky3 artifact was required".to_string();
                error!("plonky3 {expected} proof decode failure: {message}");
                Err(Plonky3VerificationError::malformed(expected, message))
            }
        }
    }

    fn decode_proof(
        proof: &ChainProof,
        expected: &str,
    ) -> Result<Plonky3Proof, Plonky3VerificationError> {
        let value = Self::decode_chain_value(proof, expected)?;
        let parsed = Plonky3Proof::from_value(value).map_err(|err| {
            error!("plonky3 {expected} proof decode failure: {err}");
            Plonky3VerificationError::malformed(expected, err.to_string())
        })?;
        if parsed.circuit != expected {
            let message = format!("expected {expected} circuit, received {}", parsed.circuit);
            error!("plonky3 {expected} proof decode failure: {message}");
            return Err(Plonky3VerificationError::malformed(expected, message));
        }

        let expected_commitment =
            crypto::compute_commitment(&parsed.public_inputs).map_err(|err| {
                error!("plonky3 {expected} proof commitment computation failed: {err}");
                Plonky3VerificationError::malformed(expected, err.to_string())
            })?;
        if parsed.commitment != expected_commitment {
            let message = format!(
                "commitment mismatch: expected {expected_commitment}, found {}",
                parsed.commitment
            );
            error!("plonky3 {expected} proof verification failed: {message}");
            return Err(Plonky3VerificationError::verification(expected, message));
        }

        crypto::verify_proof(&parsed).map_err(|err| {
            error!("plonky3 {expected} proof verification failed: {err}");
            Plonky3VerificationError::verification(expected, err.to_string())
        })?;

        Ok(parsed)
    }

    fn check_recursive_inputs(
        proof: &Plonky3Proof,
        expected_commitments: &[String],
        expected_previous: Option<&str>,
    ) -> Result<(), Plonky3VerificationError> {
        let commitments_field = proof
            .public_inputs
            .get("commitments")
            .or_else(|| {
                proof
                    .public_inputs
                    .get("witness")
                    .and_then(Value::as_object)
                    .and_then(|object| object.get("commitments"))
            })
            .and_then(Value::as_array)
            .ok_or_else(|| {
                let detail = "recursive proof missing commitments array";
                error!("plonky3 recursive proof verification failed: {detail}");
                Plonky3VerificationError::malformed("recursive", detail)
            })?;

        let recorded: Result<Vec<String>, Plonky3VerificationError> = commitments_field
            .iter()
            .map(|value| {
                value.as_str().map(str::to_owned).ok_or_else(|| {
                    let detail = "recursive proof commitments must be encoded as hex strings";
                    error!("plonky3 recursive proof verification failed: {detail}");
                    Plonky3VerificationError::malformed("recursive", detail)
                })
            })
            .collect();
        let recorded = recorded?;

        for commitment in expected_commitments {
            if !recorded.iter().any(|value| value == commitment) {
                let message =
                    format!("recursive proof is missing commitment {commitment} from bundle");
                error!("plonky3 recursive proof verification failed: {message}");
                return Err(Plonky3VerificationError::verification("recursive", message));
            }
        }

        if let Some(previous) = expected_previous {
            if !recorded.iter().any(|value| value == previous) {
                let message =
                    format!("recursive proof does not reference previous accumulator {previous}");
                error!("plonky3 recursive proof verification failed: {message}");
                return Err(Plonky3VerificationError::verification("recursive", message));
            }
        }

        let accumulator_value = proof
            .public_inputs
            .get("accumulator")
            .or_else(|| {
                proof
                    .public_inputs
                    .get("witness")
                    .and_then(Value::as_object)
                    .and_then(|object| object.get("accumulator"))
            })
            .and_then(Value::as_str)
            .ok_or_else(|| {
                let detail = "recursive proof missing accumulator field";
                error!("plonky3 recursive proof verification failed: {detail}");
                Plonky3VerificationError::malformed("recursive", detail)
            })?;

        let mut hasher = Hasher::new();
        for entry in &recorded {
            hasher.update(entry.as_bytes());
        }
        let expected_accumulator = hasher.finalize().to_hex().to_string();
        if accumulator_value != expected_accumulator {
            let message = format!(
                "accumulator mismatch: expected {expected_accumulator}, found {accumulator_value}"
            );
            error!("plonky3 recursive proof verification failed: {message}");
            return Err(Plonky3VerificationError::verification("recursive", message));
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
            let parsed = Self::decode_proof(proof, "transaction").map_err(ChainError::from)?;
            commitments.push(parsed.commitment);
        }
        let state = Self::decode_proof(&bundle.state_proof, "state").map_err(ChainError::from)?;
        commitments.push(state.commitment.clone());
        let pruning =
            Self::decode_proof(&bundle.pruning_proof, "pruning").map_err(ChainError::from)?;
        commitments.push(pruning.commitment.clone());
        let recursive =
            Self::decode_proof(&bundle.recursive_proof, "recursive").map_err(ChainError::from)?;
        Self::check_recursive_inputs(&recursive, &commitments, expected_previous_commitment)
            .map_err(ChainError::from)
    }
}

impl Default for Plonky3Verifier {
    fn default() -> Self {
        if let Err(err) = crate::plonky3::experimental::require_acknowledgement() {
            panic!("{err}");
        }
        Self
    }
}

impl ProofVerifier for Plonky3Verifier {
    fn system(&self) -> ProofSystemKind {
        ProofSystemKind::Plonky3
    }

    fn verify_transaction(&self, proof: &ChainProof) -> ChainResult<()> {
        Self::decode_proof(proof, "transaction")
            .map(|_| ())
            .map_err(ChainError::from)
    }

    fn verify_identity(&self, proof: &ChainProof) -> ChainResult<()> {
        Self::decode_proof(proof, "identity")
            .map(|_| ())
            .map_err(ChainError::from)
    }

    fn verify_state(&self, proof: &ChainProof) -> ChainResult<()> {
        Self::decode_proof(proof, "state")
            .map(|_| ())
            .map_err(ChainError::from)
    }

    fn verify_pruning(&self, proof: &ChainProof) -> ChainResult<()> {
        Self::decode_proof(proof, "pruning")
            .map(|_| ())
            .map_err(ChainError::from)
    }

    fn verify_recursive(&self, proof: &ChainProof) -> ChainResult<()> {
        Self::decode_proof(proof, "recursive")
            .map(|_| ())
            .map_err(ChainError::from)
    }

    fn verify_uptime(&self, proof: &ChainProof) -> ChainResult<()> {
        Self::decode_proof(proof, "uptime")
            .map(|_| ())
            .map_err(ChainError::from)
    }

    fn verify_consensus(&self, proof: &ChainProof) -> ChainResult<()> {
        Self::decode_proof(proof, "consensus")
            .map(|_| ())
            .map_err(ChainError::from)
    }
}
