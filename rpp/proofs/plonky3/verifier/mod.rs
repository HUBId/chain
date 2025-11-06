//! Node-side verification plumbing for Plonky3 proof artifacts.

use blake3::Hasher;
use serde_json::Value;
use tracing::error;

use crate::errors::{ChainError, ChainResult};
use crate::proof_system::ProofVerifier;
use crate::rpp::ProofSystemKind;
use crate::types::{BlockProofBundle, ChainProof};

use super::crypto::{self, map_backend_error};
use super::proof::Plonky3Proof;
use plonky3_backend::validate_consensus_public_inputs;

#[derive(Clone, Debug)]
pub struct Plonky3Verifier;

pub fn telemetry_snapshot() -> crypto::Plonky3VerifierHealth {
    crypto::verifier_telemetry_snapshot()
}

impl Plonky3Verifier {
    fn malformed(circuit: &str, detail: impl Into<String>) -> ChainError {
        ChainError::InvalidProof(format!(
            "plonky3 {circuit} proof is malformed: {}",
            detail.into()
        ))
    }

    fn verification_failed(circuit: &str, detail: impl Into<String>) -> ChainError {
        ChainError::InvalidProof(format!(
            "plonky3 {circuit} proof rejected: {}",
            detail.into()
        ))
    }

    fn decode_chain_value<'a>(
        proof: &'a ChainProof,
        expected: &str,
    ) -> ChainResult<&'a serde_json::Value> {
        match proof {
            ChainProof::Plonky3(value) => Ok(value),
            ChainProof::Stwo(_) => {
                let message = "received STWO proof where Plonky3 artifact was required".to_string();
                error!("plonky3 {expected} proof decode failure: {message}");
                Err(Self::malformed(expected, message))
            }
        }
    }

    fn decode_proof(proof: &ChainProof, expected: &str) -> ChainResult<Plonky3Proof> {
        let value = Self::decode_chain_value(proof, expected)?;
        let parsed = Plonky3Proof::from_value(value).map_err(|err| {
            error!("plonky3 {expected} proof decode failure: {err}");
            Self::malformed(expected, err.to_string())
        })?;
        if parsed.circuit != expected {
            let message = format!("expected {expected} circuit, received {}", parsed.circuit);
            error!("plonky3 {expected} proof decode failure: {message}");
            return Err(Self::malformed(expected, message));
        }

        if let Err(err) = parsed.payload.validate() {
            error!("plonky3 {expected} proof payload invalid: {err}");
            return Err(Self::malformed(expected, err.to_string()));
        }

        let expected_commitment = match crypto::compute_commitment(&parsed.public_inputs) {
            Ok(commitment) => commitment,
            Err(err) => {
                error!("plonky3 {expected} proof commitment computation failed: {err}");
                return Err(Self::malformed(
                    expected,
                    format!("commitment computation failed: {err}"),
                ));
            }
        };
        if parsed.commitment != expected_commitment {
            let message = format!(
                "commitment mismatch: expected {expected_commitment}, found {}",
                parsed.commitment
            );
            error!("plonky3 {expected} proof verification failed: {message}");
            return Err(Self::verification_failed(expected, message));
        }

        if expected == "consensus" {
            if let Err(err) = validate_consensus_public_inputs(&parsed.public_inputs) {
                error!("plonky3 consensus proof verification failed: invalid public inputs: {err}");
                return Err(map_backend_error(err, |detail| {
                    format!("invalid consensus public inputs: {detail}")
                }));
            }
        }

        if let Err(err) = crypto::verify_proof(&parsed) {
            error!("plonky3 {expected} proof verification failed: {err}");
            return Err(err);
        }

        Ok(parsed)
    }

    fn check_recursive_inputs(
        proof: &Plonky3Proof,
        expected_commitments: &[String],
        expected_previous: Option<&str>,
    ) -> ChainResult<()> {
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
                Self::malformed("recursive", detail)
            })?;

        let recorded: Result<Vec<String>, ChainError> = commitments_field
            .iter()
            .map(|value| {
                value.as_str().map(str::to_owned).ok_or_else(|| {
                    let detail = "recursive proof commitments must be encoded as hex strings";
                    error!("plonky3 recursive proof verification failed: {detail}");
                    Self::malformed("recursive", detail)
                })
            })
            .collect();
        let recorded = recorded?;

        for commitment in expected_commitments {
            if !recorded.iter().any(|value| value == commitment) {
                let message =
                    format!("recursive proof is missing commitment {commitment} from bundle");
                error!("plonky3 recursive proof verification failed: {message}");
                return Err(Self::verification_failed("recursive", message));
            }
        }

        if let Some(previous) = expected_previous {
            if !recorded.iter().any(|value| value == previous) {
                let message =
                    format!("recursive proof does not reference previous accumulator {previous}");
                error!("plonky3 recursive proof verification failed: {message}");
                return Err(Self::verification_failed("recursive", message));
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
                Self::malformed("recursive", detail)
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
            return Err(Self::verification_failed("recursive", message));
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

impl Default for Plonky3Verifier {
    fn default() -> Self {
        Self
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
