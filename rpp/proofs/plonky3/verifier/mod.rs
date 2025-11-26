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

#[derive(Default)]
struct ConsensusLogContext {
    timetoke: Option<u64>,
    epoch: Option<u64>,
    slot: Option<u64>,
}

impl ConsensusLogContext {
    fn from_public_inputs(value: &Value) -> Self {
        let witness = value.get("witness");
        let epoch = witness
            .and_then(|node| node.get("epoch"))
            .and_then(Value::as_u64);
        let slot = witness
            .and_then(|node| node.get("slot"))
            .and_then(Value::as_u64);
        let timetoke = witness
            .and_then(|node| {
                node.get("timetoke")
                    .or_else(|| node.get("timetoke_hours"))
                    .or_else(|| node.get("round"))
            })
            .and_then(Value::as_u64);

        Self {
            timetoke,
            epoch,
            slot,
        }
    }
}

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
            let context = ConsensusLogContext::from_public_inputs(&parsed.public_inputs);
            if let Err(err) = validate_consensus_public_inputs(&parsed.public_inputs) {
                error!(
                    consensus_timetoke = ?context.timetoke,
                    consensus_epoch = ?context.epoch,
                    consensus_slot = ?context.slot,
                    backend = "plonky3",
                    "plonky3 consensus proof verification failed: invalid public inputs: {err}"
                );
                return Err(map_backend_error(err, |detail| {
                    format!("invalid consensus public inputs: {detail}")
                }));
            }
        }

        if let Err(err) = crypto::verify_proof(&parsed) {
            let context = if expected == "consensus" {
                ConsensusLogContext::from_public_inputs(&parsed.public_inputs)
            } else {
                ConsensusLogContext::default()
            };
            error!(
                consensus_timetoke = ?context.timetoke,
                consensus_epoch = ?context.epoch,
                consensus_slot = ?context.slot,
                backend = "plonky3",
                "plonky3 {expected} proof verification failed: {err}"
            );
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

#[cfg(test)]
mod tests {
    use super::*;
    use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
    use base64::Engine;
    use serde_json::json;
    use tracing_subscriber::fmt::writer::MakeWriterExt;

    fn consensus_proof_value() -> Value {
        let hex_digest = "00".repeat(32);
        let proof = json!({
            "circuit": "consensus",
            "commitment": hex_digest,
            "public_inputs": {
                "witness": {
                    "block_hash": hex_digest,
                    "round": 3,
                    "epoch": 7,
                    "slot": 9,
                    "leader_proposal": hex_digest,
                    "quorum_threshold": 1,
                    "pre_votes": [],
                    "pre_commits": [],
                    "commit_votes": [],
                    "quorum_bitmap_root": hex_digest,
                    "quorum_signature_root": hex_digest,
                    "vrf_entries": [],
                    "witness_commitments": [],
                    "reputation_roots": []
                },
                "bindings": {
                    "vrf_outputs": hex_digest,
                    "vrf_proofs": hex_digest,
                    "witness_commitments": hex_digest,
                    "reputation_roots": hex_digest,
                    "quorum_bitmap": hex_digest,
                    "quorum_signature": hex_digest
                },
                "vrf_entries": [],
                "block_height": 1
            },
            "payload": {
                "stark_proof": BASE64_STANDARD.encode(""),
                "auxiliary_payloads": [],
                "metadata": {
                    "trace_commitment": hex_digest,
                    "quotient_commitment": hex_digest,
                    "random_commitment": null,
                    "fri_commitments": [hex_digest],
                    "canonical_public_inputs": BASE64_STANDARD.encode(""),
                    "transcript": {
                        "degree_bits": 0,
                        "trace_length_bits": 0,
                        "alpha": [],
                        "betas": [],
                        "omegas": []
                    },
                    "hash_format": "poseidon_merkle_cap",
                    "security_bits": 0,
                    "derived_security_bits": 0,
                    "use_gpu": false
                }
            }
        });

        proof
    }

    #[test]
    fn consensus_logs_include_context() {
        let proof_value = consensus_proof_value();
        let proof = ChainProof::Plonky3(proof_value);

        let buffer = std::sync::Mutex::new(Vec::new());
        let subscriber = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::ERROR)
            .with_writer(buffer.clone().make_writer())
            .with_ansi(false)
            .finish();

        let _guard = tracing::subscriber::set_default(subscriber);

        let _ = Plonky3Verifier::decode_proof(&proof, "consensus");

        let bytes = buffer.into_inner().expect("lock log buffer");
        let logs = String::from_utf8(bytes).expect("utf8 logs");

        assert!(logs.contains("consensus_epoch=Some(7)"));
        assert!(logs.contains("consensus_slot=Some(9)"));
        assert!(logs.contains("consensus_timetoke=Some(3)"));
        assert!(logs.contains("backend=plonky3"));
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
