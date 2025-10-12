//! Top-level proof lifecycle contracts.
//!
//! The functions exposed by [`crate::generate_proof`],
//! [`crate::verify_proof`] and [`crate::batch_verify`] are documented here in
//! terms of inputs, outputs and deterministic sequencing. Only the shapes of
//! the API are provided—no runtime behaviour is implemented.
#![allow(dead_code)]

use crate::config::{ProofSystemConfig, ProverContext, VerifierContext};
use crate::utils::serialization::{ProofBytes, WitnessBlob};

use super::aggregation::{self, BatchProofRecord, BatchVerificationOutcome, BlockContext};
use super::prover;
use super::public_inputs::{ProofKind, PublicInputs};
use super::ser::map_public_to_config_kind;
use super::types::{FriVerifyIssue, MerkleSection, VerifyError, VerifyReport, PROOF_VERSION};

/// Documentation container describing the full lifecycle of a proof.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProofLifecycleSpec;

impl ProofLifecycleSpec {
    /// Canonical order of the lifecycle steps.
    pub const STEPS: &'static [&'static str] = &[
        "ingest_public_inputs",
        "prepare_contexts",
        "describe_envelope_structure",
        "assemble_envelope",
        "emit_header_report",
        "optional_batch_summary",
    ];
}

/// Signature contract for [`crate::generate_proof`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GenerateProofContract;

impl GenerateProofContract {
    /// Human-readable documentation of the inputs.
    pub const INPUTS: &'static [&'static str] = &[
        "kind: ProofKind (canonical RPP u8 coding)",
        "public_inputs: Phase-2 header/body container",
        "witness: application specific opaque bytes",
        "config: ProofSystemConfig (Phase 2/3/4/5 profile)",
        "prover_context: deterministic pipeline descriptor",
    ];

    /// Output produced by the function.
    pub const OUTPUT: &'static str = "proof_bytes: serialized envelope as ProofBytes";

    /// Determinism requirements for the function.
    pub const DETERMINISM: &'static [&'static str] = &[
        "no OS time, randomness derived solely from transcript",
        "thread scheduling fixed via ProverContext::thread_pool",
        "witness consumed exactly once in documented order",
    ];
}

/// Signature contract for [`crate::verify_proof`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VerifyProofContract;

impl VerifyProofContract {
    /// Human-readable documentation of the inputs.
    pub const INPUTS: &'static [&'static str] = &[
        "kind: ProofKind declared by caller",
        "public_inputs: authoritative Phase-2 layout",
        "proof_bytes: serialized envelope",
        "config: ProofSystemConfig",
        "verifier_context: deterministic verifier descriptor",
    ];

    /// Output produced by the function.
    pub const OUTPUT: &'static str =
        "report: VerifyReport{params_ok, public_ok, merkle_ok, fri_ok, composition_ok, total_bytes, proof, error}";

    /// Determinism requirements for the function.
    pub const DETERMINISM: &'static [&'static str] = &[
        "derive all randomness from TranscriptVersionId",
        "validate limits before hashing or polynomial checks",
        "metrics collection must avoid time-based counters",
    ];
}

/// Signature contract for [`crate::batch_verify`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BatchVerifyContract;

impl BatchVerifyContract {
    /// Human-readable documentation of the inputs.
    pub const INPUTS: &'static [&'static str] = &[
        "block_context: aggregation binding (height, prev_state_root, network_id)",
        "proofs: slice of BatchProofRecord(kind, public_inputs, proof_bytes)",
        "config: ProofSystemConfig",
        "verifier_context: deterministic verifier descriptor",
    ];

    /// Output produced by the function.
    pub const OUTPUT: &'static str = "BatchVerificationOutcome: Accept | Reject{index, error}";

    /// Determinism requirements for the function.
    pub const DETERMINISM: &'static [&'static str] = &[
        "block seed = BLAKE3('RPP-AGG' || block_context || sorted ProofKind codes)",
        "per-proof seed = BLAKE3(block_seed || u32_le(i) || ProofKind code)",
        "query positions derived strictly from per-proof seed",
    ];
}

/// Helper describing how witness containers are structured.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WitnessContainerSpec;

impl WitnessContainerSpec {
    /// Documentation of the canonical little-endian framing.
    pub const LAYOUT: &'static [&'static str] = &[
        "u32_le witness_length",
        "witness_bytes (opaque to documentation layer)",
    ];
}

/// Forward declaration of the generate_proof function (no implementation).
pub fn generate_proof(
    kind: ProofKind,
    public_inputs: &PublicInputs<'_>,
    witness: WitnessBlob<'_>,
    config: &ProofSystemConfig,
    prover_context: &ProverContext,
) -> Result<ProofBytes, VerifyError> {
    if kind != public_inputs.kind() {
        return Err(VerifyError::PublicInputMismatch);
    }

    let proof = prover::build_envelope(public_inputs, witness, config, prover_context)
        .map_err(map_prover_error_to_verify)?;
    let bytes = proof.to_bytes()?;
    Ok(ProofBytes::new(bytes))
}

/// Forward declaration of the verify_proof function (no implementation).
///
/// The returned [`VerifyReport`] mirrors the deterministic stage flags exposed by
/// the verifier. Each boolean flag defaults to `false` when the corresponding
/// stage aborts, `total_bytes` captures the measured envelope length, `proof`
/// surfaces an immutable view of the proof header and payload handles (when
/// available), and `error` documents the first failure (if any).
pub fn verify_proof(
    kind: ProofKind,
    public_inputs: &PublicInputs<'_>,
    proof_bytes: &ProofBytes,
    config: &ProofSystemConfig,
    verifier_context: &VerifierContext,
) -> Result<VerifyReport, VerifyError> {
    if kind != public_inputs.kind() {
        return Err(VerifyError::PublicInputMismatch);
    }

    let declared_kind = map_public_to_config_kind(kind);
    let report = super::verifier::verify(
        declared_kind,
        public_inputs,
        proof_bytes,
        config,
        verifier_context,
    );
    Ok(report)
}

/// Forward declaration of the batch_verify function (no implementation).
pub fn batch_verify(
    block_context: &BlockContext,
    proofs: &[BatchProofRecord<'_>],
    config: &ProofSystemConfig,
    verifier_context: &VerifierContext,
) -> Result<BatchVerificationOutcome, VerifyError> {
    for record in proofs {
        if record.kind != record.public_inputs.kind() {
            return Err(VerifyError::PublicInputMismatch);
        }
    }

    Ok(aggregation::batch_verify(
        block_context,
        proofs,
        config,
        verifier_context,
    ))
}

fn map_prover_error_to_verify(error: prover::ProverError) -> VerifyError {
    use prover::ProverError;

    match error {
        ProverError::UnsupportedProofVersion(actual) => VerifyError::VersionMismatch {
            expected: PROOF_VERSION,
            actual,
        },
        ProverError::ParamDigestMismatch => VerifyError::ParamsHashMismatch,
        ProverError::MalformedWitness(reason) => {
            VerifyError::UnexpectedEndOfBuffer(reason.to_string())
        }
        ProverError::Transcript(_) => VerifyError::TranscriptOrder,
        ProverError::Fri(_) => VerifyError::FriVerifyFailed {
            issue: FriVerifyIssue::Generic,
        },
        ProverError::Air(_) => VerifyError::TranscriptOrder,
        ProverError::Merkle(_) => VerifyError::MerkleVerifyFailed {
            section: MerkleSection::FriPath,
        },
        ProverError::ProofTooLarge { actual, limit } => {
            let got_kb = actual.div_ceil(1024).min(u32::MAX as usize) as u32;
            let max_kb = (limit as usize).div_ceil(1024) as u32;
            VerifyError::ProofTooLarge { max_kb, got_kb }
        }
        ProverError::Serialization(kind) => VerifyError::Serialization(kind),
        ProverError::FieldConstraint(context, _) => {
            VerifyError::UnexpectedEndOfBuffer(context.to_string())
        }
    }
}
