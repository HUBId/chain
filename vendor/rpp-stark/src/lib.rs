#![forbid(unsafe_code)]
#![deny(rust_2018_idioms)]

//! Core library entry point for the `rpp-stark` proof system.
//!
//! The crate exposes declarative contracts for proof generation, verification
//! and aggregation. All functions are intentionally left without
//! implementations; they simply document the required parameters and the
//! deterministic sequencing dictated by the specification. Inspectors interact
//! with strongly typed accessors when reading decoded proofs, using handles
//! such as [`proof::CompositionBinding`], [`proof::FriHandle`],
//! [`proof::OpeningsDescriptor`] and [`proof::ProofHandles`]. Configuration
//! bindings are surfaced through [`proof::types::Proof::params_hash`], while
//! optional telemetry is handled by [`proof::TelemetryOption`].

pub mod air;
pub mod config;
pub mod fft;
pub mod field;
pub mod fri;
pub mod hash;
pub mod merkle;
pub mod params;
pub mod proof;
pub mod ser;
pub mod transcript;
pub mod utils;
pub mod vrf;

#[cfg(feature = "backend-rpp-stark")]
pub mod backend;

use config::{ProofSystemConfig, ProverContext, VerifierContext};
use proof::aggregation;
use proof::prover;
use proof::public_inputs::PublicInputs;
use proof::ser::map_public_to_config_kind;
use proof::ProofKind;
use ser::{SerError, SerKind as SerializationKind};

pub use proof::aggregation::{BatchProofRecord, BatchVerificationOutcome, BlockContext};
pub use proof::types::{
    CompositionBinding, FriHandle, Openings, OpeningsDescriptor, Proof, ProofHandles, Telemetry,
    TelemetryOption, VerifyError, VerifyReport, PROOF_VERSION,
};
use utils::serialization::{ProofBytes, WitnessBlob};

pub use air::example::{
    lfsr::PublicInputs as LfsrPublicInputs, LfsrAir as ExampleLfsrAir,
    LfsrTraceBuilder as ExampleLfsrTraceBuilder,
};
pub use air::traits::{
    Air as AirContract, BoundaryBuilder as AirBoundaryBuilder,
    BoundaryConstraint as AirBoundaryConstraint, Constraint as AirConstraint,
    Evaluator as AirEvaluator, PolyExpr as AirPolyExpr, PublicInputsCodec as AirPublicInputsCodec,
    TraceBuilder as AirTraceBuilder,
};
pub use air::types::{
    AirError, BoundaryAt, DegreeBounds, LdeOrder, PublicFieldMeta, PublicFieldType, PublicSpec,
    SerKind, TraceColMeta, TraceData, TraceRole, TraceSchema,
};

/// Result type used throughout the library to surface deterministic errors.
pub type StarkResult<T> = core::result::Result<T, StarkError>;

/// Error enumeration for the STARK engine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StarkError {
    /// The requested feature is not yet implemented.
    NotImplemented(&'static str),
    /// The provided input failed validation checks.
    InvalidInput(&'static str),
    /// A generic error surfaced from a subsystem.
    SubsystemFailure(&'static str),
}

/// Verdict returned by verification functions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerificationVerdict {
    /// Proof accepted after all checks.
    Accept,
    /// Proof rejected with a documented failure class.
    Reject(VerifyError),
}

/// Generates a proof for the specified [`ProofKind`].
///
/// The function follows the canonical lifecycle:
/// 1. Bind the [`ProofSystemConfig`] and [`ProverContext`] against the declared
///    `kind`.
/// 2. Ingest the phase-2 public input layout using [`PublicInputs`].
/// 3. Absorb the witness container and execute the pipeline described in the
///    `proof::prover` module.
/// 4. Assemble the [`proof::types::Proof`] container, populate wrappers such as
///    [`proof::types::TelemetryOption`], and serialise it using the canonical
///    helpers exposed by [`proof::ser`].
///
/// No implementation logic is provided here; integrators must supply the
/// execution engine while preserving the documented order of operations.
pub fn generate_proof(
    kind: ProofKind,
    public_inputs: &PublicInputs<'_>,
    witness: WitnessBlob<'_>,
    config: &ProofSystemConfig,
    prover_context: &ProverContext,
) -> StarkResult<ProofBytes> {
    if kind != public_inputs.kind() {
        return Err(StarkError::InvalidInput("proof_kind_mismatch"));
    }

    let envelope = prover::build_envelope(public_inputs, witness, config, prover_context)
        .map_err(map_prover_error)?;
    let bytes = envelope.to_bytes().map_err(map_serialization_error)?;
    Ok(ProofBytes::new(bytes))
}

/// Verifies a single proof and returns a [`VerificationVerdict`].
///
/// The verification logic MUST execute the steps described in the
/// `proof::verifier` module. The `config` and `verifier_context`
/// parameters must match the ones used by the prover; otherwise
/// [`proof::types::VerifyError::ParamsHashMismatch`] is expected. The proof
/// [`proof::types::Proof::params_hash`] accessor must therefore agree with the
/// parameter hash stored by the prover. The underlying
/// [`proof::types::VerifyReport`] returned by the verifier summarizes the
/// deterministic stage flags (`params_ok`, `public_ok`, `merkle_ok`, `fri_ok`,
/// `composition_ok`), the measured `total_bytes`, an optional
/// [`proof::ProofHandles`] view of the proof and an optional [`VerifyError`].
/// The verdict surfaced by this helper is derived directly from
/// [`VerifyReport::error`], avoiding transport-level failures for decoded
/// envelope issues.
pub fn verify_proof(
    kind: ProofKind,
    public_inputs: &PublicInputs<'_>,
    proof_bytes: &ProofBytes,
    config: &ProofSystemConfig,
    verifier_context: &VerifierContext,
) -> StarkResult<VerificationVerdict> {
    if kind != public_inputs.kind() {
        return Err(StarkError::InvalidInput("proof_kind_mismatch"));
    }

    let declared_kind = map_public_to_config_kind(kind);
    let report = proof::verifier::verify(
        declared_kind,
        public_inputs,
        proof_bytes,
        config,
        verifier_context,
    );
    let verdict = match report.error {
        None => VerificationVerdict::Accept,
        Some(error) => VerificationVerdict::Reject(error),
    };
    Ok(verdict)
}

/// Verifies a batch of proofs under a shared block context.
///
/// Implementations must follow the aggregation rules documented in the
/// `proof::aggregation` module. The returned outcome records
/// whether all proofs were accepted and, in case of failures, which
/// [`proof::types::VerifyError`] triggered the rejection.
pub fn batch_verify(
    block_context: &proof::aggregation::BlockContext,
    proofs: &[BatchProofRecord<'_>],
    config: &ProofSystemConfig,
    verifier_context: &VerifierContext,
) -> StarkResult<BatchVerificationOutcome> {
    for record in proofs {
        if record.kind != record.public_inputs.kind() {
            return Err(StarkError::InvalidInput("proof_kind_mismatch"));
        }
    }

    let outcome = aggregation::batch_verify(block_context, proofs, config, verifier_context);
    Ok(outcome)
}

/// Convenience helper describing the canonical proof envelope layout.
pub fn proof_envelope_spec() -> &'static str {
    "See proof::types::Proof and proof::ser for the canonical layout implementation."
}

fn map_prover_error(error: prover::ProverError) -> StarkError {
    use prover::ProverError;

    match error {
        ProverError::UnsupportedProofVersion(_) => {
            StarkError::InvalidInput("unsupported_proof_version")
        }
        ProverError::ParamDigestMismatch => StarkError::InvalidInput("prover_params_hash_mismatch"),
        ProverError::MalformedWitness(reason) => StarkError::InvalidInput(reason),
        ProverError::Transcript(_) => StarkError::SubsystemFailure("prover_transcript_error"),
        ProverError::Fri(_) => StarkError::SubsystemFailure("prover_fri_error"),
        ProverError::Air(_) => StarkError::SubsystemFailure("prover_air_error"),
        ProverError::Merkle(_) => StarkError::SubsystemFailure("prover_merkle_error"),
        ProverError::ProofTooLarge { .. } => StarkError::InvalidInput("proof_too_large"),
        ProverError::Serialization(kind) => {
            map_serialization_error(SerError::invalid_value(kind, "prover_serialization"))
        }
        ProverError::FieldConstraint(context, _) => StarkError::InvalidInput(context),
    }
}

fn map_serialization_error(error: SerError) -> StarkError {
    let reason = match error.kind() {
        SerializationKind::Proof => "proof_serialization_error",
        SerializationKind::TraceCommitment => "trace_commitment_serialization_error",
        SerializationKind::CompositionCommitment => "composition_commitment_serialization_error",
        SerializationKind::Fri => "fri_serialization_error",
        SerializationKind::Openings => "openings_serialization_error",
        SerializationKind::Telemetry => "telemetry_serialization_error",
        SerializationKind::PublicInputs => "public_inputs_serialization_error",
        SerializationKind::Params => "params_serialization_error",
    };
    StarkError::SubsystemFailure(reason)
}
