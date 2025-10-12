//! Post-quantum VRF specification based on RLWE-derived PRFs with STARK proofs.
//!
//! The declarations in this module document the canonical interface, context
//! descriptors and deterministic rules required to integrate the lattice-based
//! VRF with the existing `rpp-stark` proving pipeline.  The actual execution
//! logic (NTT kernel, parameter identifiers and PRF evaluation) lives in
//! [`pq`].

pub mod pq;

use crate::config::TranscriptVersionId;
use crate::hash::{deterministic::DeterministicHashError, Hash};
use crate::proof::public_inputs::ProofKind;

/// Canonical domain separation tag absorbed into the transcript.
pub const DOMAIN_TAG: &str = "RPP-VRF-V1";

/// Canonical prefix passed to the BLAKE3 XOF during output normalization.
pub const OUTPUT_XOF_PREFIX: &str = "RPP-VRF-OUT";

/// Declares the proof kind associated with the post-quantum VRF pipeline.
pub const VRF_PROOF_KIND: ProofKind = ProofKind::VrfPostQuantum;

/// Identifier for the finite field used to encode RLWE coefficients.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FieldId(pub u16);

impl FieldId {
    /// Returns the little-endian encoding of the identifier.
    pub const fn to_le_bytes(self) -> [u8; 2] {
        self.0.to_le_bytes()
    }
}

/// Identifier for RLWE parameter profiles (ring dimension, modulus, noise bounds).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RlweParamId([u8; 32]);

impl RlweParamId {
    /// Creates a new identifier from a 32-byte digest.
    pub const fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Builds an identifier from a deterministic 32-byte hash.
    pub fn from_hash(hash: Hash) -> Self {
        Self(*hash.as_bytes())
    }

    /// Returns the canonical byte representation of the identifier.
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl core::ops::Deref for RlweParamId {
    type Target = [u8; 32];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

/// Identifier for VRF parameter profiles (thresholds, committee sizing, etc.).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VrfParamId([u8; 32]);

impl VrfParamId {
    /// Creates a new identifier from a 32-byte digest.
    pub const fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Builds an identifier from a deterministic 32-byte hash.
    pub fn from_hash(hash: Hash) -> Self {
        Self(*hash.as_bytes())
    }

    /// Returns the canonical byte representation of the identifier.
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl core::ops::Deref for VrfParamId {
    type Target = [u8; 32];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

/// Declarative mapping rules applied to PRF inputs before polynomial encoding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MappingRules {
    /// Human-readable description of the mapping (little-endian enforcement etc.).
    pub description: &'static str,
    /// Ordered list of mapping steps for deterministic replay.
    pub steps: &'static [&'static str],
}

impl MappingRules {
    /// Canonical mapping used by the VRF pipeline.
    pub const CANONICAL: Self = Self {
        description:
            "Map input bytes to RLWE polynomial coefficients (LE) with transcript-derived a(x)",
        steps: &[
            "Absorb DOMAIN_TAG into transcript",
            "Derive a(x) deterministically from transcript and input x",
            "Interpret x as little-endian coefficients mod q",
            "Pad/trim polynomial to ring dimension n",
        ],
    };
}

/// Context descriptor carried alongside VRF proofs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VrfContext {
    /// Identifier for the RLWE parameter profile.
    pub rlwe_param_id: RlweParamId,
    /// Identifier for the VRF parameter profile.
    pub vrf_param_id: VrfParamId,
    /// Transcript version used when deriving Fiat-Shamir challenges.
    pub transcript_version_id: TranscriptVersionId,
    /// Identifier for the finite field used to serialize coefficients.
    pub field_id: FieldId,
    /// Mapping rules binding input encoding to transcript derivations.
    pub mapping_rules: MappingRules,
}

impl VrfContext {
    /// Canonical ordering for context serialization (all little-endian).
    pub const ORDER: &'static [&'static str] = &[
        "rlwe_param_id:[u8;32]",
        "vrf_param_id:[u8;32]",
        "transcript_version_id:u8",
        "field_id:u16 (LE)",
        "mapping_rules: canonical string table index",
    ];
}

/// Contract for deterministic VRF key generation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VrfKeygenContract;

impl VrfKeygenContract {
    /// Input parameters accepted by `vrf_keygen`.
    pub const INPUTS: &'static [&'static str] = &[
        "param_profile: RLWEParamId + VrfParamId",
        "entropy: transcript-derived seed (no ambient RNG)",
    ];

    /// Output tuple of `vrf_keygen`.
    pub const OUTPUTS: &'static [&'static str] = &[
        "pk: DigestBytes = H(encode(sk_params))",
        "sk_commitment: opaque handle binding prover to pk",
        "aux_meta: RLWE parameter profile digest",
    ];

    /// Deterministic sequencing for the key generation pipeline.
    pub const STEPS: &'static [&'static str] = &[
        "Absorb DOMAIN_TAG || 'KEYGEN' into transcript",
        "Derive sk parameters deterministically via transcript",
        "Compute pk = BLAKE3(encode(sk_params))",
        "Emit commitment metadata (aux_meta)",
    ];
}

/// Contract for deterministic VRF evaluation and proof generation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VrfEvaluateContract;

impl VrfEvaluateContract {
    /// Input parameters accepted by `vrf_evaluate`.
    pub const INPUTS: &'static [&'static str] = &[
        "pk: DigestBytes",
        "sk_commitment: prover-held opaque commitment",
        "x: input bytes bound to RLWE polynomial",
        "ctx: VrfContext (RLWEParamID, VrfParamID, TranscriptVersionID, FieldID, MappingRules)",
    ];

    /// Output tuple emitted by `vrf_evaluate`.
    pub const OUTPUTS: &'static [&'static str] = &[
        "y: RLWE polynomial evaluation coefficients mod q",
        "pi_stark: STARK proof attesting y = F_s(x) with pk binding",
    ];

    /// Deterministic sequencing for VRF evaluation.
    pub const STEPS: &'static [&'static str] = &[
        "Bind DOMAIN_TAG and ctx into transcript",
        "Derive a(x) and challenge streams deterministically",
        "Evaluate RLWE PRF to obtain y without adding noise",
        "Generate STARK proof following phases 2–5 with VRF_PROOF_KIND",
    ];
}

/// Contract for verifying a VRF output and associated STARK proof.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VrfVerifyContract;

impl VrfVerifyContract {
    /// Input parameters accepted by `vrf_verify`.
    pub const INPUTS: &'static [&'static str] = &[
        "pk: DigestBytes",
        "x: input bytes",
        "y: RLWE output coefficients",
        "pi_stark: proof bytes",
        "ctx: VrfContext",
    ];

    /// Verification verdict description.
    pub const OUTPUT: &'static str = "verdict: Accept | Reject(VrfVerificationFailure)";

    /// Deterministic verification steps.
    pub const STEPS: &'static [&'static str] = &[
        "Check ctx identifiers against ParamDigest",
        "Reconstruct transcript with DOMAIN_TAG and ctx",
        "Derive challenges identically to prover",
        "Verify pk = H(encode(sk)) via commitment inside proof",
        "Validate STARK proof and output normalization",
    ];
}

/// Normalization rules producing a 32-byte bias-free VRF output.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VrfOutputNormalizationSpec;

impl VrfOutputNormalizationSpec {
    /// Output length after normalization.
    pub const OUTPUT_LENGTH: usize = 32;
    /// Description of the BLAKE3 XOF invocation.
    pub const XOF_RULE: &'static str =
        "Run BLAKE3-XOF with prefix OUTPUT_XOF_PREFIX over canonical y serialization";
    /// Rejection sampling rule ensuring uniformity.
    pub const REJECTION_RULE: &'static str =
        "Discard draws >= 2^256 - (2^256 mod q_target); retry with next XOF block";
}

/// Anti-grinding commitments used during leader election.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VrfAntiGrindingSpec;

impl VrfAntiGrindingSpec {
    /// Commitment formula binding output to the round context.
    pub const COMMIT_RULE: &'static str = "commit = H(vrf_output || round_id || pk)";
    /// Reveal rule executed after commitments are collected.
    pub const REVEAL_RULE: &'static str =
        "Reveal (y, pi_stark) and recompute vrf_output; commit must match";
    /// Failure classification for invalid reveals.
    pub const FAILURE: VrfVerificationFailure = VrfVerificationFailure::ErrVrfCommitMismatch;
}

/// Threshold selection rules for leader election.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VrfThresholdingSpec;

impl VrfThresholdingSpec {
    /// Acceptance rule based on threshold comparison.
    pub const ACCEPT_RULE: &'static str =
        "Accept winner if H(vrf_output || round_ctx) < T (little-endian interpretation)";
    /// Sorting rule applied when multiple winners appear.
    pub const SORTING_RULE: &'static str = "Sort by (vrf_output, pk) lexicographically";
}

/// Transcript binding rules specific to VRF proofs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VrfTranscriptSpec;

impl VrfTranscriptSpec {
    /// Ordered transcript sections absorbed before proof generation.
    pub const SECTION_ORDER: &'static [&'static str] = &[
        "DOMAIN_TAG",
        "VRF-PIs: pk || x || PRF-ParamDigest",
        "COMMITMENTS (if grouped)",
        "PARAM_DIGEST (FieldID, RLWEParamID, TranscriptVersionID, ...)",
        "BLOCK_CONTEXT (consensus binding)",
    ];

    /// Challenge derivation rule referencing Phase 3.
    pub const CHALLENGE_RULE: &'static str =
        "Reuse Phase-3 deterministic challenges; no auxiliary RNG";

    /// Validates that the transcript sections match the documented ordering.
    pub fn validate_section_sequence(observed: &[&str]) -> Result<(), VrfVerificationFailure> {
        if observed.len() < Self::SECTION_ORDER.len() {
            return Err(VrfVerificationFailure::ErrVrfTranscriptOrder);
        }
        for (expected, actual) in Self::SECTION_ORDER.iter().zip(observed.iter()) {
            if expected != actual {
                return Err(VrfVerificationFailure::ErrVrfTranscriptOrder);
            }
        }
        Ok(())
    }
}

/// Cutover policy enforcing the hard switch from EC-VRF to PQ-VRF.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VrfCutoverPolicy;

impl VrfCutoverPolicy {
    /// Name of the chain configuration constant expressing the switch height.
    pub const SWITCH_HEIGHT_CONST: &'static str = "VRF_SWITCH_HEIGHT";
    /// Name of the optional epoch-based switch constant.
    pub const SWITCH_EPOCH_CONST: &'static str = "VRF_SWITCH_EPOCH";
    /// Behavioural rule before the switch point.
    pub const PRE_CUTOVER_RULE: &'static str =
        "If height < VRF_SWITCH_HEIGHT, accept EC-VRF or PQ-VRF (best-effort compatibility)";
    /// Behavioural rule after the switch point.
    pub const POST_CUTOVER_RULE: &'static str =
        "If height >= VRF_SWITCH_HEIGHT, reject EC-VRF with ErrVrfLegacyRejected";
}

/// Lifecycle documentation for epoch-bound keys.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VrfKeyLifecycleSpec;

impl VrfKeyLifecycleSpec {
    /// Description of epoch key generation.
    pub const EPOCH_KEYGEN_RULE: &'static str =
        "Call epoch_keygen before the epoch starts; publish pk and aux metadata";
    /// Grace period rule describing overlap.
    pub const GRACE_PERIOD_RULE: &'static str =
        "Previous epoch keys remain valid until the epoch boundary; new keys activate afterwards";
    /// Invalid state rule once epoch ends.
    pub const EXPIRY_RULE: &'static str =
        "After grace period, old keys yield ErrVrfEpochKeyNotActive";
}

/// VRF specific failure classes surfaced by verification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VrfVerificationFailure {
    /// VRF context disagreed with the negotiated parameters.
    ErrVrfParamMismatch,
    /// Commit-reveal binding failed (commit did not match reveal data).
    ErrVrfCommitMismatch,
    /// Transcript ordering or domain tag mismatch detected.
    ErrVrfTranscriptOrder,
    /// STARK proof invalid or inconsistent with declared public inputs.
    ErrVrfProofInvalid,
    /// Output normalization detected bias (rejection sampling failed to converge deterministically).
    ErrVrfBiasDetected,
    /// Epoch key not yet active or outside grace period.
    ErrVrfEpochKeyNotActive,
    /// Legacy EC-VRF observed after cutover height.
    ErrVrfLegacyRejected,
    /// PQ-VRF attempted before the cutover point when disallowed.
    ErrVrfCutoverNotReached,
    /// Deterministic hashing helper failed.
    ErrDeterministicHash(DeterministicHashError),
}

impl From<DeterministicHashError> for VrfVerificationFailure {
    fn from(err: DeterministicHashError) -> Self {
        VrfVerificationFailure::ErrDeterministicHash(err)
    }
}

/// Test plan covering determinism, bias checks and cutover enforcement.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VrfTestPlan;

impl VrfTestPlan {
    /// Summary of deterministic fixtures.
    pub const DETERMINISM_CASES: &'static [&'static str] = &[
        "Same inputs -> identical (y, vrf_output, pi_stark)",
        "Transcript replay reproduces a(x) and challenges exactly",
    ];

    /// Summary of bias and fairness checks.
    pub const BIAS_CASES: &'static [&'static str] = &[
        "XOF + rejection sampling yields uniform 32-byte outputs",
        "Commit-reveal mismatch triggers ErrVrfCommitMismatch",
    ];

    /// Summary of cutover validation cases.
    pub const CUTOVER_CASES: &'static [&'static str] = &[
        "Pre-cutover: EC-VRF accepted, PQ-VRF accepted",
        "Post-cutover: EC-VRF rejected with ErrVrfLegacyRejected",
        "Post-cutover: PQ-VRF validated with ErrVrfProofInvalid used for malformed proofs",
    ];

    /// Summary of batch verification coverage.
    pub const BATCH_CASES: &'static [&'static str] = &[
        "Batch mixing PQ-VRF with other proof kinds respects ProofKind ordering",
        "Aggregation rejects on ErrVrfParamMismatch when ctx inconsistent",
    ];
}

/// Alias for the normalized VRF output bytes.
pub type VrfOutput = [u8; VrfOutputNormalizationSpec::OUTPUT_LENGTH];

#[cfg(test)]
pub mod tests {
    use super::*;

    #[test]
    fn accept_complete_vrf_transcript_sections_ok() {
        let observed = VrfTranscriptSpec::SECTION_ORDER.to_vec();
        VrfTranscriptSpec::validate_section_sequence(&observed).expect("valid");
    }

    #[test]
    fn reject_missing_vrf_transcript_sections() {
        let observed =
            &VrfTranscriptSpec::SECTION_ORDER[..VrfTranscriptSpec::SECTION_ORDER.len() - 1];
        let err = VrfTranscriptSpec::validate_section_sequence(observed).unwrap_err();
        assert_eq!(err, VrfVerificationFailure::ErrVrfTranscriptOrder);
    }

    #[test]
    fn reject_reordered_vrf_transcript_sections() {
        let mut observed = VrfTranscriptSpec::SECTION_ORDER.to_vec();
        observed.swap(0, 1);
        let err = VrfTranscriptSpec::validate_section_sequence(&observed).unwrap_err();
        assert_eq!(err, VrfVerificationFailure::ErrVrfTranscriptOrder);
    }
}
