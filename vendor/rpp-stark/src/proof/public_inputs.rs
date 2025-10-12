//! Declarative description of public input layouts per proof kind.
//!
//! Public inputs follow Phase-2 framing rules: each variable length component
//! is preceded by a 32-bit little-endian length. All fixed width integers and
//! field elements are serialized in little-endian order.

use crate::config::TranscriptVersionId;
use crate::utils::serialization::{DigestBytes, FieldElementBytes};
use crate::vrf::{FieldId, RlweParamId, VrfParamId};

/// Enumerates all supported proof kinds using canonical RPP coding.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ProofKind {
    /// Proves a single execution trace.
    Execution = 0x00,
    /// Aggregates multiple execution proofs into a compressed certificate.
    Aggregation = 0x01,
    /// Wraps recursion layers for rollup scenarios.
    Recursion = 0x02,
    /// Post-quantum VRF proof binding an RLWE PRF evaluation to a STARK witness.
    VrfPostQuantum = 0x10,
}

impl ProofKind {
    /// Returns the canonical u8 code used in envelopes and seeds.
    pub const fn code(self) -> u8 {
        self as u8
    }

    /// Canonical ordering used for deterministic sorting.
    pub const ORDER: &'static [ProofKind; 4] = &[
        ProofKind::Execution,
        ProofKind::Aggregation,
        ProofKind::Recursion,
        ProofKind::VrfPostQuantum,
    ];
}

/// Version tag for public input headers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PublicInputVersion {
    /// First stable version of the documentation.
    V1,
}

/// Public input header for execution proofs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecutionHeaderV1 {
    /// Version of the header format.
    pub version: PublicInputVersion,
    /// Hash of the program being executed.
    pub program_digest: DigestBytes,
    /// Length of the execution trace in field elements.
    pub trace_length: u32,
    /// Number of columns in the execution trace.
    pub trace_width: u32,
}

/// Public input header for aggregation proofs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AggregationHeaderV1 {
    /// Version of the header format.
    pub version: PublicInputVersion,
    /// Digest of the aggregation circuit definition.
    pub circuit_digest: DigestBytes,
    /// Number of included leaf proofs.
    pub leaf_count: u32,
    /// Commitment to the root of the aggregation tree.
    pub root_digest: DigestBytes,
}

/// Public input header for recursion proofs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecursionHeaderV1 {
    /// Version of the header format.
    pub version: PublicInputVersion,
    /// Depth of the recursion stack.
    pub depth: u8,
    /// Digest binding the recursion boundary values.
    pub boundary_digest: DigestBytes,
    /// Field element that seeds the recursive verifier context.
    pub recursion_seed: FieldElementBytes,
}

/// Public input header for post-quantum VRF proofs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VrfHeaderV1 {
    /// Version of the header format.
    pub version: PublicInputVersion,
    /// Commitment to the secret key parameters: `pk = H(encode(sk_params))`.
    pub public_key_commit: DigestBytes,
    /// Digest pinning the RLWE PRF parameters (A/q/n/σ/domain separation).
    pub prf_param_digest: DigestBytes,
    /// Identifier for the negotiated RLWE ring dimension and modulus profile.
    pub rlwe_param_id: RlweParamId,
    /// Identifier for the VRF parameter profile (thresholds, committees, etc.).
    pub vrf_param_id: VrfParamId,
    /// Transcript version that must agree with Phase 3 bindings.
    pub transcript_version_id: TranscriptVersionId,
    /// Field identifier determining serialization rules for polynomial elements.
    pub field_id: FieldId,
    /// Digest of the VRF evaluation context (round identifiers, domain tags).
    pub context_digest: DigestBytes,
}

/// Unified container for public inputs across proof kinds.
#[derive(Debug, Clone)]
pub enum PublicInputs<'a> {
    /// Execution proof layout.
    Execution {
        /// Header metadata.
        header: ExecutionHeaderV1,
        /// Body bytes (application specific data).
        body: &'a [u8],
    },
    /// Aggregation proof layout.
    Aggregation {
        /// Header metadata.
        header: AggregationHeaderV1,
        /// Serialized accumulator witnesses.
        body: &'a [u8],
    },
    /// Recursion proof layout.
    Recursion {
        /// Header metadata.
        header: RecursionHeaderV1,
        /// Serialized recursion stack body.
        body: &'a [u8],
    },
    /// Post-quantum VRF proof layout.
    Vrf {
        /// Header metadata.
        header: VrfHeaderV1,
        /// Serialized RLWE output polynomial coefficients (little-endian mod q).
        body: &'a [u8],
    },
}

impl<'a> PublicInputs<'a> {
    /// Returns the declared proof kind for these public inputs.
    pub fn kind(&self) -> ProofKind {
        match self {
            Self::Execution { .. } => ProofKind::Execution,
            Self::Aggregation { .. } => ProofKind::Aggregation,
            Self::Recursion { .. } => ProofKind::Recursion,
            Self::Vrf { .. } => ProofKind::VrfPostQuantum,
        }
    }

    /// Returns the header version used by the layout.
    pub fn version(&self) -> PublicInputVersion {
        match self {
            Self::Execution { header, .. } => header.version,
            Self::Aggregation { header, .. } => header.version,
            Self::Recursion { header, .. } => header.version,
            Self::Vrf { header, .. } => header.version,
        }
    }

    /// Returns the raw body bytes for the layout.
    pub fn body(&self) -> &'a [u8] {
        match self {
            Self::Execution { body, .. } => body,
            Self::Aggregation { body, .. } => body,
            Self::Recursion { body, .. } => body,
            Self::Vrf { body, .. } => body,
        }
    }
}

/// Documentation structure describing serialization rules for public inputs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PublicInputSerializationSpec;

impl PublicInputSerializationSpec {
    /// Field order for execution headers.
    pub const EXECUTION_FIELDS: &'static [&'static str] = &[
        "version:u8",
        "program_digest:32B",
        "trace_length:u32 (LE)",
        "trace_width:u32 (LE)",
    ];

    /// Field order for aggregation headers.
    pub const AGGREGATION_FIELDS: &'static [&'static str] = &[
        "version:u8",
        "circuit_digest:32B",
        "leaf_count:u32 (LE)",
        "root_digest:32B",
    ];

    /// Field order for recursion headers.
    pub const RECURSION_FIELDS: &'static [&'static str] = &[
        "version:u8",
        "depth:u8",
        "boundary_digest:32B",
        "recursion_seed:32B",
    ];

    /// Field order for post-quantum VRF headers.
    pub const VRF_FIELDS: &'static [&'static str] = &[
        "version:u8",
        "public_key_commit:32B",
        "prf_param_digest:32B",
        "rlwe_param_id:u16 (LE)",
        "vrf_param_id:u16 (LE)",
        "transcript_version_id:u8",
        "field_id:u16 (LE)",
        "context_digest:32B",
    ];

    /// Description of the length prefix rule.
    pub const LENGTH_PREFIX_RULE: &'static str = "u32 little-endian before each variable section";
}
