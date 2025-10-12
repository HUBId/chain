//! Canonical configuration scaffolding shared by prover, verifier and AIR
//! authors.
//!
//! This module intentionally exposes **only** identifiers, constants and
//! layout descriptors. No runtime logic is provided; implementors are expected
//! to use these declarations when wiring their respective engines. The
//! documentation embedded in this module forms part of the specification and
//! records the change-control rules, test obligations and canonical ordering of
//! all configuration artefacts.

use crate::hash::Hasher;
use crate::utils::serialization::DigestBytes;
use serde::{Deserialize, Serialize};

/// Fixed domain separator used when hashing the parameter layout into the
/// [`ParamDigest`]. The tag is ASCII encoded and **must** be prepended to the
/// little-endian fields listed in the canonical order below before running the
/// BLAKE3 hash function.
pub const PARAM_DIGEST_DOMAIN_TAG: &[u8; 13] = b"RPP-PARAMS-V1";

/// Domain separator used when deriving per-proof public-input digests for
/// sorting and batch aggregation. Proof builders and verifiers prepend this tag
/// before hashing the canonical proof-kind byte and public-input encoding.
pub const PI_DIGEST_DOMAIN_TAG: &[u8; 9] = b"RPP-PI-V1";

/// Identifier describing a configuration profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProfileId(pub u8);

impl ProfileId {
    /// Returns the canonical single-byte little-endian representation.
    pub const fn to_le_bytes(self) -> [u8; 1] {
        [self.0]
    }
}

/// Standard proving profile optimised for balanced rollup workloads.
pub const PROFILE_STD: ProfileId = ProfileId(1);

/// High-security proving profile favouring query redundancy and stronger FRI
/// parameters.
pub const PROFILE_HISEC: ProfileId = ProfileId(2);

/// Optional high-throughput profile for latency-sensitive rollups. It shares
/// the same Poseidon parameters as the standard profile while reducing FRI
/// queries. Integrators **must** benchmark before enabling it.
pub const PROFILE_THROUGHPUT: ProfileId = ProfileId(3);

/// Standard proving profile using quaternary Merkle trees.
pub const PROFILE_STD_ARITY4: ProfileId = ProfileId(4);

/// Identifier describing the base field of the AIR.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct FieldId(pub u8);

impl FieldId {
    /// Returns the canonical representation used in the [`ParamDigest`].
    pub const fn to_le_bytes(self) -> [u8; 1] {
        [self.0]
    }
}

/// Goldilocks 64-bit field used by the proof system.
pub const FIELD_ID_GOLDILOCKS_64: FieldId = FieldId(1);

/// Identifier describing a Poseidon parameter set.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PoseidonParamId(pub DigestBytes);

impl PoseidonParamId {
    /// Returns the raw 32-byte identifier used across transcripts.
    pub const fn bytes(self) -> DigestBytes {
        self.0
    }

    /// Returns the canonical byte representation without transferring
    /// ownership. Useful when hashing parameters.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0.bytes
    }
}

/// Identifier describing the Merkle commitment scheme.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MerkleSchemeId(pub DigestBytes);

impl MerkleSchemeId {
    /// Returns the raw 32-byte identifier.
    pub const fn bytes(self) -> DigestBytes {
        self.0
    }

    /// Returns the canonical byte representation without transferring
    /// ownership.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0.bytes
    }
}

/// Identifier describing the Fiat-Shamir transcript version.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TranscriptVersionId(pub DigestBytes);

impl TranscriptVersionId {
    /// Returns the raw 32-byte identifier.
    pub const fn bytes(self) -> DigestBytes {
        self.0
    }

    /// Returns the canonical byte representation without transferring
    /// ownership.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0.bytes
    }
}

/// Identifier describing the canonical FRI folding plan.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FriPlanId(pub DigestBytes);

impl FriPlanId {
    /// Returns the raw 32-byte identifier.
    pub const fn bytes(self) -> DigestBytes {
        self.0
    }

    /// Returns the canonical byte representation without transferring
    /// ownership.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0.bytes
    }
}

/// Identifier describing the AIR specification bound to a proof kind.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AirSpecId(pub DigestBytes);

impl AirSpecId {
    /// Returns the raw 32-byte identifier.
    pub const fn bytes(self) -> DigestBytes {
        self.0
    }

    /// Returns the canonical byte representation without transferring
    /// ownership.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0.bytes
    }
}

/// Identifier describing the version of the proof envelope/layout.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofVersion(pub u8);

impl ProofVersion {
    /// Returns the canonical single-byte representation.
    pub const fn to_le_bytes(self) -> [u8; 1] {
        [self.0]
    }
}

/// Canonical proof kinds. **The order of the variants is immutable** and must
/// be used whenever serialising per-proof data (limits, AIR identifiers,
/// public-input digests, …).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[allow(non_camel_case_types)]
pub enum ProofKind {
    /// Transaction execution proofs.
    Tx,
    /// Global state transition proofs.
    State,
    /// Historical pruning proofs.
    Pruning,
    /// Uptime / liveness proofs.
    Uptime,
    /// Consensus proofs.
    Consensus,
    /// Identity proofs.
    Identity,
    /// Aggregation proofs.
    Aggregation,
    /// Verifiable random function proofs.
    VRF,
}

impl ProofKind {
    /// Global immutable order used across layouts and hashes.
    pub const ORDER: [ProofKind; 8] = [
        ProofKind::Tx,
        ProofKind::State,
        ProofKind::Pruning,
        ProofKind::Uptime,
        ProofKind::Consensus,
        ProofKind::Identity,
        ProofKind::Aggregation,
        ProofKind::VRF,
    ];
}

/// Helper struct storing values per [`ProofKind`] in canonical order. When
/// serialising, fields must be emitted in declaration order using
/// little-endian encoding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProofKindLayout<T> {
    pub tx: T,
    pub state: T,
    pub pruning: T,
    pub uptime: T,
    pub consensus: T,
    pub identity: T,
    pub aggregation: T,
    pub vrf: T,
}

impl<T> ProofKindLayout<T> {
    /// Returns a reference to the value associated with the given
    /// [`ProofKind`].
    pub fn get(&self, kind: ProofKind) -> &T {
        match kind {
            ProofKind::Tx => &self.tx,
            ProofKind::State => &self.state,
            ProofKind::Pruning => &self.pruning,
            ProofKind::Uptime => &self.uptime,
            ProofKind::Consensus => &self.consensus,
            ProofKind::Identity => &self.identity,
            ProofKind::Aggregation => &self.aggregation,
            ProofKind::VRF => &self.vrf,
        }
    }
}

/// Poseidon round configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PoseidonRoundConfiguration {
    pub full_rounds: u8,
    pub partial_rounds: u8,
}

/// Allowed depth range for the FRI folding tree.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FriDepthRange {
    pub min: u8,
    pub max: u8,
}

/// Deterministic threading configuration. Work stealing runtimes are forbidden;
/// only the policies listed here are allowed and **must** be executed with
/// deterministic scheduling.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ThreadPoolProfile {
    /// Exactly one worker executes all tasks sequentially.
    SingleThread,
    /// Fixed number of workers processed in a round-robin manner.
    FixedStatic { worker_count: u8 },
}

/// Chunking strategy used for distributing workloads across workers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChunkingPolicy {
    /// Minimum number of field elements per worker chunk.
    pub min_chunk_items: u32,
    /// Maximum number of field elements per worker chunk.
    pub max_chunk_items: u32,
    /// Explicit stride applied when slicing evaluation domains.
    pub stride: u32,
}

/// Hard resource limits shared between prover and verifier. Every field is
/// serialised little-endian when deriving the [`ParamDigest`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResourceLimits {
    pub max_proof_size_bytes: u32,
    pub max_layers: u8,
    pub max_queries: u16,
    pub per_proof_max_trace_width: ProofKindLayout<u16>,
    pub per_proof_max_trace_steps: ProofKindLayout<u32>,
}

/// Collection of AIR identifiers bound to the canonical proof kinds.
pub type AirSpecLayout = ProofKindLayout<AirSpecId>;

/// Canonical configuration description shared by prover, verifier and AIR.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProfileConfig {
    pub id: ProfileId,
    pub name: &'static str,
    pub security_goal: &'static str,
    pub lde_factor: u8,
    pub fri_queries: u16,
    pub fri_depth_range: FriDepthRange,
    pub poseidon_rounds: PoseidonRoundConfiguration,
    pub poseidon_param_id: PoseidonParamId,
    pub merkle_scheme_id: MerkleSchemeId,
    pub transcript_version_id: TranscriptVersionId,
    pub fri_plan_id: FriPlanId,
    pub batch_verification_enabled: bool,
    pub max_threads: u8,
    pub limits: ResourceLimits,
    pub air_spec_ids: AirSpecLayout,
}

/// Canonical digest binding all protocol parameters for a given profile.
///
/// The digest MUST be computed as follows:
///
/// * Concatenate `PARAM_DIGEST_DOMAIN_TAG` with the little-endian encoding of
///   the fields listed **in order**:
///   1. `profile_id:u8`
///   2. `field_id:u8`
///   3. `poseidon_param_id: [u8; 32]`
///   4. `merkle_scheme_id: [u8; 32]`
///   5. `transcript_version_id: [u8; 32]`
///   6. `fri_plan_id: [u8; 32]`
///   7. `lde_factor:u8`
///   8. `fri_queries:u16`
///   9. `fri_depth_min:u8`
///   10. `fri_depth_max:u8`
///   11. `max_proof_size_bytes:u32`
///   12. `max_layers:u8`
///   13. `max_queries:u16`
///   14. `per_proof_max_trace_width` for each [`ProofKind`] in canonical order
///       (`u16` each)
///   15. `per_proof_max_trace_steps` for each [`ProofKind`] in canonical order
///       (`u32` each)
///   16. `air_spec_id` for each [`ProofKind`] in canonical order (`[u8; 32]`
///       each)
///   17. `reserved:u16` (currently zero)
/// * Hash the resulting byte string with BLAKE3.
/// * The 32-byte output is stored in this wrapper.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ParamDigest(pub DigestBytes);

impl ParamDigest {
    /// Returns the raw 32-byte parameter digest committed by the profile.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0.bytes
    }
}

/// Digest binding a single proof's public inputs for deterministic batching.
/// The hash is computed as `BLAKE3(PI_DIGEST_DOMAIN_TAG || proof_kind:u8 ||
/// canonical_public_input_bytes)`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PiDigest(pub DigestBytes);

/// Common identifiers shared across all profiles.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommonIdentifiers {
    pub field_id: FieldId,
    pub merkle_scheme_id: MerkleSchemeId,
    pub transcript_version_id: TranscriptVersionId,
    pub fri_plan_id: FriPlanId,
}

/// Deterministic counters optionally collected by the verifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeterministicMetrics {
    pub hash_invocations: u64,
    pub field_operations: u64,
}

/// Context required by the prover to execute the deterministic pipeline. It
/// mirrors [`ProfileConfig`] and pins the negotiated identifiers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProverContext {
    pub profile: ProfileConfig,
    pub param_digest: ParamDigest,
    pub common_ids: CommonIdentifiers,
    pub limits: ResourceLimits,
    pub thread_pool: ThreadPoolProfile,
    pub chunking: ChunkingPolicy,
}

/// Context required by the verifier when replaying proofs. Mirrors the prover
/// context but may additionally expose deterministic counters.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifierContext {
    pub profile: ProfileConfig,
    pub param_digest: ParamDigest,
    pub common_ids: CommonIdentifiers,
    pub limits: ResourceLimits,
    pub metrics: Option<DeterministicMetrics>,
}

/// Shared configuration struct referencing profiles and parameter IDs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProofSystemConfig {
    pub proof_version: ProofVersion,
    pub profile: ProfileConfig,
    pub param_digest: ParamDigest,
}

impl ProofSystemConfig {
    /// Change-control statement for this configuration.
    pub const DESCRIPTION: &'static str =
        "ProofVersion bumps are reserved for envelope layout changes;\
         ParamDigest changes capture all parameter, limit or AIR updates.";
}

/// Computes the canonical [`ParamDigest`] for the provided profile.
///
/// The profile is hashed together with the shared identifiers contained in
/// [`CommonIdentifiers`] using the canonical order documented above. The digest
/// is deterministic and must be shared between prover and verifier.
pub fn compute_param_digest(
    profile: &ProfileConfig,
    common_ids: &CommonIdentifiers,
) -> ParamDigest {
    let mut hasher = Hasher::new();
    hasher.update(PARAM_DIGEST_DOMAIN_TAG);
    hasher.update(&profile.id.to_le_bytes());
    hasher.update(&common_ids.field_id.to_le_bytes());
    hasher.update(profile.poseidon_param_id.as_bytes());
    hasher.update(common_ids.merkle_scheme_id.as_bytes());
    hasher.update(common_ids.transcript_version_id.as_bytes());
    hasher.update(common_ids.fri_plan_id.as_bytes());
    hasher.update(&profile.lde_factor.to_le_bytes());
    hasher.update(&profile.fri_queries.to_le_bytes());
    hasher.update(&profile.fri_depth_range.min.to_le_bytes());
    hasher.update(&profile.fri_depth_range.max.to_le_bytes());
    hasher.update(&profile.limits.max_proof_size_bytes.to_le_bytes());
    hasher.update(&profile.limits.max_layers.to_le_bytes());
    hasher.update(&profile.limits.max_queries.to_le_bytes());

    for kind in ProofKind::ORDER.iter() {
        let width = *profile.limits.per_proof_max_trace_width.get(*kind);
        hasher.update(&width.to_le_bytes());
    }

    for kind in ProofKind::ORDER.iter() {
        let steps = *profile.limits.per_proof_max_trace_steps.get(*kind);
        hasher.update(&steps.to_le_bytes());
    }

    for kind in ProofKind::ORDER.iter() {
        let air_spec_id = profile.air_spec_ids.get(*kind);
        hasher.update(air_spec_id.as_bytes());
    }

    hasher.update(&0u16.to_le_bytes());

    ParamDigest(DigestBytes {
        bytes: *hasher.finalize().as_bytes(),
    })
}

/// Binds the proof version to the provided profile and parameter digest.
pub fn build_proof_system_config(
    profile: &ProfileConfig,
    param_digest: &ParamDigest,
) -> ProofSystemConfig {
    ProofSystemConfig {
        proof_version: PROOF_VERSION_V1,
        profile: profile.clone(),
        param_digest: param_digest.clone(),
    }
}

/// Builds a [`ProverContext`] by pairing the profile with deterministic
/// threading information and the canonical parameter digest.
pub fn build_prover_context(
    profile: &ProfileConfig,
    common_ids: &CommonIdentifiers,
    param_digest: &ParamDigest,
    thread_pool: ThreadPoolProfile,
    chunking: ChunkingPolicy,
) -> ProverContext {
    ProverContext {
        profile: profile.clone(),
        param_digest: param_digest.clone(),
        common_ids: common_ids.clone(),
        limits: profile.limits.clone(),
        thread_pool,
        chunking,
    }
}

/// Builds a [`VerifierContext`] tied to the canonical parameter digest and
/// optional deterministic metrics.
pub fn build_verifier_context(
    profile: &ProfileConfig,
    common_ids: &CommonIdentifiers,
    param_digest: &ParamDigest,
    metrics: Option<DeterministicMetrics>,
) -> VerifierContext {
    VerifierContext {
        profile: profile.clone(),
        param_digest: param_digest.clone(),
        common_ids: common_ids.clone(),
        limits: profile.limits.clone(),
        metrics,
    }
}

const fn digest(bytes: [u8; 32]) -> DigestBytes {
    DigestBytes { bytes }
}

/// Canonical Merkle scheme identifier (`BLAKE3_2ARY_V1`).
pub const MERKLE_SCHEME_ID_BLAKE3_2ARY_V1: MerkleSchemeId = MerkleSchemeId(digest([
    b'B', b'L', b'A', b'K', b'E', b'3', b'_', b'2', b'A', b'R', b'Y', b'_', b'V', b'1', 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
]));

/// Canonical Merkle scheme identifier (`BLAKE3_4ARY_V1`).
pub const MERKLE_SCHEME_ID_BLAKE3_4ARY_V1: MerkleSchemeId = MerkleSchemeId(digest([
    b'B', b'L', b'A', b'K', b'E', b'3', b'_', b'4', b'A', b'R', b'Y', b'_', b'V', b'1', 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2,
]));

/// Canonical transcript identifier (`RPP_FS_V1`).
pub const TRANSCRIPT_VERSION_ID_RPP_FS_V1: TranscriptVersionId = TranscriptVersionId(digest([
    b'R', b'P', b'P', b'_', b'F', b'S', b'_', b'V', b'1', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 1,
]));

/// Canonical FRI folding plan identifier (fold factor 2).
pub const FRI_PLAN_ID_FOLD2_V1: FriPlanId = FriPlanId(digest([
    b'F', b'R', b'I', b'_', b'P', b'L', b'A', b'N', b'_', b'F', b'2', b'_', b'V', b'1', 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2,
]));

/// Poseidon parameter identifier for `rf=8, rp=56`.
pub const POSEIDON_PARAM_ID_STANDARD: PoseidonParamId = PoseidonParamId(digest([
    b'P', b'O', b'S', b'E', b'I', b'D', b'O', b'N', b'_', b'R', b'F', b'8', b'_', b'R', b'P', b'5',
    b'6', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
]));

/// Poseidon parameter identifier for `rf=8, rp=60` (high-security profile).
pub const POSEIDON_PARAM_ID_HISEC: PoseidonParamId = PoseidonParamId(digest([
    b'P', b'O', b'S', b'E', b'I', b'D', b'O', b'N', b'_', b'R', b'F', b'8', b'_', b'R', b'P', b'6',
    b'0', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2,
]));

/// Placeholder AIR identifiers for all proof kinds (version 1 lineage).
pub const AIR_SPEC_IDS_V1: AirSpecLayout = ProofKindLayout {
    tx: AirSpecId(digest([
        b'R', b'P', b'P', b'-', b'T', b'X', b'-', b'A', b'I', b'R', b'-', b'V', b'1', 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
    ])),
    state: AirSpecId(digest([
        b'R', b'P', b'P', b'-', b'S', b'T', b'A', b'T', b'E', b'-', b'A', b'I', b'R', b'-', b'V',
        b'1', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2,
    ])),
    pruning: AirSpecId(digest([
        b'R', b'P', b'P', b'-', b'P', b'R', b'U', b'N', b'E', b'-', b'A', b'I', b'R', b'-', b'V',
        b'1', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3,
    ])),
    uptime: AirSpecId(digest([
        b'R', b'P', b'P', b'-', b'U', b'P', b'T', b'I', b'M', b'E', b'-', b'A', b'I', b'R', b'-',
        b'1', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4,
    ])),
    consensus: AirSpecId(digest([
        b'R', b'P', b'P', b'-', b'C', b'O', b'N', b'S', b'E', b'N', b'S', b'U', b'S', b'-', b'V',
        b'1', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 5,
    ])),
    identity: AirSpecId(digest([
        b'R', b'P', b'P', b'-', b'I', b'D', b'E', b'N', b'T', b'I', b'T', b'Y', b'-', b'V', b'1',
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 6,
    ])),
    aggregation: AirSpecId(digest([
        b'R', b'P', b'P', b'-', b'A', b'G', b'G', b'R', b'E', b'G', b'-', b'V', b'1', 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 7,
    ])),
    vrf: AirSpecId(digest([
        b'R', b'P', b'P', b'-', b'V', b'R', b'F', b'-', b'V', b'1', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 8,
    ])),
};

/// Common identifiers shared across profiles.
pub const COMMON_IDENTIFIERS: CommonIdentifiers = CommonIdentifiers {
    field_id: FIELD_ID_GOLDILOCKS_64,
    merkle_scheme_id: MERKLE_SCHEME_ID_BLAKE3_2ARY_V1,
    transcript_version_id: TRANSCRIPT_VERSION_ID_RPP_FS_V1,
    fri_plan_id: FRI_PLAN_ID_FOLD2_V1,
};

/// Common identifiers variant using quaternary Merkle commitments.
pub const COMMON_IDENTIFIERS_ARITY4: CommonIdentifiers = CommonIdentifiers {
    field_id: FIELD_ID_GOLDILOCKS_64,
    merkle_scheme_id: MERKLE_SCHEME_ID_BLAKE3_4ARY_V1,
    transcript_version_id: TRANSCRIPT_VERSION_ID_RPP_FS_V1,
    fri_plan_id: FRI_PLAN_ID_FOLD2_V1,
};

/// Standard profile configuration (`PROFILE_STD`).
pub const PROFILE_STANDARD_CONFIG: ProfileConfig = ProfileConfig {
    id: PROFILE_STD,
    name: "standard",
    security_goal: "80-bit query soundness with balanced throughput",
    lde_factor: 8,
    fri_queries: 64,
    fri_depth_range: FriDepthRange { min: 8, max: 12 },
    poseidon_rounds: PoseidonRoundConfiguration {
        full_rounds: 8,
        partial_rounds: 56,
    },
    poseidon_param_id: POSEIDON_PARAM_ID_STANDARD,
    merkle_scheme_id: MERKLE_SCHEME_ID_BLAKE3_2ARY_V1,
    transcript_version_id: TRANSCRIPT_VERSION_ID_RPP_FS_V1,
    fri_plan_id: FRI_PLAN_ID_FOLD2_V1,
    batch_verification_enabled: true,
    max_threads: 8,
    limits: ResourceLimits {
        max_proof_size_bytes: 1_500_000,
        max_layers: 16,
        max_queries: 96,
        per_proof_max_trace_width: ProofKindLayout {
            tx: 64,
            state: 128,
            pruning: 96,
            uptime: 48,
            consensus: 96,
            identity: 64,
            aggregation: 160,
            vrf: 48,
        },
        per_proof_max_trace_steps: ProofKindLayout {
            tx: 1_048_576,
            state: 4_194_304,
            pruning: 2_097_152,
            uptime: 524_288,
            consensus: 1_048_576,
            identity: 262_144,
            aggregation: 1_048_576,
            vrf: 131_072,
        },
    },
    air_spec_ids: AIR_SPEC_IDS_V1,
};

/// Standard profile using the quaternary Merkle commitment scheme.
pub const PROFILE_STANDARD_ARITY4_CONFIG: ProfileConfig = ProfileConfig {
    id: PROFILE_STD_ARITY4,
    name: "standard-arity4",
    security_goal: "80-bit query soundness with quaternary Merkle commitments",
    lde_factor: 8,
    fri_queries: 64,
    fri_depth_range: FriDepthRange { min: 8, max: 12 },
    poseidon_rounds: PoseidonRoundConfiguration {
        full_rounds: 8,
        partial_rounds: 56,
    },
    poseidon_param_id: POSEIDON_PARAM_ID_STANDARD,
    merkle_scheme_id: MERKLE_SCHEME_ID_BLAKE3_4ARY_V1,
    transcript_version_id: TRANSCRIPT_VERSION_ID_RPP_FS_V1,
    fri_plan_id: FRI_PLAN_ID_FOLD2_V1,
    batch_verification_enabled: true,
    max_threads: 8,
    limits: ResourceLimits {
        max_proof_size_bytes: 1_500_000,
        max_layers: 16,
        max_queries: 96,
        per_proof_max_trace_width: ProofKindLayout {
            tx: 64,
            state: 128,
            pruning: 96,
            uptime: 48,
            consensus: 96,
            identity: 64,
            aggregation: 160,
            vrf: 48,
        },
        per_proof_max_trace_steps: ProofKindLayout {
            tx: 1_048_576,
            state: 4_194_304,
            pruning: 2_097_152,
            uptime: 524_288,
            consensus: 1_048_576,
            identity: 262_144,
            aggregation: 1_048_576,
            vrf: 131_072,
        },
    },
    air_spec_ids: AIR_SPEC_IDS_V1,
};

/// High-security profile configuration (`PROFILE_HISEC`).
pub const PROFILE_HIGH_SECURITY_CONFIG: ProfileConfig = ProfileConfig {
    id: PROFILE_HISEC,
    name: "high-security",
    security_goal: "128-bit query soundness with increased redundancy",
    lde_factor: 16,
    fri_queries: 96,
    fri_depth_range: FriDepthRange { min: 10, max: 14 },
    poseidon_rounds: PoseidonRoundConfiguration {
        full_rounds: 8,
        partial_rounds: 60,
    },
    poseidon_param_id: POSEIDON_PARAM_ID_HISEC,
    merkle_scheme_id: MERKLE_SCHEME_ID_BLAKE3_2ARY_V1,
    transcript_version_id: TRANSCRIPT_VERSION_ID_RPP_FS_V1,
    fri_plan_id: FRI_PLAN_ID_FOLD2_V1,
    batch_verification_enabled: true,
    max_threads: 12,
    limits: ResourceLimits {
        max_proof_size_bytes: 2_200_000,
        max_layers: 20,
        max_queries: 128,
        per_proof_max_trace_width: ProofKindLayout {
            tx: 80,
            state: 160,
            pruning: 120,
            uptime: 60,
            consensus: 120,
            identity: 80,
            aggregation: 200,
            vrf: 60,
        },
        per_proof_max_trace_steps: ProofKindLayout {
            tx: 1_310_720,
            state: 5_242_880,
            pruning: 2_621_440,
            uptime: 655_360,
            consensus: 1_310_720,
            identity: 327_680,
            aggregation: 1_310_720,
            vrf: 163_840,
        },
    },
    air_spec_ids: AIR_SPEC_IDS_V1,
};

/// High-throughput profile configuration (`PROFILE_THROUGHPUT`).
pub const PROFILE_THROUGHPUT_CONFIG: ProfileConfig = ProfileConfig {
    id: PROFILE_THROUGHPUT,
    name: "high-throughput",
    security_goal: "Reduced latency; retains standard soundness assumptions",
    lde_factor: 8,
    fri_queries: 48,
    fri_depth_range: FriDepthRange { min: 8, max: 10 },
    poseidon_rounds: PoseidonRoundConfiguration {
        full_rounds: 8,
        partial_rounds: 56,
    },
    poseidon_param_id: POSEIDON_PARAM_ID_STANDARD,
    merkle_scheme_id: MERKLE_SCHEME_ID_BLAKE3_2ARY_V1,
    transcript_version_id: TRANSCRIPT_VERSION_ID_RPP_FS_V1,
    fri_plan_id: FRI_PLAN_ID_FOLD2_V1,
    batch_verification_enabled: true,
    max_threads: 8,
    limits: ResourceLimits {
        max_proof_size_bytes: 1_200_000,
        max_layers: 14,
        max_queries: 64,
        per_proof_max_trace_width: ProofKindLayout {
            tx: 64,
            state: 128,
            pruning: 96,
            uptime: 48,
            consensus: 96,
            identity: 64,
            aggregation: 160,
            vrf: 48,
        },
        per_proof_max_trace_steps: ProofKindLayout {
            tx: 1_048_576,
            state: 4_194_304,
            pruning: 2_097_152,
            uptime: 524_288,
            consensus: 1_048_576,
            identity: 262_144,
            aggregation: 1_048_576,
            vrf: 131_072,
        },
    },
    air_spec_ids: AIR_SPEC_IDS_V1,
};

/// Canonical proof version of the envelope layout.
pub const PROOF_VERSION_V1: ProofVersion = ProofVersion(1);

/// Change-control policy:
///
/// * **ProofVersion**: increment only when the proof envelope byte layout
///   changes (new sections, reordered fields, endianness adjustments, …).
/// * **ParamDigest**: recompute whenever any profile parameter, identifier,
///   limit or AIR specification changes. Switching profiles, updating
///   Poseidon/Merkle/transcript identifiers, tweaking FRI parameters, touching
///   limits or bumping an AIR specification ID all trigger a new digest.
/// * **PI digests**: recompute whenever public-input encoding per proof kind
///   changes.
///
/// There is no fallback: prover and verifier must agree on all identifiers and
/// digests before any proof exchange.
pub const CHANGE_CONTROL_RULES: &str = "ProofVersion bumps reserved for envelope layout;\
ParamDigest changes cover any parameter or AIR updates;\
PI digests updated on public-input layout changes.";

/// Test obligations expected from implementations:
///
/// 1. Recompute [`ParamDigest`] deterministically across repeated runs for the
///    same profile.
/// 2. Switching profiles (e.g. standard → high-security) must yield a new
///    [`ParamDigest`] without altering the [`ProofVersion`].
/// 3. Mutating any AIR specification identifier must change the
///    [`ParamDigest`].
/// 4. Adjusting limits such as `max_proof_size_bytes` must change the
///    [`ParamDigest`].
/// 5. Enforce the global [`ProofKind::ORDER`]; any deviation is a protocol
///    error.
/// 6. Cross-check prover and verifier contexts for digest equality and abort on
///    mismatches.
/// 7. Validate deterministic threading by running with fixed worker counts and
///    verifying reproducible digests.
pub const TEST_OBLIGATIONS: &str = "Determinism, profile switching, AIR updates, limit changes,\
proof-kind order invariants and prover/verifier cross-checks must be covered.";

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proof::public_inputs::{ExecutionHeaderV1, PublicInputVersion, PublicInputs};
    use crate::proof::types::VerifyError;
    use crate::proof::verifier::verify;
    use crate::utils::serialization::{DigestBytes, ProofBytes};

    fn sample_public_inputs() -> PublicInputs<'static> {
        PublicInputs::Execution {
            header: ExecutionHeaderV1 {
                version: PublicInputVersion::V1,
                program_digest: DigestBytes { bytes: [0u8; 32] },
                trace_length: 1,
                trace_width: 1,
            },
            body: b"",
        }
    }

    #[test]
    fn paramdigest_differs_between_std_and_hisec_ok() {
        let common_ids = COMMON_IDENTIFIERS.clone();
        let std_profile = PROFILE_STANDARD_CONFIG.clone();
        let hisec_profile = PROFILE_HIGH_SECURITY_CONFIG.clone();

        let std_digest = compute_param_digest(&std_profile, &common_ids);
        let hisec_digest = compute_param_digest(&hisec_profile, &common_ids);

        assert_ne!(std_digest, hisec_digest);
    }

    #[test]
    fn paramdigest_profile_switch_preserves_proof_version_ok() {
        let common_ids = COMMON_IDENTIFIERS.clone();
        let std_profile = PROFILE_STANDARD_CONFIG.clone();
        let hisec_profile = PROFILE_HIGH_SECURITY_CONFIG.clone();

        let std_digest = compute_param_digest(&std_profile, &common_ids);
        let hisec_digest = compute_param_digest(&hisec_profile, &common_ids);

        let std_config = build_proof_system_config(&std_profile, &std_digest);
        let hisec_config = build_proof_system_config(&hisec_profile, &hisec_digest);

        assert_eq!(std_config.proof_version, hisec_config.proof_version);
    }

    #[test]
    fn paramdigest_enforced_by_verifier_rejects_mismatch() {
        let common_ids = COMMON_IDENTIFIERS.clone();
        let std_profile = PROFILE_STANDARD_CONFIG.clone();
        let hisec_profile = PROFILE_HIGH_SECURITY_CONFIG.clone();

        let std_digest = compute_param_digest(&std_profile, &common_ids);
        let hisec_digest = compute_param_digest(&hisec_profile, &common_ids);

        let std_config = build_proof_system_config(&std_profile, &std_digest);
        let hisec_context =
            build_verifier_context(&hisec_profile, &common_ids, &hisec_digest, None);

        let public_inputs = sample_public_inputs();
        let proof_bytes = ProofBytes::new(Vec::new());

        let report = verify(
            ProofKind::Tx,
            &public_inputs,
            &proof_bytes,
            &std_config,
            &hisec_context,
        );

        assert!(matches!(
            report.error,
            Some(VerifyError::ParamsHashMismatch)
        ));
    }
}
