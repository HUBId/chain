//! BLAKE3 transcript specification and Fiat–Shamir challenge derivation rules.
//!
//! This module documents how transcripts are framed, which domain prefixes are
//! accepted and how deterministic challenges are sampled.  No hashing logic is
//! included; the declarations are intended to be consumed by host environments
//! that provide a stable BLAKE3 implementation.

/// Canonical domain descriptors used when instantiating transcripts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Blake3Domain {
    /// ASCII prefix absorbed before the domain specific payload.
    pub canonical_prefix: &'static str,
    /// Human readable description aiding audits.
    pub description: &'static str,
}

impl Blake3Domain {
    /// Returns the static list of byte-oriented domains.
    pub const fn all() -> &'static [Blake3Domain] {
        &[
            Blake3Domain {
                canonical_prefix: "RPP-TX",
                description: "Transaction level commitments",
            },
            Blake3Domain {
                canonical_prefix: "RPP-UPTIME",
                description: "Liveness and uptime attestations",
            },
            Blake3Domain {
                canonical_prefix: "RPP-CONSENSUS",
                description: "Consensus round binding",
            },
            Blake3Domain {
                canonical_prefix: "RPP-STATE",
                description: "Global state roots",
            },
            Blake3Domain {
                canonical_prefix: "RPP-PRUNING",
                description: "Pruning digests shared with Poseidon",
            },
            Blake3Domain {
                canonical_prefix: "RPP-AGG",
                description: "Batch aggregation seed namespace",
            },
            Blake3Domain {
                canonical_prefix: "RPP-MERKLE-2",
                description: "Binary Merkle commitment namespace",
            },
        ]
    }

    /// Dynamic prefix used for FRI layer transcripts (`RPP-FRI-LAYER-{i}`).
    pub const FRI_LAYER_PREFIX: &'static str = "RPP-FRI-LAYER-";
}

/// Transcript sections in the canonical ordering.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Blake3TranscriptSection {
    /// ASCII domain tag (including optional sub-tag).
    DomainTag,
    /// Public inputs serialized with little-endian length prefixes.
    PublicInputs,
    /// Commitment roots (Merkle and FRI) in deterministic order.
    CommitmentRoots,
    /// Parameter digest binding configuration knobs.
    ParameterDigest,
    /// Block level context (height, previous root, network id, proof version).
    BlockContext,
}

impl Blake3TranscriptSection {
    /// Canonical ordering used for Fiat–Shamir derivation.
    pub const ORDER: [Blake3TranscriptSection; 5] = [
        Blake3TranscriptSection::DomainTag,
        Blake3TranscriptSection::PublicInputs,
        Blake3TranscriptSection::CommitmentRoots,
        Blake3TranscriptSection::ParameterDigest,
        Blake3TranscriptSection::BlockContext,
    ];
}

/// Phase tags delimiting transcript restarts (AIR → FRI).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TranscriptPhaseTag {
    /// Algebraic intermediate representation phase.
    Air,
    /// FRI phase for low degree testing.
    Fri,
}

impl TranscriptPhaseTag {
    /// Returns the ASCII identifier injected before restarting sections.
    pub const fn label(self) -> &'static str {
        match self {
            TranscriptPhaseTag::Air => "RPP-PHASE-AIR",
            TranscriptPhaseTag::Fri => "RPP-PHASE-FRI",
        }
    }
}

/// Static transcript specification with deterministic framing instructions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Blake3TranscriptSpec;

impl Blake3TranscriptSpec {
    /// Little-endian framing: each section is encoded as `len: u32` + payload.
    pub const FRAMING_RULE: &'static str = "u32 little-endian length prefix per section";
    /// Canonical ordering of sections before hashing.
    pub const SECTIONS: &'static [Blake3TranscriptSection; 5] = &Blake3TranscriptSection::ORDER;
    /// All payloads must use little-endian integer encodings.
    pub const ENDIANNESS: &'static str = "little-endian for integers, field bytes and indices";
    /// Transcript restarts when phase tags are inserted.
    pub const PHASE_BEHAVIOUR: &'static str =
        "Insert phase tag (RPP-PHASE-AIR/FRI), restart sections 1..5, continue hashing";
}

/// Fiat–Shamir challenge derivation using chained BLAKE3 hashes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FiatShamirChallengeRules;

impl FiatShamirChallengeRules {
    /// Salt prefix used after the initial challenge draw.
    pub const SALT_PREFIX: &'static str = "RPP-FS/";
    /// Description of the recurrence relation binding challenges.
    pub const DESCRIPTION: &'static str =
        "challenge_0 = BLAKE3(sections 1..5); challenge_{i+1} = BLAKE3(challenge_i || ASCII('RPP-FS/i'))";
}

/// Versioning for transcript layouts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Blake3TranscriptVersion {
    /// Monotonic version counter (starts at 1).
    pub version: u8,
    /// Digest binding framing, domains and challenge derivation rules.
    pub digest: [u8; 32],
}

impl Blake3TranscriptVersion {
    /// First documented transcript version (stable).
    pub const V1: Blake3TranscriptVersion = Blake3TranscriptVersion {
        version: 1,
        digest: [
            0x52, 0x50, 0x50, 0x2d, 0x42, 0x4c, 0x41, 0x4b, 0x45, 0x33, 0x2d, 0x54, 0x52, 0x41,
            0x4e, 0x53, 0x43, 0x52, 0x49, 0x50, 0x54, 0x2d, 0x56, 0x31, 0x2d, 0x30, 0x30, 0x30,
            0x30, 0x30, 0x30, 0x30,
        ],
    };
}
