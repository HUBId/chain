#![deny(unsafe_code)]
#![doc = "Canonical pruning data structures shared across pruning-aware components."]

//! This crate defines canonical serialization formats for pruning snapshots and
//! associated commitments.  The goal is to ensure that pruning data exchanged
//! between nodes is stable across implementations, schema upgrades, and
//! serialization backends.  The types exposed here enforce the following
//! guarantees:
//!
//! * Schema and parameter versions are carried explicitly as big-endian byte
//!   sequences.  The conversion helpers guarantee that the canonical byte order
//!   is preserved independently from the platform endianness.
//! * Hashes are wrapped in [`TaggedDigest`] so that every digest is paired with a
//!   domain-separation tag.  When serialized, the tag is emitted before the raw
//!   digest bytes, making the prefixed representation unambiguous.
//! * Helper constructors perform validation so callers cannot accidentally mix
//!   and match domain tags.  This makes round-tripping through
//!   [`serde`]/[`bincode`] deterministic when combined with
//!   [`canonical_bincode_options`].
//!
//! The domain tags are ASCII identifiers padded to sixteen bytes.  They are
//!   chosen to describe the semantic context of the digest:
//!
//! * [`SNAPSHOT_STATE_TAG`] – commitments to the prunable state itself.
//! * [`PROOF_SEGMENT_TAG`] – merkle segments that prove inclusion of snapshot
//!   chunks.
//! * [`COMMITMENT_TAG`] – aggregate commitments that bind a snapshot and its
//!   segments together.
//! * [`ENVELOPE_TAG`] – outer envelope bindings that authenticate the entire
//!   payload when transported over the network.
//!
//! Downstream crates should treat these definitions as the source of truth when
//! exchanging pruning data.  Doing so avoids divergence in serialization logic
//! and keeps pruning proofs fully deterministic.

use bincode::Options;
use core::fmt;
use serde::{Deserialize, Serialize};

/// Canonical configuration for `bincode` consumers of this crate.
///
/// The returned options enforce fixed-width integer encoding while retaining
/// the default behaviour of rejecting trailing bytes, which keeps the
/// serialized stream deterministic.
pub fn canonical_bincode_options() -> impl Options {
    bincode::DefaultOptions::new().with_fixint_encoding()
}

/// Errors reported when validating tagged digests and structured documents.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValidationError {
    /// Raised when a [`TaggedDigest`] does not carry the expected domain tag.
    UnexpectedDomainTag {
        /// Domain tag that was expected by the caller.
        expected: DomainTag,
        /// Domain tag actually stored in the digest.
        actual: DomainTag,
    },
    /// Raised when a proof segment range is malformed.
    InvalidSegmentRange {
        /// Inclusive lower bound of the range that failed validation.
        start: BlockHeight,
        /// Inclusive upper bound of the range that failed validation.
        end: BlockHeight,
    },
}

impl fmt::Display for ValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ValidationError::UnexpectedDomainTag { expected, actual } => {
                write!(
                    f,
                    "domain tag mismatch (expected {:x?}, found {:x?})",
                    expected.as_bytes(),
                    actual.as_bytes()
                )
            }
            ValidationError::InvalidSegmentRange { start, end } => {
                write!(f, "invalid proof segment range: {} > {}", start.as_u64(), end.as_u64())
            }
        }
    }
}

/// Sixteen byte domain-separation tags used by the pruning structures.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct DomainTag {
    bytes: [u8; DOMAIN_TAG_LENGTH],
}

impl DomainTag {
    /// Creates a new domain tag from a fixed-length byte array.
    pub const fn new(bytes: [u8; DOMAIN_TAG_LENGTH]) -> Self {
        Self { bytes }
    }

    /// Returns the raw tag bytes.
    pub const fn as_bytes(self) -> [u8; DOMAIN_TAG_LENGTH] {
        self.bytes
    }
}

/// Domain tag for [`Snapshot::state_commitment`].
pub const SNAPSHOT_STATE_TAG: DomainTag = DomainTag::new(*b"rpp:prune:state\0");
/// Domain tag for [`ProofSegment::segment_commitment`].
pub const PROOF_SEGMENT_TAG: DomainTag = DomainTag::new(*b"rpp:prune:proof\0");
/// Domain tag for [`Commitment::aggregate_commitment`].
pub const COMMITMENT_TAG: DomainTag = DomainTag::new(*b"rpp:prune:commit");
/// Domain tag for [`Envelope::binding_digest`].
pub const ENVELOPE_TAG: DomainTag = DomainTag::new(*b"rpp:prune:envlp\0");

/// Number of bytes used by every domain tag.
pub const DOMAIN_TAG_LENGTH: usize = 16;
/// Number of bytes used by hashing algorithms referenced by this module.
pub const DIGEST_LENGTH: usize = 32;

/// Digest that is prefixed with a [`DomainTag`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct TaggedDigest {
    tag: DomainTag,
    digest: [u8; DIGEST_LENGTH],
}

impl TaggedDigest {
    /// Builds a new tagged digest with the provided domain tag and raw digest bytes.
    pub const fn new(tag: DomainTag, digest: [u8; DIGEST_LENGTH]) -> Self {
        Self { tag, digest }
    }

    /// Accessor for the domain tag.
    pub const fn tag(self) -> DomainTag {
        self.tag
    }

    /// Accessor for the raw digest bytes.
    pub const fn digest(&self) -> &[u8; DIGEST_LENGTH] {
        &self.digest
    }

    /// Returns the concatenation `tag || digest`, which is useful when hashing
    /// higher-level structures.
    pub fn prefixed_bytes(&self) -> [u8; DOMAIN_TAG_LENGTH + DIGEST_LENGTH] {
        let mut bytes = [0u8; DOMAIN_TAG_LENGTH + DIGEST_LENGTH];
        bytes[..DOMAIN_TAG_LENGTH].copy_from_slice(&self.tag.as_bytes());
        bytes[DOMAIN_TAG_LENGTH..].copy_from_slice(&self.digest);
        bytes
    }

    /// Ensures that this digest carries the expected domain tag.
    pub fn ensure_tag(&self, expected: DomainTag) -> Result<(), ValidationError> {
        if self.tag == expected {
            Ok(())
        } else {
            Err(ValidationError::UnexpectedDomainTag {
                expected,
                actual: self.tag,
            })
        }
    }
}

macro_rules! be_bytes_newtype {
    ($(#[$meta:meta])* $vis:vis struct $name:ident([$len:expr]); $int:ty) => {
        $(#[$meta])*
        #[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
        $vis struct $name {
            bytes: [u8; $len],
        }

        impl $name {
            /// Creates a new value from its native integer representation.
            pub const fn new(value: $int) -> Self {
                Self { bytes: value.to_be_bytes() }
            }

            /// Returns the native integer represented by this value.
            pub const fn get(self) -> $int {
                <$int>::from_be_bytes(self.bytes)
            }
        }

        impl From<$int> for $name {
            fn from(value: $int) -> Self {
                Self::new(value)
            }
        }

        impl From<$name> for $int {
            fn from(value: $name) -> Self {
                value.get()
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}", self.get())
            }
        }
    };
}

be_bytes_newtype!(/// Schema version identifier stored using two big-endian bytes.
pub struct SchemaVersion([2]); u16);
be_bytes_newtype!(/// Parameter version identifier stored using two big-endian bytes.
pub struct ParameterVersion([2]); u16);
be_bytes_newtype!(/// Inclusive block height stored using eight big-endian bytes.
pub struct BlockHeight([8]); u64);
be_bytes_newtype!(/// Segment index stored using four big-endian bytes.
pub struct SegmentIndex([4]); u32);

impl BlockHeight {
    /// Returns the block height as a `u64`.
    pub const fn as_u64(self) -> u64 {
        self.get()
    }
}

impl SegmentIndex {
    /// Returns the underlying index as a `u32`.
    pub const fn as_u32(self) -> u32 {
        self.get()
    }
}

/// Canonical pruning snapshot that binds schema/parameter versions to a state commitment.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Snapshot {
    schema_version: SchemaVersion,
    parameter_version: ParameterVersion,
    block_height: BlockHeight,
    state_commitment: TaggedDigest,
}

impl Snapshot {
    /// Constructs a snapshot after verifying that the commitment uses the
    /// [`SNAPSHOT_STATE_TAG`].
    pub fn new(
        schema_version: SchemaVersion,
        parameter_version: ParameterVersion,
        block_height: BlockHeight,
        state_commitment: TaggedDigest,
    ) -> Result<Self, ValidationError> {
        state_commitment.ensure_tag(SNAPSHOT_STATE_TAG)?;
        Ok(Self {
            schema_version,
            parameter_version,
            block_height,
            state_commitment,
        })
    }

    /// Returns the schema version identifier.
    pub const fn schema_version(&self) -> SchemaVersion {
        self.schema_version
    }

    /// Returns the parameter version identifier.
    pub const fn parameter_version(&self) -> ParameterVersion {
        self.parameter_version
    }

    /// Returns the height of the block used to generate the snapshot.
    pub const fn block_height(&self) -> BlockHeight {
        self.block_height
    }

    /// Returns the state commitment.
    pub const fn state_commitment(&self) -> TaggedDigest {
        self.state_commitment
    }
}

/// A segment that proves inclusion of a pruning snapshot chunk.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofSegment {
    schema_version: SchemaVersion,
    parameter_version: ParameterVersion,
    segment_index: SegmentIndex,
    start_height: BlockHeight,
    end_height: BlockHeight,
    segment_commitment: TaggedDigest,
}

impl ProofSegment {
    /// Constructs a proof segment after validating the commitment tag and the
    /// height range ordering.
    pub fn new(
        schema_version: SchemaVersion,
        parameter_version: ParameterVersion,
        segment_index: SegmentIndex,
        start_height: BlockHeight,
        end_height: BlockHeight,
        segment_commitment: TaggedDigest,
    ) -> Result<Self, ValidationError> {
        if start_height.as_u64() > end_height.as_u64() {
            return Err(ValidationError::InvalidSegmentRange {
                start: start_height,
                end: end_height,
            });
        }
        segment_commitment.ensure_tag(PROOF_SEGMENT_TAG)?;
        Ok(Self {
            schema_version,
            parameter_version,
            segment_index,
            start_height,
            end_height,
            segment_commitment,
        })
    }

    /// Returns the schema version identifier.
    pub const fn schema_version(&self) -> SchemaVersion {
        self.schema_version
    }

    /// Returns the parameter version identifier.
    pub const fn parameter_version(&self) -> ParameterVersion {
        self.parameter_version
    }

    /// Returns the segment index.
    pub const fn segment_index(&self) -> SegmentIndex {
        self.segment_index
    }

    /// Returns the inclusive starting block height for the segment.
    pub const fn start_height(&self) -> BlockHeight {
        self.start_height
    }

    /// Returns the inclusive ending block height for the segment.
    pub const fn end_height(&self) -> BlockHeight {
        self.end_height
    }

    /// Returns the commitment that authenticates the segment contents.
    pub const fn segment_commitment(&self) -> TaggedDigest {
        self.segment_commitment
    }
}

/// Aggregate commitment that binds snapshots and segments.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Commitment {
    schema_version: SchemaVersion,
    parameter_version: ParameterVersion,
    aggregate_commitment: TaggedDigest,
}

impl Commitment {
    /// Builds a commitment validated against the [`COMMITMENT_TAG`].
    pub fn new(
        schema_version: SchemaVersion,
        parameter_version: ParameterVersion,
        aggregate_commitment: TaggedDigest,
    ) -> Result<Self, ValidationError> {
        aggregate_commitment.ensure_tag(COMMITMENT_TAG)?;
        Ok(Self {
            schema_version,
            parameter_version,
            aggregate_commitment,
        })
    }

    /// Returns the schema version identifier.
    pub const fn schema_version(&self) -> SchemaVersion {
        self.schema_version
    }

    /// Returns the parameter version identifier.
    pub const fn parameter_version(&self) -> ParameterVersion {
        self.parameter_version
    }

    /// Returns the aggregate commitment digest.
    pub const fn aggregate_commitment(&self) -> TaggedDigest {
        self.aggregate_commitment
    }
}

/// Outer envelope that wraps snapshots, proof segments, and the aggregate commitment.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Envelope {
    schema_version: SchemaVersion,
    parameter_version: ParameterVersion,
    snapshot: Snapshot,
    segments: Vec<ProofSegment>,
    commitment: Commitment,
    binding_digest: TaggedDigest,
}

impl Envelope {
    /// Builds an envelope validated against the [`ENVELOPE_TAG`].
    pub fn new(
        schema_version: SchemaVersion,
        parameter_version: ParameterVersion,
        snapshot: Snapshot,
        segments: Vec<ProofSegment>,
        commitment: Commitment,
        binding_digest: TaggedDigest,
    ) -> Result<Self, ValidationError> {
        binding_digest.ensure_tag(ENVELOPE_TAG)?;
        Ok(Self {
            schema_version,
            parameter_version,
            snapshot,
            segments,
            commitment,
            binding_digest,
        })
    }

    /// Returns the schema version identifier.
    pub const fn schema_version(&self) -> SchemaVersion {
        self.schema_version
    }

    /// Returns the parameter version identifier.
    pub const fn parameter_version(&self) -> ParameterVersion {
        self.parameter_version
    }

    /// Returns the snapshot carried by this envelope.
    pub fn snapshot(&self) -> &Snapshot {
        &self.snapshot
    }

    /// Returns the proof segments carried by this envelope.
    pub fn segments(&self) -> &[ProofSegment] {
        &self.segments
    }

    /// Returns the aggregate commitment for the envelope.
    pub fn commitment(&self) -> &Commitment {
        &self.commitment
    }

    /// Returns the binding digest that authenticates the envelope.
    pub const fn binding_digest(&self) -> TaggedDigest {
        self.binding_digest
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn snapshot_roundtrip_is_canonical() {
        let snapshot = Snapshot::new(
            SchemaVersion::new(1),
            ParameterVersion::new(2),
            BlockHeight::new(3),
            TaggedDigest::new(SNAPSHOT_STATE_TAG, [0x11; DIGEST_LENGTH]),
        )
        .unwrap();
        let bytes = canonical_bincode_options()
            .serialize(&snapshot)
            .expect("serialization must succeed");
        // Schema version (0,1), parameter version (0,2), block height (0..0,3), tag, digest.
        assert_eq!(bytes[0..2], [0, 1]);
        assert_eq!(bytes[2..4], [0, 2]);
        assert_eq!(bytes[4..12], [0, 0, 0, 0, 0, 0, 0, 3]);
        assert_eq!(bytes[12..28], SNAPSHOT_STATE_TAG.as_bytes());
        assert_eq!(bytes[28..], vec![0x11; DIGEST_LENGTH]);
    }

    #[test]
    fn envelope_rejects_wrong_tag() {
        let snapshot = Snapshot::new(
            SchemaVersion::new(1),
            ParameterVersion::new(2),
            BlockHeight::new(3),
            TaggedDigest::new(SNAPSHOT_STATE_TAG, [0x22; DIGEST_LENGTH]),
        )
        .unwrap();
        let commitment = Commitment::new(
            SchemaVersion::new(1),
            ParameterVersion::new(2),
            TaggedDigest::new(COMMITMENT_TAG, [0x33; DIGEST_LENGTH]),
        )
        .unwrap();
        let segments = vec![
            ProofSegment::new(
                SchemaVersion::new(1),
                ParameterVersion::new(2),
                SegmentIndex::new(0),
                BlockHeight::new(3),
                BlockHeight::new(4),
                TaggedDigest::new(PROOF_SEGMENT_TAG, [0x44; DIGEST_LENGTH]),
            )
            .unwrap(),
        ];

        let wrong_tag_result = Envelope::new(
            SchemaVersion::new(1),
            ParameterVersion::new(2),
            snapshot,
            segments,
            commitment,
            TaggedDigest::new(COMMITMENT_TAG, [0x55; DIGEST_LENGTH]),
        );
        assert!(matches!(
            wrong_tag_result,
            Err(ValidationError::UnexpectedDomainTag { .. })
        ));
    }
}
