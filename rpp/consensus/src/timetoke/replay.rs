use std::fmt;

use hex;
use rpp_p2p::{
    NetworkPruningCommitment, NetworkPruningEnvelope, NetworkPruningSegment,
    NetworkPruningSnapshot, NetworkTaggedDigestHex,
};
use rpp_pruning::{
    DomainTag, COMMITMENT_TAG, DIGEST_LENGTH, DOMAIN_TAG_LENGTH, ENVELOPE_TAG, PROOF_SEGMENT_TAG,
    SNAPSHOT_STATE_TAG,
};

use super::snapshots::TimetokeSnapshot;

/// Validates incoming snapshots against pruning receipts and locally trusted
/// ledger commitments to defend against replay attempts.
#[derive(Debug, Default)]
pub struct TimetokeReplayValidator;

impl TimetokeReplayValidator {
    /// Verifies that the snapshot and pruning envelope are consistent with the
    /// locally stored commitments. Errors indicate a potential replay or data
    /// integrity issue.
    pub fn validate(
        snapshot: &TimetokeSnapshot,
        pruning: &NetworkPruningEnvelope,
        ledger_timetoke_root: [u8; 32],
        ledger_global_state_root: [u8; 32],
    ) -> Result<(), TimetokeReplayError> {
        let snapshot_root = decode_hex32("snapshot.timetoke_root", &snapshot.timetoke_root)?;
        if snapshot_root != ledger_timetoke_root {
            return Err(TimetokeReplayError::SnapshotRootMismatch {
                expected: hex::encode(ledger_timetoke_root),
                found: snapshot.timetoke_root.clone(),
            });
        }

        let snapshot_state = decode_tagged_digest(
            "pruning.snapshot.state_commitment",
            &pruning.snapshot.state_commitment,
        )?;
        ensure_tag(
            "pruning.snapshot.state_commitment",
            snapshot_state.tag,
            SNAPSHOT_STATE_TAG,
        )?;
        if snapshot_state.digest != ledger_global_state_root {
            return Err(TimetokeReplayError::PruningDigestMismatch {
                field: "pruning.snapshot.state_commitment",
                expected: hex::encode(ledger_global_state_root),
                found: hex::encode(snapshot_state.digest),
            });
        }

        for (index, segment) in pruning.segments.iter().enumerate() {
            let commitment =
                decode_tagged_digest("pruning.segment.commitment", &segment.segment_commitment)?;
            ensure_tag_segment(index, commitment.tag, PROOF_SEGMENT_TAG)?;
        }

        let aggregate = decode_tagged_digest(
            "pruning.commitment.aggregate_commitment",
            &pruning.commitment.aggregate_commitment,
        )?;
        ensure_tag(
            "pruning.commitment.aggregate_commitment",
            aggregate.tag,
            COMMITMENT_TAG,
        )?;

        let binding = decode_tagged_digest("pruning.binding_digest", &pruning.binding_digest)?;
        ensure_tag("pruning.binding_digest", binding.tag, ENVELOPE_TAG)?;

        Ok(())
    }
}

struct TaggedDigestParts {
    tag: DomainTag,
    digest: [u8; DIGEST_LENGTH],
}

fn decode_hex32(field: &'static str, value: &str) -> Result<[u8; 32], TimetokeReplayError> {
    let bytes = hex::decode(value).map_err(|err| TimetokeReplayError::InvalidHex {
        field,
        error: err.to_string(),
    })?;
    if bytes.len() != 32 {
        return Err(TimetokeReplayError::InvalidLength {
            field,
            expected: 32,
            found: bytes.len(),
        });
    }
    let mut output = [0u8; 32];
    output.copy_from_slice(&bytes);
    Ok(output)
}

fn decode_tagged_digest(
    field: &'static str,
    value: &NetworkTaggedDigestHex,
) -> Result<TaggedDigestParts, TimetokeReplayError> {
    let bytes = hex::decode(value.as_str()).map_err(|err| TimetokeReplayError::InvalidHex {
        field,
        error: err.to_string(),
    })?;
    if bytes.len() != DOMAIN_TAG_LENGTH + DIGEST_LENGTH {
        return Err(TimetokeReplayError::InvalidLength {
            field,
            expected: DOMAIN_TAG_LENGTH + DIGEST_LENGTH,
            found: bytes.len(),
        });
    }
    let mut tag_bytes = [0u8; DOMAIN_TAG_LENGTH];
    tag_bytes.copy_from_slice(&bytes[..DOMAIN_TAG_LENGTH]);
    let mut digest = [0u8; DIGEST_LENGTH];
    digest.copy_from_slice(&bytes[DOMAIN_TAG_LENGTH..]);
    Ok(TaggedDigestParts {
        tag: DomainTag::new(tag_bytes),
        digest,
    })
}

fn ensure_tag(
    field: &'static str,
    actual: DomainTag,
    expected: DomainTag,
) -> Result<(), TimetokeReplayError> {
    if actual.as_bytes() != expected.as_bytes() {
        return Err(TimetokeReplayError::DomainTagMismatch {
            field,
            expected: expected.as_bytes(),
            found: actual.as_bytes(),
        });
    }
    Ok(())
}

fn ensure_tag_segment(
    index: usize,
    actual: DomainTag,
    expected: DomainTag,
) -> Result<(), TimetokeReplayError> {
    if actual.as_bytes() != expected.as_bytes() {
        return Err(TimetokeReplayError::SegmentDomainTagMismatch {
            index,
            expected: expected.as_bytes(),
            found: actual.as_bytes(),
        });
    }
    Ok(())
}

/// Errors reported during snapshot replay validation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TimetokeReplayError {
    /// Hex decoding failed for the referenced field.
    InvalidHex { field: &'static str, error: String },
    /// The decoded field length did not match the expected size.
    InvalidLength {
        field: &'static str,
        expected: usize,
        found: usize,
    },
    /// A domain tag differed from the expected pruning schema.
    DomainTagMismatch {
        field: &'static str,
        expected: [u8; DOMAIN_TAG_LENGTH],
        found: [u8; DOMAIN_TAG_LENGTH],
    },
    /// A pruning segment carried an unexpected domain tag.
    SegmentDomainTagMismatch {
        index: usize,
        expected: [u8; DOMAIN_TAG_LENGTH],
        found: [u8; DOMAIN_TAG_LENGTH],
    },
    /// The pruning digest did not match the locally trusted ledger root.
    PruningDigestMismatch {
        field: &'static str,
        expected: String,
        found: String,
    },
    /// The snapshot announced a Timetoke commitment different from the local ledger.
    SnapshotRootMismatch { expected: String, found: String },
}

impl fmt::Display for TimetokeReplayError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TimetokeReplayError::InvalidHex { field, error } => {
                write!(f, "invalid hex for {field}: {error}")
            }
            TimetokeReplayError::InvalidLength {
                field,
                expected,
                found,
            } => {
                write!(
                    f,
                    "invalid length for {field}: expected {expected} bytes, found {found}"
                )
            }
            TimetokeReplayError::DomainTagMismatch {
                field,
                expected,
                found,
            } => {
                write!(
                    f,
                    "domain tag mismatch for {field}: expected {:x?}, found {:x?}",
                    expected, found
                )
            }
            TimetokeReplayError::SegmentDomainTagMismatch {
                index,
                expected,
                found,
            } => {
                write!(
                    f,
                    "segment {index} tag mismatch: expected {:x?}, found {:x?}",
                    expected, found
                )
            }
            TimetokeReplayError::PruningDigestMismatch {
                field,
                expected,
                found,
            } => {
                write!(
                    f,
                    "pruning digest mismatch for {field}: expected {expected}, found {found}"
                )
            }
            TimetokeReplayError::SnapshotRootMismatch { expected, found } => {
                write!(
                    f,
                    "snapshot timetoke root mismatch: expected {expected}, found {found}"
                )
            }
        }
    }
}

impl std::error::Error for TimetokeReplayError {}

// Ensure the unused imports from helper functions remain justified.
#[allow(dead_code)]
fn _assert_pruning_types(
    _snapshot: &NetworkPruningSnapshot,
    _segment: &NetworkPruningSegment,
    _commitment: &NetworkPruningCommitment,
    _digest: &NetworkTaggedDigestHex,
) {
}
