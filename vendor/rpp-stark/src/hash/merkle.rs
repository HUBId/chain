//! Blake2s-based binary Merkle tree implementation used by the proving system.
//!
//! The tree adheres to the specification circulated with the repository:
//!
//! * Inner nodes hash the concatenation of their two children in order.
//! * Leaves are hashed as `Blake2s(u32_le(len) || payload)`.
//! * Missing children on the right-hand side are padded with a fixed
//!   `EMPTY` digest derived from the string `"RPP-MERKLE-EMPTY\0"`.
//! * Authentication paths serialise an index byte followed by the sibling
//!   digest ordered by its position (0 or 1) within the parent.
//!
//! The module provides helpers to build Merkle trees, derive authentication
//! paths and recompute the root from a path.  Errors are surfaced when a
//! caller attempts to verify malformed paths (e.g. mismatched padding or
//! tampered length prefixes).

use crate::hash::{hash, Hasher};
use core::fmt;

/// Number of children per internal node.
const ARITY: usize = 2;

/// Size of a digest emitted by the tree (Blake2s output size).
pub const DIGEST_SIZE: usize = 32;

/// Canonical digest for an empty child.
pub const EMPTY_DIGEST: [u8; DIGEST_SIZE] = [
    0xe6, 0x81, 0x37, 0x62, 0x79, 0xe1, 0xdf, 0xc4, 0x11, 0xcb, 0xc0, 0xa2, 0x3e, 0xd1, 0xfe, 0x32,
    0xfe, 0xf7, 0x80, 0x87, 0x03, 0x14, 0x9f, 0x30, 0x1a, 0xdf, 0x3a, 0xb3, 0xbb, 0xec, 0x73, 0x34,
];

/// Digest binding the documented Merkle layout for parameter commitments.
pub const MERKLE_SCHEME_ID: [u8; DIGEST_SIZE] = [
    0xa0, 0x02, 0xd1, 0xc1, 0x58, 0xcd, 0x9b, 0x91, 0x2d, 0x51, 0x38, 0x67, 0x50, 0x7b, 0xcd, 0x19,
    0x5a, 0xe8, 0x15, 0xfa, 0x16, 0xdb, 0x7b, 0x3a, 0xc2, 0x5f, 0xae, 0x6f, 0x6b, 0xd9, 0x13, 0xa4,
];

/// Index of a child within a binary node (stored as little-endian byte in proofs).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MerkleIndex(pub u8);

impl MerkleIndex {
    /// Maximum allowed index for the binary fan-out.
    pub const MAX: u8 = 1;
}

/// Path element capturing siblings and the caller position.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MerklePathElement {
    /// Position of the caller node within the parent (`0..=1`).
    pub index: MerkleIndex,
    /// Sibling hash ordered from left (0) to right (1).
    pub siblings: [[u8; DIGEST_SIZE]; ARITY - 1],
}

/// Errors reported while verifying or constructing Merkle proofs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MerkleError {
    /// The u32 little-endian length prefix disagrees with the payload size.
    ErrMerkleLeafLength,
    /// Missing leaves on the right-hand side were not padded with `EMPTY`.
    ErrMerkleEmptyPadding,
    /// Sibling order within a Merkle proof was inconsistent with the specification.
    ErrMerkleSiblingOrder,
    /// Encountered an invalid index byte or inconsistent path structure.
    ErrPathIndexByte,
}

impl fmt::Display for MerkleError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MerkleError::ErrMerkleLeafLength => write!(f, "ErrFRIPathInvalid: leaf length"),
            MerkleError::ErrMerkleEmptyPadding => write!(f, "ErrFRIPathInvalid: right padding"),
            MerkleError::ErrMerkleSiblingOrder => write!(f, "ErrFRIPathInvalid: sibling order"),
            MerkleError::ErrPathIndexByte => write!(f, "ErrFRIPathInvalid: index byte"),
        }
    }
}

impl std::error::Error for MerkleError {}

/// Convenience wrapper for a binary Blake2s Merkle tree.
#[derive(Debug, Clone)]
pub struct Blake3MerkleTree {
    levels: Vec<Vec<[u8; DIGEST_SIZE]>>,
    leaf_count: usize,
}

impl Blake3MerkleTree {
    /// Builds a Merkle tree from canonical leaf encodings.
    ///
    /// Each leaf must follow the framing `len: u32 (little-endian) || payload`.
    pub fn from_leaves<I, B>(leaves: I) -> Result<Self, MerkleError>
    where
        I: IntoIterator<Item = B>,
        B: AsRef<[u8]>,
    {
        let mut hashed = Vec::new();
        let mut leaf_count = 0usize;
        for leaf in leaves {
            let leaf_bytes = leaf.as_ref();
            hashed.push(hash_leaf(leaf_bytes)?);
            leaf_count += 1;
        }

        if leaf_count == 0 {
            return Ok(Self {
                levels: vec![vec![EMPTY_DIGEST]],
                leaf_count: 0,
            });
        }

        let mut levels = Vec::new();
        levels.push(hashed.clone());
        let mut current = hashed;

        while current.len() > 1 {
            let mut next = Vec::with_capacity(current.len().div_ceil(ARITY));
            for chunk in current.chunks(ARITY) {
                let mut children = [[0u8; DIGEST_SIZE]; ARITY];
                for (position, child) in children.iter_mut().enumerate() {
                    *child = if position < chunk.len() {
                        chunk[position]
                    } else {
                        EMPTY_DIGEST
                    };
                }
                next.push(hash_internal(&children));
            }
            levels.push(next.clone());
            current = next;
        }

        Ok(Self { levels, leaf_count })
    }

    /// Returns the Merkle root digest.
    pub fn root(&self) -> [u8; DIGEST_SIZE] {
        self.levels
            .last()
            .and_then(|level| level.first().copied())
            .unwrap_or(EMPTY_DIGEST)
    }

    /// Number of leaves provided when building the tree (after implicit padding).
    pub fn leaf_count(&self) -> usize {
        self.leaf_count
    }

    /// Generates an authentication path for the leaf at `index`.
    pub fn open(&self, index: usize) -> Result<Vec<MerklePathElement>, MerkleError> {
        if index >= self.leaf_count {
            return Err(MerkleError::ErrPathIndexByte);
        }

        let mut path = Vec::with_capacity(self.levels.len().saturating_sub(1));
        let mut current_index = index;

        for level in 0..self.levels.len().saturating_sub(1) {
            let nodes = &self.levels[level];
            let parent_index = current_index / ARITY;
            let position = current_index % ARITY;
            let chunk_base = parent_index * ARITY;
            let chunk_len = nodes.len().saturating_sub(chunk_base).min(ARITY);

            let sibling = if position == 0 {
                if chunk_len > 1 {
                    nodes[chunk_base + 1]
                } else {
                    EMPTY_DIGEST
                }
            } else if chunk_len > 1 {
                nodes[chunk_base]
            } else {
                EMPTY_DIGEST
            };

            path.push(MerklePathElement {
                index: MerkleIndex(position as u8),
                siblings: [sibling],
            });

            current_index /= ARITY;
        }

        Ok(path)
    }
}

/// Encodes raw payload bytes into the canonical leaf representation.
pub fn encode_leaf(payload: &[u8]) -> Vec<u8> {
    let mut encoded = Vec::with_capacity(4 + payload.len());
    encoded.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    encoded.extend_from_slice(payload);
    encoded
}

/// Hashes a leaf using the canonical framing rules while checking the length prefix.
pub fn hash_leaf(encoded_leaf: &[u8]) -> Result<[u8; DIGEST_SIZE], MerkleError> {
    if encoded_leaf.len() < 4 {
        return Err(MerkleError::ErrMerkleLeafLength);
    }

    let mut len_bytes = [0u8; 4];
    len_bytes.copy_from_slice(&encoded_leaf[..4]);
    let declared_len = u32::from_le_bytes(len_bytes) as usize;
    let payload = &encoded_leaf[4..];

    if declared_len != payload.len() {
        return Err(MerkleError::ErrMerkleLeafLength);
    }

    Ok(hash(encoded_leaf).into())
}

/// Hashes two child digests into their parent digest.
pub fn hash_internal(children: &[[u8; DIGEST_SIZE]; ARITY]) -> [u8; DIGEST_SIZE] {
    let mut hasher = Hasher::new();
    for child in children {
        hasher.update(child);
    }
    hasher.finalize().into()
}

/// Recomputes the Merkle root from a leaf and its authentication path.
///
/// * `leaf`: canonical encoding `len || payload`.
/// * `index`: position of the leaf within the tree (0-based).
/// * `leaf_count`: total number of leaves committed by the tree.
/// * `path`: authentication path (leaf to root order).
pub fn compute_root_from_path(
    leaf: &[u8],
    index: usize,
    leaf_count: usize,
    path: &[MerklePathElement],
) -> Result<[u8; DIGEST_SIZE], MerkleError> {
    if leaf_count == 0 || index >= leaf_count {
        return Err(MerkleError::ErrPathIndexByte);
    }

    let mut hash = hash_leaf(leaf)?;
    let mut current_index = index;
    let mut nodes_in_level = leaf_count;

    for element in path {
        if element.index.0 > MerkleIndex::MAX {
            return Err(MerkleError::ErrPathIndexByte);
        }
        let expected_position = current_index % ARITY;
        if element.index.0 as usize != expected_position {
            return Err(MerkleError::ErrPathIndexByte);
        }

        let parent_index = current_index / ARITY;
        let chunk_base = parent_index * ARITY;
        let chunk_len = nodes_in_level.saturating_sub(chunk_base).min(ARITY);

        let mut children = [[0u8; DIGEST_SIZE]; ARITY];
        children[expected_position] = hash;
        let sibling = element
            .siblings
            .first()
            .copied()
            .ok_or(MerkleError::ErrPathIndexByte)?;
        let sibling_position = expected_position ^ 1;
        if sibling_position >= chunk_len && sibling != EMPTY_DIGEST {
            return Err(MerkleError::ErrMerkleEmptyPadding);
        }
        children[sibling_position] = if sibling_position < chunk_len {
            sibling
        } else {
            EMPTY_DIGEST
        };

        hash = hash_internal(&children);
        current_index = parent_index;
        nodes_in_level = nodes_in_level.div_ceil(ARITY);
    }

    if current_index != 0 {
        return Err(MerkleError::ErrPathIndexByte);
    }

    Ok(hash)
}

/// Verifies a Merkle path against an expected root digest.
pub fn verify_path(
    leaf: &[u8],
    index: usize,
    leaf_count: usize,
    path: &[MerklePathElement],
    expected_root: &[u8; DIGEST_SIZE],
) -> Result<(), MerkleError> {
    let computed = compute_root_from_path(leaf, index, leaf_count, path)?;
    if &computed != expected_root {
        return Err(MerkleError::ErrMerkleSiblingOrder);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_digest_matches_reference() {
        assert_eq!(EMPTY_DIGEST, hash(b"RPP-MERKLE-EMPTY\0").into_bytes());
    }

    #[test]
    fn empty_tree_root_is_empty() -> Result<(), MerkleError> {
        let leaves: Vec<Vec<u8>> = Vec::new();
        let tree = Blake3MerkleTree::from_leaves(leaves)?;
        assert_eq!(tree.leaf_count(), 0);
        assert_eq!(tree.root(), EMPTY_DIGEST);
        Ok(())
    }

    #[test]
    fn build_path_verify_roundtrip_ok() -> Result<(), MerkleError> {
        let payloads = [
            encode_leaf(&[1, 2, 3]),
            encode_leaf(&[4, 5, 6, 7]),
            encode_leaf(&[]),
            encode_leaf(&[9; 12]),
            encode_leaf(b"final"),
        ];

        let tree = Blake3MerkleTree::from_leaves(payloads.iter())?;
        let root = tree.root();

        for (index, leaf) in payloads.iter().enumerate() {
            let path = tree.open(index)?;
            verify_path(leaf, index, tree.leaf_count(), &path, &root)?;
        }
        Ok(())
    }

    #[test]
    fn verify_fails_on_wrong_sibling_order() -> Result<(), MerkleError> {
        let payloads = [
            encode_leaf(&[1, 2, 3, 4]),
            encode_leaf(&[5, 6, 7, 8]),
            encode_leaf(&[9, 10, 11, 12]),
            encode_leaf(&[13, 14, 15, 16]),
        ];

        let tree = Blake3MerkleTree::from_leaves(payloads.iter())?;
        let mut path = tree.open(2)?;
        // Corrupt the sibling digest to break the order constraint.
        path[0].siblings[0][0] ^= 0x01;
        let err = verify_path(&payloads[2], 2, tree.leaf_count(), &path, &tree.root()).unwrap_err();
        assert_eq!(err, MerkleError::ErrMerkleSiblingOrder);
        assert_eq!(err.to_string(), "ErrFRIPathInvalid: sibling order");
        Ok(())
    }

    #[test]
    fn verify_fails_on_bad_index_byte() -> Result<(), MerkleError> {
        let payloads = [encode_leaf(&[42]), encode_leaf(&[43])];
        let tree = Blake3MerkleTree::from_leaves(payloads.iter())?;
        let mut path = tree.open(0)?;
        path[0].index = MerkleIndex(2);
        let err = verify_path(&payloads[0], 0, tree.leaf_count(), &path, &tree.root()).unwrap_err();
        assert_eq!(err, MerkleError::ErrPathIndexByte);
        assert_eq!(err.to_string(), "ErrFRIPathInvalid: index byte");
        Ok(())
    }

    #[test]
    fn verify_fails_on_leaf_len_mismatch() {
        let mut leaf = encode_leaf(&[1, 2, 3]);
        leaf[0] ^= 0x01; // corrupt the length prefix
        let path = Vec::new();
        let err = compute_root_from_path(&leaf, 0, 1, &path).unwrap_err();
        assert_eq!(err, MerkleError::ErrMerkleLeafLength);
        assert_eq!(err.to_string(), "ErrFRIPathInvalid: leaf length");
    }

    #[test]
    fn verify_fails_on_bad_padding() {
        let leaf = encode_leaf(&[42]);
        let path = [MerklePathElement {
            index: MerkleIndex(0),
            siblings: [[0xFF; DIGEST_SIZE]],
        }];
        let err = compute_root_from_path(&leaf, 0, 1, &path).unwrap_err();
        assert_eq!(err, MerkleError::ErrMerkleEmptyPadding);
        assert_eq!(err.to_string(), "ErrFRIPathInvalid: right padding");
    }

    #[test]
    fn right_padding_with_empty_constant_ok() -> Result<(), MerkleError> {
        assert_eq!(EMPTY_DIGEST, hash(b"RPP-MERKLE-EMPTY\0").into_bytes());
        let payloads = [
            encode_leaf(&[1]),
            encode_leaf(&[2]),
            encode_leaf(&[3]),
            encode_leaf(&[4]),
            encode_leaf(&[5]),
        ];
        let tree = Blake3MerkleTree::from_leaves(payloads.iter())?;
        let index = payloads.len() - 1;
        let path = tree.open(index)?;
        assert!(path.iter().any(|element| element
            .siblings
            .iter()
            .any(|sibling| sibling == &EMPTY_DIGEST)));
        verify_path(
            &payloads[index],
            index,
            tree.leaf_count(),
            &path,
            &tree.root(),
        )?;
        Ok(())
    }
}
