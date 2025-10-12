//! Layer management utilities shared by the binary FRI prover.
//!
//! A [`FriLayer`] owns the evaluations for a specific domain, tracks the
//! associated coset shift and materialises the canonical Merkle commitment
//! over those values.  Leaves are encoded as described in the repository
//! documentation: the prover hashes `len || payload` where `len` is the
//! little-endian `u32` value `8` and `payload` is the eight byte
//! little-endian representation of the evaluation.  Internal nodes hash the
//! concatenation of their two children with the rightmost position padded by
//! [`EMPTY_DIGEST`](crate::hash::merkle::EMPTY_DIGEST) when the layer contains
//! an odd number of leaves.
//!
//! Indices follow the standard binary layout where position `i` at layer `L`
//! maps to parent `i / 2` at layer `L + 1`.  The prover therefore keeps the
//! original index when sampling queries and repeatedly divides it by
//! [`BINARY_FOLD_ARITY`](crate::fri::BINARY_FOLD_ARITY) to travel upwards.
//! Cosets are tracked explicitly: each layer records the shift applied when
//! the evaluations were generated so consumers can reconstruct the exact
//! folding schedule.

use crate::field::FieldElement;
use crate::fri::proof::FriQueryLayerProof;
use crate::fri::types::FriError;
use crate::fri::{field_to_bytes, hash_internal, hash_leaf, BINARY_FOLD_ARITY};
use crate::hash::merkle::{
    compute_root_from_path, encode_leaf, MerkleError, MerkleIndex, MerklePathElement, EMPTY_DIGEST,
};

/// Fully materialised view of a binary Merkle tree.
#[derive(Debug, Clone)]
struct LayerTree {
    levels: Vec<Vec<[u8; 32]>>,
}

impl LayerTree {
    /// Builds a Merkle tree from the provided evaluations using the canonical
    /// hashing helpers.
    fn new(values: &[FieldElement]) -> Result<Self, FriError> {
        let mut levels = Vec::new();
        let mut current: Vec<[u8; 32]> = values
            .iter()
            .map(|value| hash_leaf(value).map_err(FriError::from))
            .collect::<Result<_, _>>()?;
        if current.is_empty() {
            current.push(hash_leaf(&FieldElement::ZERO)?);
        }
        levels.push(current.clone());

        while current.len() > 1 {
            let mut next = Vec::with_capacity(current.len().div_ceil(BINARY_FOLD_ARITY));
            for chunk in current.chunks(BINARY_FOLD_ARITY) {
                let mut children = [[0u8; 32]; BINARY_FOLD_ARITY];
                for (position, slot) in children.iter_mut().enumerate() {
                    *slot = if position < chunk.len() {
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

        Ok(Self { levels })
    }

    /// Returns the Merkle root digest.
    fn root(&self) -> [u8; 32] {
        self.levels
            .last()
            .and_then(|level| level.first().copied())
            .unwrap_or(EMPTY_DIGEST)
    }

    /// Generates the authentication path for the leaf at `index`.
    fn prove(&self, mut index: usize) -> Vec<MerklePathElement> {
        let mut path = Vec::with_capacity(self.levels.len().saturating_sub(1));
        for level in 0..self.levels.len().saturating_sub(1) {
            let nodes = &self.levels[level];
            let parent_index = index / BINARY_FOLD_ARITY;
            let position = index % BINARY_FOLD_ARITY;
            let base = parent_index * BINARY_FOLD_ARITY;
            let sibling = if position == 0 {
                if base + 1 < nodes.len() {
                    nodes[base + 1]
                } else {
                    EMPTY_DIGEST
                }
            } else {
                nodes[base]
            };

            path.push(MerklePathElement {
                index: MerkleIndex(position as u8),
                siblings: [sibling],
            });

            index = parent_index;
        }

        path
    }
}

/// Verifies a query opening against the expected Merkle root.
pub(crate) fn verify_query_opening(
    layer_index: usize,
    opening: &FriQueryLayerProof,
    expected_root: &[u8; 32],
    position: usize,
    domain_size: usize,
) -> Result<(), FriError> {
    let encoded_leaf = encode_leaf(&field_to_bytes(&opening.value)?);
    let computed = compute_root_from_path(&encoded_leaf, position, domain_size, &opening.path)
        .map_err(|reason| FriError::PathInvalid {
            layer: layer_index,
            reason,
        })?;

    if &computed != expected_root {
        return Err(FriError::PathInvalid {
            layer: layer_index,
            reason: MerkleError::ErrMerkleSiblingOrder,
        });
    }

    Ok(())
}

/// Encapsulates the state of a single FRI layer (values, commitment and domain metadata).
#[derive(Debug, Clone)]
pub struct FriLayer {
    index: usize,
    domain_size: usize,
    coset_shift: FieldElement,
    evaluations: Vec<FieldElement>,
    tree: LayerTree,
}

impl FriLayer {
    /// Materialises a new layer by hashing the provided evaluations.
    pub fn new(
        index: usize,
        coset_shift: FieldElement,
        evaluations: Vec<FieldElement>,
    ) -> Result<Self, FriError> {
        let domain_size = evaluations.len();
        let tree = LayerTree::new(&evaluations)?;
        Ok(Self {
            index,
            domain_size,
            coset_shift,
            evaluations,
            tree,
        })
    }

    /// Returns the index of the layer within the folding schedule.
    pub fn index(&self) -> usize {
        self.index
    }

    /// Size of the evaluation domain covered by the layer.
    #[allow(dead_code)]
    pub fn domain_size(&self) -> usize {
        self.domain_size
    }

    /// Coset shift applied to the evaluations stored in the layer.
    pub fn coset_shift(&self) -> FieldElement {
        self.coset_shift
    }

    /// Accessor returning the evaluations committed by the layer.
    pub fn evaluations(&self) -> &[FieldElement] {
        &self.evaluations
    }

    /// Returns the Merkle root associated with the layer.
    pub fn root(&self) -> [u8; 32] {
        self.tree.root()
    }

    /// Opens the layer at `position`, returning the evaluation and its path.
    pub fn open(&self, position: usize) -> Result<FriQueryLayerProof, FriError> {
        if position >= self.domain_size {
            return Err(FriError::QueryOutOfRange { position });
        }

        let value = self.evaluations[position];
        let path = self.tree.prove(position);
        Ok(FriQueryLayerProof { value, path })
    }
}
