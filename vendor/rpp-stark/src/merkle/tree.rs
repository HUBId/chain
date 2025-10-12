use crate::params::{Endianness, FieldKind, MerkleArity, StarkParams};
use serde::{Deserialize, Serialize};
use std::marker::PhantomData;

use super::traits::MerkleHasher;
use super::types::{Digest, Leaf, MerkleArityExt, MerkleError, TreeDepth};

/// Version identifier for [`CommitAux`].
const AUX_VERSION: u16 = 1;

pub(crate) fn field_element_size(field: FieldKind) -> usize {
    match field {
        FieldKind::Goldilocks => 8,
        FieldKind::Bn254 => 32,
    }
}

#[derive(Clone, Debug)]
struct TreeConfig {
    field: FieldKind,
    arity: MerkleArity,
    leaf_width: u8,
    leaf_encoding: Endianness,
    domain_sep: u64,
}

impl TreeConfig {
    fn from_params(params: &StarkParams) -> Result<Self, MerkleError> {
        if params.merkle().leaf_encoding != Endianness::Little {
            return Err(MerkleError::IncompatibleParams {
                reason: "merkle leaf encoding must be little-endian",
            });
        }
        Ok(Self {
            field: params.field(),
            arity: params.merkle().arity,
            leaf_width: params.merkle().leaf_width,
            leaf_encoding: params.merkle().leaf_encoding,
            domain_sep: params.merkle().domain_sep,
        })
    }

    fn expected_leaf_bytes(&self) -> usize {
        field_element_size(self.field) * self.leaf_width as usize
    }
}

/// Auxiliary commitment data that allows generating openings without
/// rebuilding the full tree.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommitAux {
    pub version: u16,
    pub arity: MerkleArity,
    pub leaf_width: u8,
    pub leaf_encoding: Endianness,
    pub domain_sep: u64,
    pub digest_size: u16,
    pub leaf_count: u32,
    pub depth: TreeDepth,
    pub levels: Vec<Vec<Digest>>,
}

impl CommitAux {
    fn ensure_compatible(&self, params: &StarkParams) -> Result<(), MerkleError> {
        let merkle = params.merkle();
        if self.arity != merkle.arity {
            return Err(MerkleError::ArityMismatch);
        }
        if self.leaf_encoding != merkle.leaf_encoding {
            return Err(MerkleError::IncompatibleParams {
                reason: "leaf encoding mismatch",
            });
        }
        if self.leaf_width != merkle.leaf_width {
            return Err(MerkleError::LeafWidthMismatch {
                expected: merkle.leaf_width,
                got: self.leaf_width,
            });
        }
        if self.domain_sep != merkle.domain_sep {
            return Err(MerkleError::IncompatibleParams {
                reason: "domain separation mismatch",
            });
        }
        Ok(())
    }
}

impl<H: MerkleHasher> super::traits::MerkleCommit for MerkleTree<H> {
    type Hasher = H;

    fn commit<I>(
        params: &StarkParams,
        leaves: I,
    ) -> Result<(super::types::Digest, CommitAux), MerkleError>
    where
        I: ExactSizeIterator<Item = Leaf>,
    {
        let mut tree = MerkleTree::<H>::new(params)?;
        let root = tree.commit(leaves)?;
        Ok((root, tree.into_aux()))
    }

    fn open(
        params: &StarkParams,
        aux: &CommitAux,
        indices: &[u32],
    ) -> Result<super::proof::MerkleProof, MerkleError> {
        let builder = super::proof::ProofBuilder::new(aux);
        builder.open(params, indices)
    }

    fn verify(
        params: &StarkParams,
        root: &super::types::Digest,
        proof: &super::proof::MerkleProof,
        leaves: &[Leaf],
    ) -> Result<(), MerkleError> {
        super::proof::verify_proof::<H>(params, root, proof, leaves)
    }
}

/// Merkle tree builder storing the hashed levels for subsequent openings.
pub struct MerkleTree<H: MerkleHasher> {
    config: TreeConfig,
    levels: Option<Vec<Vec<H::Digest>>>,
    leaf_count: usize,
    marker: PhantomData<H>,
}

impl<H: MerkleHasher> MerkleTree<H> {
    /// Creates a new tree using the parameters.
    pub fn new(params: &StarkParams) -> Result<Self, MerkleError> {
        let config = TreeConfig::from_params(params)?;
        if H::hash_family() != params.hash().family() {
            return Err(MerkleError::IncompatibleParams {
                reason: "hash family mismatch",
            });
        }
        Ok(Self {
            config,
            levels: None,
            leaf_count: 0,
            marker: PhantomData,
        })
    }

    /// Commits to a set of leaves and returns the root digest.
    pub fn commit<I>(&mut self, leaves: I) -> Result<Digest, MerkleError>
    where
        I: ExactSizeIterator<Item = Leaf>,
    {
        let expected = self.config.expected_leaf_bytes();
        let leaves_vec: Vec<Leaf> = leaves.collect();
        if leaves_vec.is_empty() {
            return Err(MerkleError::EmptyLeaves);
        }

        for leaf in &leaves_vec {
            if leaf.as_bytes().len() != expected {
                let got = (leaf.as_bytes().len() / field_element_size(self.config.field)) as u8;
                return Err(MerkleError::LeafWidthMismatch {
                    expected: self.config.leaf_width,
                    got,
                });
            }
        }

        let leaf_count = leaves_vec.len();
        #[cfg(feature = "parallel")]
        let hashed: Vec<H::Digest> = if crate::utils::parallelism_enabled() {
            use rayon::prelude::*;
            let chunk = crate::utils::preferred_chunk_size(leaf_count.max(1));
            leaves_vec
                .par_iter()
                .with_min_len(chunk)
                .with_max_len(chunk)
                .map(|leaf| H::hash_leaves(self.config.domain_sep, leaf.as_bytes()))
                .collect()
        } else {
            leaves_vec
                .iter()
                .map(|leaf| H::hash_leaves(self.config.domain_sep, leaf.as_bytes()))
                .collect()
        };
        #[cfg(not(feature = "parallel"))]
        let hashed: Vec<H::Digest> = leaves_vec
            .iter()
            .map(|leaf| H::hash_leaves(self.config.domain_sep, leaf.as_bytes()))
            .collect();

        let mut levels = Vec::new();
        levels.push(hashed.clone());

        let arity = self.config.arity.as_usize();
        let mut current = hashed;

        while current.len() > 1 {
            let next_len = current.len().div_ceil(arity);
            #[cfg(feature = "parallel")]
            let next: Vec<H::Digest> = if crate::utils::parallelism_enabled() {
                use rayon::prelude::*;
                let chunk = crate::utils::preferred_chunk_size(next_len.max(1));
                (0..next_len)
                    .into_par_iter()
                    .with_min_len(chunk)
                    .with_max_len(chunk)
                    .map(|index| {
                        let start = index * arity;
                        let end = (start + arity).min(current.len());
                        let mut children: Vec<H::Digest> = current[start..end].to_vec();
                        assert!(!children.is_empty(), "missing child when padding level");
                        let last = *children
                            .last()
                            .expect("padded branch must have at least one child");
                        while children.len() < arity {
                            children.push(last);
                        }
                        H::hash_nodes(self.config.domain_sep, &children)
                    })
                    .collect()
            } else {
                (0..next_len)
                    .map(|index| {
                        let start = index * arity;
                        let end = (start + arity).min(current.len());
                        let mut children: Vec<H::Digest> = current[start..end].to_vec();
                        assert!(!children.is_empty(), "missing child when padding level");
                        let last = *children
                            .last()
                            .expect("padded branch must have at least one child");
                        while children.len() < arity {
                            children.push(last);
                        }
                        H::hash_nodes(self.config.domain_sep, &children)
                    })
                    .collect()
            };
            #[cfg(not(feature = "parallel"))]
            let next: Vec<H::Digest> = (0..next_len)
                .map(|index| {
                    let start = index * arity;
                    let end = (start + arity).min(current.len());
                    let mut children: Vec<H::Digest> = current[start..end].to_vec();
                    assert!(!children.is_empty(), "missing child when padding level");
                    let last = *children
                        .last()
                        .expect("padded branch must have at least one child");
                    while children.len() < arity {
                        children.push(last);
                    }
                    H::hash_nodes(self.config.domain_sep, &children)
                })
                .collect();
            levels.push(next.clone());
            current = next;
        }

        let root = current
            .first()
            .copied()
            .ok_or(MerkleError::InvalidTreeState {
                reason: "missing root after commitment",
            })?;
        self.leaf_count = leaf_count;
        self.levels = Some(levels);

        Ok(convert_digest::<H>(root))
    }

    /// Returns the root digest from the last commitment.
    pub fn root(&self) -> Option<Digest> {
        let levels = self.levels.as_ref()?;
        let last = levels.last()?;
        last.first().copied().map(convert_digest::<H>)
    }

    /// Consumes the tree and returns the auxiliary information required for openings.
    pub fn into_aux(self) -> CommitAux {
        let digest_size = H::digest_size();
        let levels: Vec<Vec<Digest>> = self
            .levels
            .unwrap_or_default()
            .into_iter()
            .map(|level| level.into_iter().map(convert_digest::<H>).collect())
            .collect();
        CommitAux {
            version: AUX_VERSION,
            arity: self.config.arity,
            leaf_width: self.config.leaf_width,
            leaf_encoding: self.config.leaf_encoding,
            domain_sep: self.config.domain_sep,
            digest_size: digest_size as u16,
            leaf_count: self.leaf_count as u32,
            depth: TreeDepth(levels.len() as u32),
            levels,
        }
    }
}

fn convert_digest<H: MerkleHasher>(digest: H::Digest) -> Digest {
    Digest::new(digest.as_ref().to_vec())
}

impl CommitAux {
    pub(crate) fn level(&self, depth: usize) -> Option<&[Digest]> {
        self.levels.get(depth).map(|level| level.as_slice())
    }

    pub(crate) fn ensure_openable(
        &self,
        params: &StarkParams,
        expected_version: u16,
    ) -> Result<(), MerkleError> {
        if self.version != expected_version {
            return Err(MerkleError::ProofVersionMismatch {
                expected: expected_version,
                got: self.version,
            });
        }
        self.ensure_compatible(params)
    }

    pub(crate) fn height(&self) -> usize {
        self.levels.len()
    }

    pub(crate) fn digest_size(&self) -> usize {
        self.digest_size as usize
    }

    pub(crate) fn leaves(&self) -> usize {
        self.leaf_count as usize
    }

    pub(crate) fn domain_sep(&self) -> u64 {
        self.domain_sep
    }

    pub(crate) fn arity(&self) -> MerkleArity {
        self.arity
    }
}
