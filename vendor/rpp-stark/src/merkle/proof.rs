use crate::params::{Endianness, MerkleArity, StarkParams};

use super::traits::MerkleHasher;
use super::tree::CommitAux;
use super::types::{Digest, Leaf, MerkleArityExt, MerkleError, ProofNode};

use crate::proof::types::PROOF_VERSION;

/// Canonical Merkle opening containing a batch of indices.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct MerkleProof {
    pub version: u16,
    pub arity: MerkleArity,
    pub leaf_encoding: Endianness,
    pub path: Vec<ProofNode>,
    pub indices: Vec<u32>,
    pub leaf_width: u8,
    pub domain_sep: u64,
    pub leaf_width_bytes: u32,
    pub digest_size: u16,
}

impl MerkleProof {
    pub fn path(&self) -> &[ProofNode] {
        &self.path
    }
}

/// Deterministic builder for Merkle openings.
pub struct ProofBuilder<'a> {
    aux: &'a CommitAux,
}

impl<'a> ProofBuilder<'a> {
    pub fn new(aux: &'a CommitAux) -> Self {
        Self { aux }
    }

    pub fn open(&self, params: &StarkParams, indices: &[u32]) -> Result<MerkleProof, MerkleError> {
        self.aux.ensure_openable(params, PROOF_VERSION)?;
        if indices.is_empty() {
            return Err(MerkleError::InvalidPathLength);
        }
        let mut sorted = indices.to_vec();
        sorted.sort_unstable();
        for window in sorted.windows(2) {
            if window[0] == window[1] {
                return Err(MerkleError::DuplicateIndex { index: window[1] });
            }
        }
        let leaves = self.aux.leaves();
        for &index in &sorted {
            if index as usize >= leaves {
                return Err(MerkleError::IndexOutOfRange {
                    index,
                    max: leaves.saturating_sub(1) as u32,
                });
            }
        }

        let arity = self.aux.arity().as_usize();
        let mut current = sorted.clone();
        let mut path = Vec::new();

        for depth in 0..self.aux.height().saturating_sub(1) {
            let level = self.aux.level(depth).unwrap_or(&[]);
            let mut next = Vec::new();
            let mut i = 0;
            while i < current.len() {
                let index = current[i];
                let parent = index / arity as u32;
                let mut group_end = i + 1;
                while group_end < current.len() && current[group_end] / arity as u32 == parent {
                    group_end += 1;
                }
                let mut present = vec![false; arity];
                for child in &current[i..group_end] {
                    present[(child % arity as u32) as usize] = true;
                }
                let missing: Vec<usize> = (0..arity).filter(|pos| !present[*pos]).collect();
                if !missing.is_empty() {
                    let mut node = new_proof_node(self.aux.arity(), self.aux.digest_size());
                    for (slot, position) in missing.iter().enumerate() {
                        let absolute = parent as usize * arity + position;
                        let digest = if absolute < level.len() {
                            level[absolute].clone()
                        } else {
                            level
                                .last()
                                .cloned()
                                .unwrap_or_else(|| Digest::zero(self.aux.digest_size()))
                        };
                        node.siblings_mut()[slot] = digest;
                    }
                    path.push(node);
                }
                next.push(parent);
                i = group_end;
            }
            current = next;
        }

        Ok(MerkleProof {
            version: PROOF_VERSION,
            arity: self.aux.arity(),
            leaf_encoding: self.aux.leaf_encoding,
            path,
            indices: sorted,
            leaf_width: self.aux.leaf_width,
            domain_sep: self.aux.domain_sep(),
            leaf_width_bytes: (self.aux.leaf_width as u32)
                * super::tree::field_element_size(params.field()) as u32,
            digest_size: self.aux.digest_size() as u16,
        })
    }
}

fn new_proof_node(arity: MerkleArity, digest_size: usize) -> ProofNode {
    match arity {
        MerkleArity::Binary => {
            ProofNode::Arity2(core::array::from_fn(|_| Digest::zero(digest_size)))
        }
        MerkleArity::Quaternary => {
            ProofNode::Arity4(core::array::from_fn(|_| Digest::zero(digest_size)))
        }
    }
}

fn ensure_indices_sorted(indices: &[u32]) -> Result<(), MerkleError> {
    for window in indices.windows(2) {
        if window[0] >= window[1] {
            return Err(MerkleError::DuplicateIndex { index: window[1] });
        }
    }
    Ok(())
}

pub fn verify_proof<H: MerkleHasher>(
    params: &StarkParams,
    root: &Digest,
    proof: &MerkleProof,
    leaves: &[Leaf],
) -> Result<(), MerkleError> {
    if proof.version != PROOF_VERSION {
        return Err(MerkleError::ProofVersionMismatch {
            expected: PROOF_VERSION,
            got: proof.version,
        });
    }
    if proof.arity != params.merkle().arity {
        return Err(MerkleError::ArityMismatch);
    }
    if proof.leaf_encoding != params.merkle().leaf_encoding {
        return Err(MerkleError::IncompatibleParams {
            reason: "leaf encoding mismatch",
        });
    }
    if proof.leaf_width != params.merkle().leaf_width {
        return Err(MerkleError::LeafWidthMismatch {
            expected: params.merkle().leaf_width,
            got: proof.leaf_width,
        });
    }
    if proof.domain_sep != params.merkle().domain_sep {
        return Err(MerkleError::IncompatibleParams {
            reason: "domain separation mismatch",
        });
    }
    if proof.indices.len() != leaves.len() {
        return Err(MerkleError::InvalidPathLength);
    }
    if proof.digest_size as usize != H::digest_size() {
        return Err(MerkleError::IncompatibleParams {
            reason: "digest size mismatch",
        });
    }
    ensure_indices_sorted(&proof.indices)?;

    let element_size = super::tree::field_element_size(params.field());
    let expected = element_size * proof.leaf_width as usize;
    let mut current: Vec<(u32, H::Digest)> = Vec::with_capacity(leaves.len());
    for (&index, leaf) in proof.indices.iter().zip(leaves.iter()) {
        if leaf.as_bytes().len() != expected {
            let got = (leaf.as_bytes().len() / element_size) as u8;
            return Err(MerkleError::LeafWidthMismatch {
                expected: proof.leaf_width,
                got,
            });
        }
        let digest = H::hash_leaves(proof.domain_sep, leaf.as_bytes());
        current.push((index, digest));
    }

    if current.is_empty() {
        return Err(MerkleError::InvalidPathLength);
    }

    let mut path_iter = proof.path.iter();
    let arity = proof.arity.as_usize() as u32;

    while !(current.len() == 1 && path_iter.clone().next().is_none()) {
        if current.is_empty() {
            return Err(MerkleError::InvalidPathLength);
        }
        let mut next = Vec::new();
        let mut i = 0;
        while i < current.len() {
            let (index, _) = current[i];
            let parent = index / arity;
            let mut group_end = i + 1;
            while group_end < current.len() && current[group_end].0 / arity == parent {
                group_end += 1;
            }
            let mut children: Vec<Option<H::Digest>> = vec![None; arity as usize];
            for &(child_index, digest) in &current[i..group_end] {
                let position = (child_index % arity) as usize;
                children[position] = Some(digest);
            }
            let missing = children.iter().filter(|child| child.is_none()).count();
            if missing > 0 {
                let node = path_iter.next().ok_or(MerkleError::InvalidPathLength)?;
                let siblings = node.siblings();
                if siblings.len() != (arity as usize - 1) {
                    return Err(MerkleError::InvalidPathLength);
                }
                let mut sibling_iter = siblings.iter();
                for child in children.iter_mut() {
                    if child.is_none() {
                        if let Some(raw) = sibling_iter.next() {
                            let digest = H::from_bytes(raw.as_bytes())
                                .ok_or(MerkleError::VerificationFailed)?;
                            *child = Some(digest);
                        }
                    }
                }
                for raw in sibling_iter {
                    if raw.as_bytes().iter().any(|byte| *byte != 0) {
                        return Err(MerkleError::InvalidPathLength);
                    }
                }
            }

            let mut ordered = Vec::with_capacity(arity as usize);
            for child in children {
                let digest = child.ok_or(MerkleError::VerificationFailed)?;
                ordered.push(digest);
            }
            let parent_digest = H::hash_nodes(proof.domain_sep, &ordered);
            next.push((parent, parent_digest));
            i = group_end;
        }
        next.sort_by_key(|entry| entry.0);
        current = next;
    }

    let computed = current.first().ok_or(MerkleError::InvalidPathLength)?;
    let root_digest = H::from_bytes(root.as_bytes()).ok_or(MerkleError::VerificationFailed)?;
    if computed.1.as_ref() == root_digest.as_ref() {
        Ok(())
    } else {
        Err(MerkleError::VerificationFailed)
    }
}
