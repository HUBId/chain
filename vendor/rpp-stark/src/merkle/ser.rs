use super::proof::MerkleProof;
use super::tree::CommitAux;
use super::types::{Digest, MerkleError, ProofNode, SerKind};
use crate::params::{Endianness, MerkleArity};

fn encode_endianness(value: Endianness) -> u8 {
    match value {
        Endianness::Little => 1,
        Endianness::Big => 2,
    }
}

fn decode_endianness(code: u8) -> Option<Endianness> {
    match code {
        1 => Some(Endianness::Little),
        2 => Some(Endianness::Big),
        _ => None,
    }
}

fn encode_arity(arity: MerkleArity) -> u8 {
    match arity {
        MerkleArity::Binary => 2,
        MerkleArity::Quaternary => 4,
    }
}

fn decode_arity(code: u8) -> Option<MerkleArity> {
    match code {
        2 => Some(MerkleArity::Binary),
        4 => Some(MerkleArity::Quaternary),
        _ => None,
    }
}

/// Serialises a [`MerkleProof`] into the canonical byte layout.
pub fn encode_proof(proof: &MerkleProof) -> Result<Vec<u8>, MerkleError> {
    let mut out = Vec::new();
    out.extend_from_slice(&proof.version.to_le_bytes());
    out.push(encode_arity(proof.arity));
    out.push(encode_endianness(proof.leaf_encoding));
    out.push(proof.leaf_width);
    out.extend_from_slice(&proof.domain_sep.to_le_bytes());
    out.extend_from_slice(&proof.leaf_width_bytes.to_le_bytes());
    out.extend_from_slice(&proof.digest_size.to_le_bytes());
    out.extend_from_slice(&(proof.indices.len() as u32).to_le_bytes());
    for &index in &proof.indices {
        out.extend_from_slice(&index.to_le_bytes());
    }
    out.extend_from_slice(&(proof.path.len() as u32).to_le_bytes());
    for node in &proof.path {
        match node {
            ProofNode::Arity2(digests) => {
                out.push(2);
                out.push(digests.len() as u8);
                for digest in digests {
                    if digest.as_bytes().len() != proof.digest_size as usize {
                        return Err(MerkleError::Serialization(SerKind::Proof));
                    }
                    out.extend_from_slice(digest.as_bytes());
                }
            }
            ProofNode::Arity4(digests) => {
                out.push(4);
                out.push(digests.len() as u8);
                for digest in digests {
                    if digest.as_bytes().len() != proof.digest_size as usize {
                        return Err(MerkleError::Serialization(SerKind::Proof));
                    }
                    out.extend_from_slice(digest.as_bytes());
                }
            }
        }
    }
    Ok(out)
}

/// Deserialises a [`MerkleProof`] from its canonical byte representation.
pub fn decode_proof(bytes: &[u8]) -> Result<MerkleProof, MerkleError> {
    let mut cursor = 0usize;
    let mut take = |len: usize| -> Result<&[u8], MerkleError> {
        if cursor + len > bytes.len() {
            return Err(MerkleError::Serialization(SerKind::Proof));
        }
        let slice = &bytes[cursor..cursor + len];
        cursor += len;
        Ok(slice)
    };

    let mut version_bytes = [0u8; 2];
    version_bytes.copy_from_slice(take(2)?);
    let version = u16::from_le_bytes(version_bytes);
    let arity = decode_arity(take(1)?[0]).ok_or(MerkleError::Serialization(SerKind::Proof))?;
    let leaf_encoding =
        decode_endianness(take(1)?[0]).ok_or(MerkleError::Serialization(SerKind::Proof))?;
    let leaf_width = take(1)?[0];
    let mut domain_sep_bytes = [0u8; 8];
    domain_sep_bytes.copy_from_slice(take(8)?);
    let domain_sep = u64::from_le_bytes(domain_sep_bytes);
    let mut leaf_width_bytes_raw = [0u8; 4];
    leaf_width_bytes_raw.copy_from_slice(take(4)?);
    let leaf_width_bytes = u32::from_le_bytes(leaf_width_bytes_raw);
    let mut digest_size_bytes = [0u8; 2];
    digest_size_bytes.copy_from_slice(take(2)?);
    let digest_size = u16::from_le_bytes(digest_size_bytes);
    let mut index_len_bytes = [0u8; 4];
    index_len_bytes.copy_from_slice(take(4)?);
    let index_len = u32::from_le_bytes(index_len_bytes) as usize;
    let mut indices = Vec::with_capacity(index_len);
    for _ in 0..index_len {
        let mut index_bytes = [0u8; 4];
        index_bytes.copy_from_slice(take(4)?);
        indices.push(u32::from_le_bytes(index_bytes));
    }
    let mut path_len_bytes = [0u8; 4];
    path_len_bytes.copy_from_slice(take(4)?);
    let path_len = u32::from_le_bytes(path_len_bytes) as usize;
    let mut path = Vec::with_capacity(path_len);
    for _ in 0..path_len {
        let tag = take(1)?[0];
        let count = take(1)?[0] as usize;
        let expected = match tag {
            2 => 1,
            4 => 3,
            _ => return Err(MerkleError::Serialization(SerKind::Proof)),
        };
        if count != expected {
            return Err(MerkleError::Serialization(SerKind::Proof));
        }
        let mut digests = Vec::with_capacity(count);
        for _ in 0..count {
            let raw = take(digest_size as usize)?;
            digests.push(Digest::new(raw.to_vec()));
        }
        let node = match tag {
            2 => {
                let arr = [digests
                    .into_iter()
                    .next()
                    .ok_or(MerkleError::Serialization(SerKind::Proof))?];
                ProofNode::Arity2(arr)
            }
            4 => {
                let mut iter = digests.into_iter();
                let arr = [
                    iter.next()
                        .ok_or(MerkleError::Serialization(SerKind::Proof))?,
                    iter.next()
                        .ok_or(MerkleError::Serialization(SerKind::Proof))?,
                    iter.next()
                        .ok_or(MerkleError::Serialization(SerKind::Proof))?,
                ];
                ProofNode::Arity4(arr)
            }
            _ => unreachable!(),
        };
        path.push(node);
    }

    Ok(MerkleProof {
        version,
        arity,
        leaf_encoding,
        path,
        indices,
        leaf_width,
        domain_sep,
        leaf_width_bytes,
        digest_size,
    })
}

/// Serialises the commitment auxiliary structure for storage.
pub fn encode_commit_aux(aux: &CommitAux) -> Result<Vec<u8>, MerkleError> {
    let mut out = Vec::new();
    out.extend_from_slice(&aux.version.to_le_bytes());
    out.push(encode_arity(aux.arity));
    out.push(encode_endianness(aux.leaf_encoding));
    out.push(aux.leaf_width);
    out.extend_from_slice(&aux.domain_sep.to_le_bytes());
    out.extend_from_slice(&aux.digest_size.to_le_bytes());
    out.extend_from_slice(&aux.leaf_count.to_le_bytes());
    out.extend_from_slice(&aux.depth.0.to_le_bytes());
    out.extend_from_slice(&(aux.levels.len() as u32).to_le_bytes());
    for level in &aux.levels {
        out.extend_from_slice(&(level.len() as u32).to_le_bytes());
        for digest in level {
            out.extend_from_slice(&(digest.as_bytes().len() as u32).to_le_bytes());
            out.extend_from_slice(digest.as_bytes());
        }
    }
    Ok(out)
}

/// Deserialises [`CommitAux`] from its canonical encoding.
pub fn decode_commit_aux(bytes: &[u8]) -> Result<CommitAux, MerkleError> {
    let mut cursor = 0usize;
    let mut take = |len: usize| -> Result<&[u8], MerkleError> {
        if cursor + len > bytes.len() {
            return Err(MerkleError::Serialization(SerKind::CommitAux));
        }
        let slice = &bytes[cursor..cursor + len];
        cursor += len;
        Ok(slice)
    };

    let mut version_bytes = [0u8; 2];
    version_bytes.copy_from_slice(take(2)?);
    let version = u16::from_le_bytes(version_bytes);
    let arity = decode_arity(take(1)?[0]).ok_or(MerkleError::Serialization(SerKind::CommitAux))?;
    let leaf_encoding =
        decode_endianness(take(1)?[0]).ok_or(MerkleError::Serialization(SerKind::CommitAux))?;
    let leaf_width = take(1)?[0];
    let mut domain_sep_bytes = [0u8; 8];
    domain_sep_bytes.copy_from_slice(take(8)?);
    let domain_sep = u64::from_le_bytes(domain_sep_bytes);
    let mut digest_size_bytes = [0u8; 2];
    digest_size_bytes.copy_from_slice(take(2)?);
    let digest_size = u16::from_le_bytes(digest_size_bytes);
    let mut leaf_count_bytes = [0u8; 4];
    leaf_count_bytes.copy_from_slice(take(4)?);
    let leaf_count = u32::from_le_bytes(leaf_count_bytes);
    let mut depth_bytes = [0u8; 4];
    depth_bytes.copy_from_slice(take(4)?);
    let depth = u32::from_le_bytes(depth_bytes);
    let mut level_count_bytes = [0u8; 4];
    level_count_bytes.copy_from_slice(take(4)?);
    let level_count = u32::from_le_bytes(level_count_bytes) as usize;
    let mut levels = Vec::with_capacity(level_count);
    for _ in 0..level_count {
        let mut node_count_bytes = [0u8; 4];
        node_count_bytes.copy_from_slice(take(4)?);
        let node_count = u32::from_le_bytes(node_count_bytes) as usize;
        let mut level = Vec::with_capacity(node_count);
        for _ in 0..node_count {
            let mut len_bytes = [0u8; 4];
            len_bytes.copy_from_slice(take(4)?);
            let len = u32::from_le_bytes(len_bytes) as usize;
            let raw = take(len)?;
            level.push(Digest::new(raw.to_vec()));
        }
        levels.push(level);
    }

    Ok(CommitAux {
        version,
        arity,
        leaf_width,
        leaf_encoding,
        domain_sep,
        digest_size,
        leaf_count,
        depth: super::types::TreeDepth(depth),
        levels,
    })
}
