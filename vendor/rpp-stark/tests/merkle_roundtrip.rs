use proptest::prelude::*;
use rpp_stark::merkle::{
    decode_commit_aux, decode_proof, encode_commit_aux, encode_proof, CommitAux,
    DeterministicMerkleHasher, Leaf, MerkleCommit, MerkleError, MerkleTree,
};
use rpp_stark::params::{Endianness, HashKind, MerkleArity, StarkParams, StarkParamsBuilder};

fn build_params(arity: MerkleArity, leaf_width: u8) -> StarkParams {
    let mut builder = StarkParamsBuilder::new();
    builder.hash = HashKind::Blake2s { digest_size: 32 };
    builder.merkle.arity = arity;
    builder.merkle.leaf_width = leaf_width;
    builder.merkle.leaf_encoding = Endianness::Little;
    builder.build().expect("valid params")
}

fn make_leaves(count: usize, width: u8) -> Vec<Leaf> {
    let mut leaves = Vec::with_capacity(count);
    for i in 0..count {
        let mut bytes = Vec::new();
        for j in 0..width as usize {
            let value = (i * width as usize + j) as u64;
            bytes.extend_from_slice(&value.to_le_bytes());
        }
        leaves.push(Leaf::new(bytes));
    }
    leaves
}

fn commit_aux(params: &StarkParams, leaves: Vec<Leaf>) -> (rpp_stark::merkle::Digest, CommitAux) {
    let mut tree = MerkleTree::<DeterministicMerkleHasher>::new(params).unwrap();
    let root = tree.commit(leaves.into_iter()).expect("commit");
    let aux = tree.into_aux();
    (root, aux)
}

#[test]
fn roundtrip_binary_single_index() {
    let params = build_params(MerkleArity::Binary, 4);
    let leaves = make_leaves(16, params.merkle().leaf_width);
    let (root, aux) = commit_aux(&params, leaves.clone());
    let proof = MerkleTree::<DeterministicMerkleHasher>::open(&params, &aux, &[3]).unwrap();
    MerkleTree::<DeterministicMerkleHasher>::verify(&params, &root, &proof, &[leaves[3].clone()])
        .unwrap();
}

#[test]
fn roundtrip_quaternary_multi_index() {
    let params = build_params(MerkleArity::Quaternary, 4);
    let leaves = make_leaves(32, params.merkle().leaf_width);
    let (root, aux) = commit_aux(&params, leaves.clone());
    let proof = MerkleTree::<DeterministicMerkleHasher>::open(&params, &aux, &[1, 7, 11]).unwrap();
    let selected = vec![leaves[1].clone(), leaves[7].clone(), leaves[11].clone()];
    MerkleTree::<DeterministicMerkleHasher>::verify(&params, &root, &proof, &selected).unwrap();
}

#[test]
fn roundtrip_quaternary_single_index() {
    let params = build_params(MerkleArity::Quaternary, 4);
    let leaves = make_leaves(16, params.merkle().leaf_width);
    let (root, aux) = commit_aux(&params, leaves.clone());
    let proof = MerkleTree::<DeterministicMerkleHasher>::open(&params, &aux, &[5]).unwrap();
    MerkleTree::<DeterministicMerkleHasher>::verify(&params, &root, &proof, &[leaves[5].clone()])
        .unwrap();
}

#[test]
fn determinism_snapshot() {
    let params = build_params(MerkleArity::Binary, 4);
    let leaves = make_leaves(8, params.merkle().leaf_width);
    let (root, aux) = commit_aux(&params, leaves.clone());
    let proof = MerkleTree::<DeterministicMerkleHasher>::open(&params, &aux, &[2, 5]).unwrap();
    let proof_bytes = encode_proof(&proof).unwrap();
    let aux_bytes = encode_commit_aux(&aux).unwrap();
    insta::assert_snapshot!("merkle_root_bin", hex_bytes(root.as_bytes()));
    insta::assert_snapshot!("merkle_proof_bin", hex_bytes(&proof_bytes));
    insta::assert_snapshot!("merkle_aux_bin", hex_bytes(&aux_bytes));
}

#[test]
fn proof_serialization_roundtrip() {
    let params = build_params(MerkleArity::Binary, 4);
    let leaves = make_leaves(8, params.merkle().leaf_width);
    let (_, aux) = commit_aux(&params, leaves.clone());
    let proof = MerkleTree::<DeterministicMerkleHasher>::open(&params, &aux, &[1, 6]).unwrap();
    let encoded = encode_proof(&proof).unwrap();
    let decoded = decode_proof(&encoded).unwrap();
    assert_eq!(proof.indices, decoded.indices);
    assert_eq!(proof.path.len(), decoded.path.len());
}

#[test]
fn aux_serialization_roundtrip() {
    let params = build_params(MerkleArity::Quaternary, 4);
    let leaves = make_leaves(8, params.merkle().leaf_width);
    let (_, aux) = commit_aux(&params, leaves);
    let encoded = encode_commit_aux(&aux).unwrap();
    let decoded = decode_commit_aux(&encoded).unwrap();
    assert_eq!(aux.leaf_count, decoded.leaf_count);
    assert_eq!(aux.domain_sep, decoded.domain_sep);
}

#[test]
fn invalid_index_open() {
    let params = build_params(MerkleArity::Binary, 4);
    let leaves = make_leaves(4, params.merkle().leaf_width);
    let (_, aux) = commit_aux(&params, leaves);
    let err = MerkleTree::<DeterministicMerkleHasher>::open(&params, &aux, &[10]).unwrap_err();
    assert!(matches!(err, MerkleError::IndexOutOfRange { .. }));
}

#[test]
fn duplicate_index_open() {
    let params = build_params(MerkleArity::Binary, 4);
    let leaves = make_leaves(4, params.merkle().leaf_width);
    let (_, aux) = commit_aux(&params, leaves);
    let err = MerkleTree::<DeterministicMerkleHasher>::open(&params, &aux, &[1, 1]).unwrap_err();
    assert!(matches!(err, MerkleError::DuplicateIndex { .. }));
}

#[test]
fn tampered_proof_fails() {
    let params = build_params(MerkleArity::Binary, 4);
    let leaves = make_leaves(8, params.merkle().leaf_width);
    let (root, aux) = commit_aux(&params, leaves.clone());
    let mut proof = MerkleTree::<DeterministicMerkleHasher>::open(&params, &aux, &[2]).unwrap();
    if let Some(first) = proof.path.first_mut() {
        if let Some(sibling) = first.siblings_mut().first_mut() {
            let bytes = sibling.as_bytes_mut();
            bytes[0] ^= 0x01;
        }
    }
    let err = MerkleTree::<DeterministicMerkleHasher>::verify(
        &params,
        &root,
        &proof,
        &[leaves[2].clone()],
    )
    .unwrap_err();
    assert!(matches!(err, MerkleError::VerificationFailed));
}

#[test]
fn tampered_quaternary_proof_fails() {
    let params = build_params(MerkleArity::Quaternary, 4);
    let leaves = make_leaves(16, params.merkle().leaf_width);
    let (root, aux) = commit_aux(&params, leaves.clone());
    let mut proof = MerkleTree::<DeterministicMerkleHasher>::open(&params, &aux, &[3]).unwrap();
    if let Some(first) = proof.path.first_mut() {
        if let Some(sibling) = first.siblings_mut().first_mut() {
            let bytes = sibling.as_bytes_mut();
            bytes[0] ^= 0x02;
        }
    }
    let err = MerkleTree::<DeterministicMerkleHasher>::verify(
        &params,
        &root,
        &proof,
        &[leaves[3].clone()],
    )
    .unwrap_err();
    assert!(matches!(err, MerkleError::VerificationFailed));
}

fn hex_bytes(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

proptest! {
    #[test]
    fn random_roundtrip(num_leaves in 2usize..32, indices in proptest::collection::btree_set(0u32..64u32, 1..4)) {
        let params = build_params(MerkleArity::Binary, 4);
        let leaves = make_leaves(num_leaves, params.merkle().leaf_width);
        let remapped: std::collections::BTreeSet<u32> = indices
            .into_iter()
            .map(|i| i % num_leaves as u32)
            .collect();
        let indices: Vec<u32> = remapped.into_iter().collect();
        let (root, aux) = commit_aux(&params, leaves.clone());
        let proof = MerkleTree::<DeterministicMerkleHasher>::open(&params, &aux, &indices).unwrap();
        for node in proof.path() {
            let mut seen_zero = false;
            for sibling in node.siblings() {
                let is_zero = sibling.as_bytes().iter().all(|b| *b == 0);
                if is_zero {
                    seen_zero = true;
                } else {
                    assert!(!seen_zero, "non-zero digest after zero padding");
                }
            }
        }
        let selected: Vec<Leaf> = indices.iter().map(|i| leaves[*i as usize].clone()).collect();
        MerkleTree::<DeterministicMerkleHasher>::verify(&params, &root, &proof, &selected).unwrap();
    }
}
