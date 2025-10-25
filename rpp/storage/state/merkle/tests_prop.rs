use super::*;
use crate::proof_backend::Blake2sHasher;
use proptest::prelude::*;

fn proptest_config() -> ProptestConfig {
    let cases = std::env::var("PROPTEST_CASES")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(64);
    ProptestConfig {
        cases,
        ..ProptestConfig::default()
    }
}

prop_compose! {
    fn arb_leaves()(entries in prop::collection::vec((prop::array::uniform32(any::<u8>()), any::<u8>()), 0..12))
        -> Vec<([u8; 32], u8)>
    {
        entries
    }
}

proptest! {
    #![proptest_config(proptest_config())]
    fn merkle_root_is_order_independent(entries in arb_leaves()) {
        let mut original: Vec<[u8; 32]> = entries.iter().map(|(leaf, _)| *leaf).collect();
        let mut permuted_pairs = entries.clone();
        permuted_pairs.sort_by_key(|(_, weight)| *weight);
        let mut permuted: Vec<[u8; 32]> = permuted_pairs.into_iter().map(|(leaf, _)| leaf).collect();

        let root_original = compute_merkle_root(&mut original.clone());
        let root_permuted = compute_merkle_root(&mut permuted);
        assert_eq!(root_original, root_permuted);
    }
}

proptest! {
    #![proptest_config(proptest_config())]
    fn merkle_root_sorts_in_place(entries in arb_leaves()) {
        let mut leaves: Vec<[u8; 32]> = entries.into_iter().map(|(leaf, _)| leaf).collect();
        compute_merkle_root(&mut leaves);
        let mut sorted = leaves.clone();
        sorted.sort();
        assert_eq!(leaves, sorted);
    }
}

#[test]
fn empty_merkle_root_is_constant() {
    let mut leaves = Vec::new();
    let root = compute_merkle_root(&mut leaves);
    let expected: [u8; 32] = Blake2sHasher::hash(b"rpp-empty").into();
    assert_eq!(root, expected);
}
