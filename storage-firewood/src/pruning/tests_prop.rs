use super::*;
use proptest::prelude::*;
use std::collections::BTreeMap;

fn proptest_config() -> ProptestConfig {
    let cases = std::env::var("PROPTEST_CASES")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(48);
    ProptestConfig {
        cases,
        ..ProptestConfig::default()
    }
}

prop_compose! {
    fn arb_hash()(bytes in prop::array::uniform32(any::<u8>())) -> Hash {
        bytes
    }
}

prop_compose! {
    fn arb_pruning_sequence()(retain in 1usize..6usize,
                              entries in prop::collection::vec((any::<u64>(), arb_hash()), 1..6))
        -> (usize, Vec<(u64, Hash)>)
    {
        let mut unique = BTreeMap::new();
        for (id, root) in entries {
            unique.insert(id, root);
        }
        let mut ordered: Vec<_> = unique.into_iter().collect();
        ordered.sort_by_key(|(id, _)| *id);
        (retain, ordered)
    }
}

proptest! {
    #![proptest_config(proptest_config())]
    fn pruning_proofs_roundtrip((retain, entries) in arb_pruning_sequence()) {
        let mut pruner = FirewoodPruner::new(retain);
        for (id, root) in entries.iter().cloned() {
            let (commitment, proof) = pruner.prune_block(id, root);
            let encoded = bincode::serialize(&proof).expect("serialize pruning proof");
            let decoded: PruningProof = bincode::deserialize(&encoded).expect("deserialize pruning proof");
            assert_eq!(decoded, proof);
            assert!(FirewoodPruner::verify_pruned_state(commitment, &decoded));
        }
    }
}

proptest! {
    #![proptest_config(proptest_config())]
    fn pruning_proof_detects_mutation((retain, entries) in arb_pruning_sequence()) {
        let mut pruner = FirewoodPruner::new(retain);
        for (id, root) in entries.iter().cloned() {
            let (commitment, proof) = pruner.prune_block(id, root);
            let mut corrupted = proof.clone();
            if let Some(byte) = corrupted.root.get_mut(0) {
                *byte ^= 0xFF;
            }
            assert!(!FirewoodPruner::verify_pruned_state(commitment, &corrupted));
        }
    }
}
