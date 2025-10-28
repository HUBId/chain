use super::*;
use bincode::Options;
use proptest::prelude::*;
use rpp_pruning::{Envelope, Snapshot, TaggedDigest, SNAPSHOT_STATE_TAG};
use std::collections::BTreeMap;

#[allow(dead_code)]
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
            let proof = pruner.prune_block(id, root);
            let encoded = rpp_pruning::canonical_bincode_options()
                .serialize(&proof)
                .expect("serialize pruning envelope");
            let decoded: Envelope = rpp_pruning::canonical_bincode_options()
                .deserialize(&encoded)
                .expect("deserialize pruning envelope");
            assert_eq!(decoded, proof);
            assert!(FirewoodPruner::verify_pruned_state(root, &decoded));
        }
    }
}

proptest! {
    #![proptest_config(proptest_config())]
    fn pruning_proof_detects_mutation((retain, entries) in arb_pruning_sequence()) {
        let mut pruner = FirewoodPruner::new(retain);
        for (id, root) in entries.iter().cloned() {
            let proof = pruner.prune_block(id, root);
            let mut digest = *proof.snapshot().state_commitment().digest();
            digest[0] ^= 0xFF;
            let corrupted_snapshot = Snapshot::new(
                proof.snapshot().schema_version(),
                proof.snapshot().parameter_version(),
                proof.snapshot().block_height(),
                TaggedDigest::new(SNAPSHOT_STATE_TAG, digest),
            )
            .expect("tag preserved");
            let corrupted = Envelope::new(
                proof.schema_version(),
                proof.parameter_version(),
                corrupted_snapshot,
                proof.segments().to_vec(),
                proof.commitment().clone(),
                proof.binding_digest(),
            )
            .expect("tag preserved");
            assert!(!FirewoodPruner::verify_pruned_state(root, &corrupted));
        }
    }
}
