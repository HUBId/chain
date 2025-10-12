#![cfg(feature = "parallel")]

use rpp_stark::fft::{Fft, Radix2Fft};
use rpp_stark::field::FieldElement;
use rpp_stark::fri::binary_fold;
use rpp_stark::merkle::{DeterministicMerkleHasher, MerkleTree};
use rpp_stark::params::{BuiltinProfile, HashKind, StarkParamsBuilder};
use rpp_stark::utils::set_parallelism;

#[test]
fn fft_parallel_matches_sequential() {
    let log2_size = 5usize;
    let plan = Radix2Fft::natural_order(log2_size);
    let input: Vec<FieldElement> = (0..(1 << log2_size))
        .map(|value| FieldElement::from(value as u64))
        .collect();
    let mut baseline = input.clone();
    {
        let _guard = set_parallelism(false);
        let plan_seq = plan;
        plan_seq.forward(&mut baseline);
    }
    let mut parallel = input;
    let plan_par = plan;
    plan_par.forward(&mut parallel);
    assert_eq!(baseline, parallel);
}

#[test]
fn merkle_parallel_matches_sequential() {
    let params = {
        let mut builder = StarkParamsBuilder::from_profile(BuiltinProfile::PROFILE_X8);
        builder.hash = HashKind::Blake2s { digest_size: 32 };
        builder.build().expect("params")
    };
    let element_size = match params.field() {
        rpp_stark::params::FieldKind::Goldilocks => 8,
        rpp_stark::params::FieldKind::Bn254 => 32,
    };
    let leaf_bytes = element_size * params.merkle().leaf_width as usize;
    let leaves: Vec<_> = (0..32)
        .map(|i| rpp_stark::merkle::Leaf::new(vec![i as u8; leaf_bytes]))
        .collect();

    let baseline = {
        let _guard = set_parallelism(false);
        let mut tree = MerkleTree::<DeterministicMerkleHasher>::new(&params).expect("tree");
        let root = tree
            .commit(leaves.clone().into_iter())
            .expect("sequential commit");
        (root, tree.into_aux())
    };
    let mut tree = MerkleTree::<DeterministicMerkleHasher>::new(&params).expect("tree");
    let root = tree.commit(leaves.into_iter()).expect("parallel commit");
    let aux = tree.into_aux();

    assert_eq!(baseline.0, root);
    assert_eq!(baseline.1, aux);
}

#[test]
fn fri_binary_fold_parallel_matches_sequential() {
    let values: Vec<FieldElement> = (0..64)
        .map(|value| FieldElement::from((value * 3 + 1) as u64))
        .collect();
    let beta = FieldElement::from(7u64);
    let coset_shift = FieldElement::GENERATOR;

    let baseline = {
        let _guard = set_parallelism(false);
        binary_fold(&values, beta, coset_shift)
    };
    let parallel = binary_fold(&values, beta, coset_shift);

    assert_eq!(baseline, parallel);
}
