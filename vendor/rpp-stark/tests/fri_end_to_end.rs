use insta::assert_snapshot;
use proptest::prelude::*;
use rpp_stark::config::{PROFILE_HIGH_SECURITY_CONFIG, PROFILE_STANDARD_CONFIG};
use rpp_stark::field::prime_field::FieldElementOps;
use rpp_stark::field::FieldElement;
use rpp_stark::fri::types::FriError;
use rpp_stark::fri::{DeepOodsProof, FriProof, FriSecurityLevel, FriTranscriptSeed, FriVerifier};
use rpp_stark::hash::{hash, Blake2sXof, FiatShamirChallengeRules};
use rpp_stark::proof::params::canonical_stark_params;

fn sample_evaluations() -> Vec<FieldElement> {
    (0..512)
        .map(|i| FieldElement::from((i as u64) + 1))
        .collect()
}

fn sample_seed() -> FriTranscriptSeed {
    [7u8; 32]
}

fn final_value_oracle(values: Vec<FieldElement>) -> impl FnMut(usize) -> FieldElement {
    move |index| values[index]
}

fn standard_params() -> rpp_stark::params::StarkParams {
    canonical_stark_params(&PROFILE_STANDARD_CONFIG)
}

fn hisec_params() -> rpp_stark::params::StarkParams {
    canonical_stark_params(&PROFILE_HIGH_SECURITY_CONFIG)
}

fn hex_bytes(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use core::fmt::Write;
        let _ = write!(&mut out, "{:02x}", byte);
    }
    out
}

fn attach_deep_payload(base: &FriProof) -> FriProof {
    let deep = DeepOodsProof {
        point: FieldElement::from(123u64),
        evaluations: base.final_polynomial.iter().take(8).cloned().collect(),
    };

    FriProof::with_deep_oods(
        base.security_level,
        base.initial_domain_size,
        base.layer_roots.clone(),
        base.fold_challenges.clone(),
        base.final_polynomial.clone(),
        base.final_polynomial_digest,
        base.queries.clone(),
        Some(deep),
    )
    .expect("deep proof")
}

fn derive_query_positions_from_proof(proof: &FriProof, seed: FriTranscriptSeed) -> Vec<usize> {
    let mut state = seed;

    for (layer_index, root) in proof.layer_roots.iter().enumerate() {
        let mut payload = Vec::with_capacity(48);
        payload.extend_from_slice(&state);
        payload.extend_from_slice(&(layer_index as u64).to_le_bytes());
        payload.extend_from_slice(root);
        state = hash(&payload).into();

        let label = format!("{}ETA-{layer_index}", FiatShamirChallengeRules::SALT_PREFIX);
        let mut challenge_payload = Vec::with_capacity(state.len() + label.len());
        challenge_payload.extend_from_slice(&state);
        challenge_payload.extend_from_slice(label.as_bytes());
        let challenge: [u8; 32] = hash(&challenge_payload).into();
        state = hash(&challenge).into();

        let _ = proof
            .fold_challenges
            .get(layer_index)
            .expect("fold challenge");
    }

    let mut final_payload = Vec::with_capacity(64);
    final_payload.extend_from_slice(&state);
    final_payload.extend_from_slice(b"RPP-FS/FINAL");
    final_payload.extend_from_slice(&proof.final_polynomial_digest);
    state = hash(&final_payload).into();

    let mut query_payload = Vec::with_capacity(64);
    query_payload.extend_from_slice(&state);
    query_payload.extend_from_slice(b"RPP-FS/QUERY-SEED");
    let query_seed: [u8; 32] = hash(&query_payload).into();

    let target = proof
        .security_level
        .query_budget()
        .min(proof.initial_domain_size);
    let mut xof = Blake2sXof::new(&query_seed);
    let mut unique = Vec::with_capacity(target);
    let mut seen = vec![false; proof.initial_domain_size];

    while unique.len() < target {
        let word = xof.next_u64().expect("query sampling");
        let position = (word % (proof.initial_domain_size as u64)) as usize;
        if !seen[position] {
            seen[position] = true;
            unique.push(position);
        }
    }

    unique.sort();
    unique
}

#[test]
fn prover_verifier_roundtrip_without_deep() {
    let evaluations = sample_evaluations();
    let seed = sample_seed();

    let params = standard_params();
    let proof =
        FriProof::prove_with_params(FriSecurityLevel::Standard, seed, &evaluations, &params)
            .expect("proof");
    let finals = proof.final_polynomial.clone();
    FriVerifier::verify_with_params(
        &proof,
        FriSecurityLevel::Standard,
        seed,
        &params,
        final_value_oracle(finals.clone()),
    )
    .expect("verification");

    let bytes = proof.to_bytes().expect("serialize");
    assert_snapshot!("fri_end_to_end_standard_proof", hex_bytes(&bytes));
}

#[test]
fn prover_verifier_roundtrip_with_deep_payload() {
    let evaluations = sample_evaluations();
    let seed = sample_seed();
    let params = hisec_params();
    let base = FriProof::prove_with_params(FriSecurityLevel::HiSec, seed, &evaluations, &params)
        .expect("base proof");

    let proof = attach_deep_payload(&base);
    assert!(proof.deep_oods.is_some(), "deep payload must be attached");

    let finals = proof.final_polynomial.clone();
    FriVerifier::verify_with_params(
        &proof,
        FriSecurityLevel::HiSec,
        seed,
        &params,
        final_value_oracle(finals.clone()),
    )
    .expect("verification");

    let bytes = proof.to_bytes().expect("serialize");
    assert_snapshot!("fri_end_to_end_hisec_deep_proof", hex_bytes(&bytes));
}

#[test]
fn proofs_are_deterministic_for_fixed_inputs() {
    let evaluations = sample_evaluations();
    let seed = sample_seed();

    let params = standard_params();
    let proof_a =
        FriProof::prove_with_params(FriSecurityLevel::Standard, seed, &evaluations, &params)
            .expect("proof a");
    let proof_b =
        FriProof::prove_with_params(FriSecurityLevel::Standard, seed, &evaluations, &params)
            .expect("proof b");

    assert_eq!(proof_a, proof_b, "proofs must be identical across runs");
}

#[test]
fn tampered_leaf_opening_is_rejected() {
    let evaluations = sample_evaluations();
    let seed = sample_seed();
    let params = standard_params();
    let mut proof =
        FriProof::prove_with_params(FriSecurityLevel::Standard, seed, &evaluations, &params)
            .expect("proof");

    if let Some(path) = proof
        .queries
        .get_mut(0)
        .and_then(|query| query.layers.get_mut(0))
        .and_then(|layer| layer.path.get_mut(0))
    {
        path.siblings[0][0] ^= 0x01;
    }

    let finals = proof.final_polynomial.clone();
    let err = FriVerifier::verify_with_params(
        &proof,
        FriSecurityLevel::Standard,
        seed,
        &params,
        final_value_oracle(finals),
    )
    .expect_err("tampering should be detected");

    assert!(matches!(
        err,
        FriError::LayerRootMismatch { .. } | FriError::PathInvalid { .. }
    ));
}

#[test]
fn profile_query_budget_mismatch_is_detected() {
    let evaluations = sample_evaluations();
    let seed = sample_seed();
    let standard = standard_params();
    let hisec = hisec_params();

    let err = FriProof::prove_with_params(FriSecurityLevel::HiSec, seed, &evaluations, &standard)
        .expect_err("security/profile mismatch should be rejected");
    assert!(matches!(err, FriError::QueryBudgetMismatch { .. }));

    let proof = FriProof::prove_with_params(FriSecurityLevel::HiSec, seed, &evaluations, &hisec)
        .expect("hi-sec proof");
    let finals = proof.final_polynomial.clone();
    let err = FriVerifier::verify_with_params(
        &proof,
        FriSecurityLevel::HiSec,
        seed,
        &standard,
        final_value_oracle(finals),
    )
    .expect_err("verifier should detect mismatched parameters");
    assert!(matches!(err, FriError::QueryBudgetMismatch { .. }));
}

#[test]
fn tampered_layer_root_is_rejected() {
    let evaluations = sample_evaluations();
    let seed = sample_seed();
    let params = standard_params();
    let mut proof =
        FriProof::prove_with_params(FriSecurityLevel::Standard, seed, &evaluations, &params)
            .expect("proof");

    if let Some(root) = proof.layer_roots.get_mut(0) {
        root[0] ^= 0x01;
    }

    let finals = proof.final_polynomial.clone();
    let err = FriVerifier::verify_with_params(
        &proof,
        FriSecurityLevel::Standard,
        seed,
        &params,
        final_value_oracle(finals),
    )
    .expect_err("tampering should be detected");

    assert!(
        matches!(err, FriError::InvalidStructure(message) if message == "fold challenge mismatch")
    );
}

#[test]
fn tampered_fold_challenge_is_rejected() {
    let evaluations = sample_evaluations();
    let seed = sample_seed();
    let params = standard_params();
    let mut proof =
        FriProof::prove_with_params(FriSecurityLevel::Standard, seed, &evaluations, &params)
            .expect("proof");

    if let Some(challenge) = proof.fold_challenges.get_mut(0) {
        *challenge = challenge.add(&FieldElement::ONE);
    }

    let finals = proof.final_polynomial.clone();
    let err = FriVerifier::verify_with_params(
        &proof,
        FriSecurityLevel::Standard,
        seed,
        &params,
        final_value_oracle(finals),
    )
    .expect_err("tampering should be detected");

    assert!(
        matches!(err, FriError::InvalidStructure(message) if message == "fold challenge mismatch")
    );
}

proptest! {
    #[test]
    fn proofs_verify_for_random_low_degree_polynomials(
        seed in prop::array::uniform32(any::<u8>()),
        coeffs in prop::collection::vec(0u64..1_000_000u64, 1..5),
    ) {
        let domain_size = 128usize;
        let coefficients: Vec<FieldElement> = coeffs.into_iter().map(FieldElement::from).collect();
        let evaluations: Vec<FieldElement> = (0..domain_size)
            .map(|i| {
                let point = FieldElement::from(i as u64);
                coefficients.iter().rev().fold(FieldElement::ZERO, |acc, coeff| {
                    acc.mul(&point).add(coeff)
                })
            })
            .collect();

        let params = standard_params();
        let proof = FriProof::prove_with_params(FriSecurityLevel::Standard, seed, &evaluations, &params)
            .expect("proof");
        let finals = proof.final_polynomial.clone();
        FriVerifier::verify_with_params(
            &proof,
            FriSecurityLevel::Standard,
            seed,
            &params,
            final_value_oracle(finals),
        )
        .expect("verification");
    }
}

proptest! {
    #[test]
    fn query_positions_follow_specification(seed in prop::array::uniform32(any::<u8>()),)
    {
        let evaluations = sample_evaluations();
        let params = standard_params();
        let proof = FriProof::prove_with_params(FriSecurityLevel::Standard, seed, &evaluations, &params)
            .expect("proof");

        let expected_positions = derive_query_positions_from_proof(&proof, seed);
        let actual_positions: Vec<usize> = proof.queries.iter().map(|query| query.position).collect();

        prop_assert_eq!(actual_positions, expected_positions);
    }
}
