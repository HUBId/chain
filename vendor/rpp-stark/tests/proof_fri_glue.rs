mod _fixtures;

use _fixtures::{mini_fixture, reencode_proof, MINI_FRI_FOLD_CHALLENGES_HEX, MINI_FRI_ROOTS};
use rpp_stark::field::prime_field::CanonicalSerialize;
use rpp_stark::proof::public_inputs::PublicInputs;
use rpp_stark::proof::ser::map_public_to_config_kind;
use rpp_stark::proof::types::{FriVerifyIssue, VerifyError};
use rpp_stark::proof::verifier::verify;

fn declared_kind(inputs: &PublicInputs<'_>) -> rpp_stark::config::ProofKind {
    map_public_to_config_kind(inputs.kind())
}

fn bytes_to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{:02x}", byte)).collect()
}

#[test]
fn fri_roots_and_challenges_match_snapshot() {
    let fixture = mini_fixture();
    let proof = fixture.proof();
    assert_eq!(proof.merkle().fri_layer_roots(), &MINI_FRI_ROOTS);
    let actual_challenges: Vec<String> = proof
        .fri_proof()
        .fold_challenges
        .iter()
        .map(|value| bytes_to_hex(&value.to_bytes().expect("fold challenge encoding")))
        .collect();
    let expected_challenges: Vec<String> = MINI_FRI_FOLD_CHALLENGES_HEX
        .iter()
        .map(|value| value.to_string())
        .collect();
    assert_eq!(actual_challenges, expected_challenges);

    let public_inputs = fixture.public_inputs();
    let report = verify(
        declared_kind(&public_inputs),
        &public_inputs,
        &fixture.proof_bytes(),
        &fixture.config(),
        &fixture.verifier_context(),
    );
    assert!(
        report.error.is_none(),
        "unexpected verification failure: {:?}",
        report.error
    );
    assert!(
        report.fri_ok,
        "fri stage should succeed for canonical proof"
    );
}

#[test]
fn fri_rejects_fold_challenge_flip() {
    let fixture = mini_fixture();
    let public_inputs = fixture.public_inputs();
    let mut proof = fixture.proof();
    let challenge = proof
        .fri_proof_mut()
        .fold_challenges
        .first_mut()
        .expect("fold challenge");
    challenge.0 ^= 1;
    let tampered = reencode_proof(&mut proof);

    let report = verify(
        declared_kind(&public_inputs),
        &public_inputs,
        &tampered,
        &fixture.config(),
        &fixture.verifier_context(),
    );

    match report.error {
        Some(VerifyError::FriVerifyFailed {
            issue: FriVerifyIssue::FoldingConstraint,
        }) => {}
        other => panic!("unexpected error: {other:?}"),
    }
    assert!(!report.fri_ok, "fri stage must fail on fold mismatch");
}
