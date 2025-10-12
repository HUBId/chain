mod _fixtures;

use _fixtures::{
    mini_fixture, reencode_proof, MINI_COMPOSITION_INDICES, MINI_COMPOSITION_PATH_LENGTHS,
};
use rpp_stark::field::FieldElement;
use rpp_stark::proof::public_inputs::PublicInputs;
use rpp_stark::proof::ser::map_public_to_config_kind;
use rpp_stark::proof::types::VerifyError;
use rpp_stark::proof::verifier::verify;

fn declared_kind(inputs: &PublicInputs<'_>) -> rpp_stark::config::ProofKind {
    map_public_to_config_kind(inputs.kind())
}

#[test]
fn composition_openings_match_snapshot() {
    let fixture = mini_fixture();
    let proof = fixture.proof();
    let composition = proof
        .openings()
        .composition()
        .expect("composition openings");
    assert_eq!(composition.indices(), &MINI_COMPOSITION_INDICES);
    let path_lengths: Vec<u8> = composition
        .paths()
        .iter()
        .map(|path| path.nodes().len() as u8)
        .collect();
    assert_eq!(path_lengths, MINI_COMPOSITION_PATH_LENGTHS);

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
        report.composition_ok,
        "composition stage should succeed for canonical proof"
    );
}

#[test]
fn composition_rejects_leaf_mismatch() {
    let fixture = mini_fixture();
    let public_inputs = fixture.public_inputs();
    let mut proof = fixture.proof();
    let leaf = proof
        .openings_mut()
        .composition_mut()
        .expect("composition openings")
        .leaves_mut()
        .first_mut()
        .expect("leaf entry");
    leaf.truncate(FieldElement::BYTE_LENGTH - 1);
    let tampered = reencode_proof(&mut proof);

    let report = verify(
        declared_kind(&public_inputs),
        &public_inputs,
        &tampered,
        &fixture.config(),
        &fixture.verifier_context(),
    );

    match report.error {
        Some(VerifyError::CompositionLeafMismatch) => {}
        other => panic!("unexpected error: {other:?}"),
    }
    assert!(
        !report.merkle_ok,
        "merkle stage must fail when composition leaves are malformed"
    );
    assert!(
        !report.composition_ok,
        "composition stage must fail on leaf mismatch"
    );
}
