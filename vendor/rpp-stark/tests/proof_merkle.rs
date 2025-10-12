mod _fixtures;

use _fixtures::{
    flip_trace_root_byte, mini_fixture, reencode_proof, MINI_TRACE_INDICES, MINI_TRACE_PATH_LENGTHS,
};
use rpp_stark::proof::public_inputs::PublicInputs;
use rpp_stark::proof::ser::map_public_to_config_kind;
use rpp_stark::proof::types::{MerkleSection, VerifyError};
use rpp_stark::proof::verifier::verify;

fn declared_kind(inputs: &PublicInputs<'_>) -> rpp_stark::config::ProofKind {
    map_public_to_config_kind(inputs.kind())
}

#[test]
fn merkle_openings_match_snapshot() {
    let fixture = mini_fixture();
    let proof = fixture.proof();
    let trace_openings = proof.openings().trace();
    assert_eq!(trace_openings.indices(), &MINI_TRACE_INDICES);
    let trace_lengths: Vec<u8> = trace_openings
        .paths()
        .iter()
        .map(|path| path.nodes().len() as u8)
        .collect();
    assert_eq!(trace_lengths, MINI_TRACE_PATH_LENGTHS);

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
        report.merkle_ok,
        "merkle stage should succeed for canonical proof"
    );
}

#[test]
fn merkle_rejects_root_mismatch() {
    let fixture = mini_fixture();
    let public_inputs = fixture.public_inputs();
    let tampered = flip_trace_root_byte(&fixture.proof_bytes());

    let report = verify(
        declared_kind(&public_inputs),
        &public_inputs,
        &tampered,
        &fixture.config(),
        &fixture.verifier_context(),
    );

    match report.error {
        Some(VerifyError::RootMismatch {
            section: MerkleSection::TraceCommit,
        }) => {}
        other => panic!("unexpected error: {other:?}"),
    }
    assert!(!report.merkle_ok, "merkle stage must fail on root mismatch");
}

#[test]
fn merkle_rejects_path_corruption() {
    let fixture = mini_fixture();
    let public_inputs = fixture.public_inputs();
    let mut proof = fixture.proof();
    let path = proof
        .openings_mut()
        .trace_mut()
        .paths_mut()
        .first_mut()
        .expect("path entry");
    path.nodes_mut().first_mut().expect("node entry").sibling[0] ^= 0x01;
    let tampered = reencode_proof(&mut proof);

    let report = verify(
        declared_kind(&public_inputs),
        &public_inputs,
        &tampered,
        &fixture.config(),
        &fixture.verifier_context(),
    );

    match report.error {
        Some(VerifyError::MerkleVerifyFailed {
            section: MerkleSection::TraceCommit,
        }) => {}
        other => panic!("unexpected error: {other:?}"),
    }
    assert!(
        !report.merkle_ok,
        "merkle stage must fail on path corruption"
    );
}
