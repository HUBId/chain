#![cfg(feature = "backend-rpp-stark")]

#[path = "../vendor/rpp-stark/tests/fail_matrix/fixture.rs"]
mod fixture;

use fixture::{flip_public_digest_byte, mismatch_fri_offset, FailMatrixFixture};
use rpp_chain::zk::rpp_verifier::{
    RppStarkMerkleSection, RppStarkSerializationContext, RppStarkVerifier, RppStarkVerifierError,
    RppStarkVerifyFailure,
};
use rpp_stark::backend::params_limit_to_node_bytes;
use rpp_stark::config::PROFILE_STANDARD_CONFIG;
use rpp_stark::params::serialize_params;
use rpp_stark::proof::params::canonical_stark_params;
use rpp_stark::proof::ser::{compute_integrity_digest, serialize_proof, serialize_public_inputs};
use rpp_stark::proof::types::Proof;
use rpp_stark::utils::serialization::{DigestBytes, ProofBytes};

fn canonical_params_bytes_and_limit() -> (Vec<u8>, u32) {
    let params = canonical_stark_params(&PROFILE_STANDARD_CONFIG);
    let limit = params_limit_to_node_bytes(&params).expect("map params limit to bytes");
    (serialize_params(&params), limit)
}

fn encode_public_inputs(fixture: &FailMatrixFixture) -> Vec<u8> {
    serialize_public_inputs(&fixture.public_inputs()).expect("serialize public inputs")
}

fn proof_bytes_to_vec(bytes: &ProofBytes) -> Vec<u8> {
    bytes.as_slice().to_vec()
}

fn reencode_proof(mut proof: Proof) -> Vec<u8> {
    if proof.has_telemetry() {
        let mut canonical = proof.clone_using_parts();
        let telemetry = canonical.telemetry_frame_mut();
        telemetry.set_header_length(0);
        telemetry.set_body_length(0);
        telemetry.set_integrity_digest(DigestBytes { bytes: [0u8; 32] });
        let payload = canonical
            .serialize_payload()
            .expect("serialize canonical payload");
        let header = canonical
            .serialize_header(&payload)
            .expect("serialize canonical header");
        let integrity = compute_integrity_digest(&header, &payload);
        let telemetry = proof.telemetry_frame_mut();
        telemetry.set_header_length(header.len() as u32);
        telemetry.set_body_length((payload.len() + 32) as u32);
        telemetry.set_integrity_digest(DigestBytes { bytes: integrity });
    }

    serialize_proof(&proof).expect("serialize proof")
}

fn tamper_merkle_path(fixture: &FailMatrixFixture) -> Vec<u8> {
    let mut proof = fixture.proof();
    if let Some(node) = proof
        .openings_mut()
        .trace_mut()
        .paths_mut()
        .first_mut()
        .and_then(|path| path.nodes_mut().first_mut())
    {
        node.sibling[0] ^= 0x01;
    }
    reencode_proof(proof)
}

#[test]
fn merkle_path_tampering_maps_to_trace_commit_failure() {
    let fixture = FailMatrixFixture::new();
    let (params_bytes, node_limit) = canonical_params_bytes_and_limit();
    let public_inputs = encode_public_inputs(&fixture);
    let tampered_proof = tamper_merkle_path(&fixture);

    let verifier = RppStarkVerifier::new();
    let error = verifier
        .verify(&params_bytes, &public_inputs, &tampered_proof, node_limit)
        .expect_err("merkle tampering should be rejected");

    let (failure, report) = match error {
        RppStarkVerifierError::VerificationFailed { failure, report } => (failure, report),
        other => panic!("unexpected error variant: {other:?}"),
    };

    assert_eq!(
        failure,
        RppStarkVerifyFailure::MerkleVerifyFailed {
            section: RppStarkMerkleSection::TraceCommit,
        }
    );
    assert!(report.params_ok(), "params stage should succeed");
    assert!(report.public_ok(), "public stage should succeed");
    assert!(!report.merkle_ok(), "merkle stage must fail");
    assert!(!report.fri_ok(), "fri stage must fail");
    assert!(!report.composition_ok(), "composition stage must fail");
}

#[test]
fn public_digest_mismatch_maps_to_public_failure() {
    let fixture = FailMatrixFixture::new();
    let (params_bytes, node_limit) = canonical_params_bytes_and_limit();
    let public_inputs = encode_public_inputs(&fixture);
    let mutated_proof = proof_bytes_to_vec(&flip_public_digest_byte(&fixture.proof_bytes()));

    let verifier = RppStarkVerifier::new();
    let error = verifier
        .verify(&params_bytes, &public_inputs, &mutated_proof, node_limit)
        .expect_err("public digest mismatch should be rejected");

    let (failure, report) = match error {
        RppStarkVerifierError::VerificationFailed { failure, report } => (failure, report),
        other => panic!("unexpected error variant: {other:?}"),
    };

    assert_eq!(failure, RppStarkVerifyFailure::PublicDigestMismatch);
    assert!(
        !report.params_ok() && !report.public_ok(),
        "params and public stages must fail"
    );
}

#[test]
fn fri_payload_offset_mismatch_maps_to_serialization_error() {
    let fixture = FailMatrixFixture::new();
    let (params_bytes, node_limit) = canonical_params_bytes_and_limit();
    let public_inputs = encode_public_inputs(&fixture);
    let mutated_proof = proof_bytes_to_vec(&mismatch_fri_offset(&fixture.proof_bytes()));

    let verifier = RppStarkVerifier::new();
    let error = verifier
        .verify(&params_bytes, &public_inputs, &mutated_proof, node_limit)
        .expect_err("fri payload mismatch should be rejected");

    let (failure, report) = match error {
        RppStarkVerifierError::VerificationFailed { failure, report } => (failure, report),
        other => panic!("unexpected error variant: {other:?}"),
    };

    assert_eq!(
        failure,
        RppStarkVerifyFailure::Serialization {
            context: RppStarkSerializationContext::Fri,
        }
    );
    assert!(
        !report.params_ok() && !report.public_ok(),
        "verification must stop before merkle checks"
    );
}
