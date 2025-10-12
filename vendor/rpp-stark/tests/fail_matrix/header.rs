use insta::assert_snapshot;
use rpp_stark::proof::ser::map_public_to_config_kind;
use rpp_stark::proof::types::VerifyError;
use rpp_stark::proof::verify;
use rpp_stark::ser::SerKind;
use rpp_stark::utils::serialization::ProofBytes;

use super::fixture::header_layout;
use super::{
    flip_header_version, flip_param_digest_byte, flip_public_digest_byte, mismatch_fri_offset,
    mismatch_openings_offset, mismatch_telemetry_flag, mismatch_telemetry_offset,
    FailMatrixFixture,
};

fn hex_bytes(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write;
        let _ = write!(out, "{:02x}", byte);
    }
    out
}

fn header_bytes(bytes: &ProofBytes) -> Vec<u8> {
    let layout = header_layout(bytes.as_slice());
    bytes.as_slice()[..layout.payload_start()].to_vec()
}

#[test]
fn header_rejects_version_bump() {
    let fixture = FailMatrixFixture::new();
    let public_inputs = fixture.public_inputs();
    let config = fixture.config();
    let context = fixture.verifier_context();
    let mutated_bytes = flip_header_version(&fixture.proof());

    let declared_kind = map_public_to_config_kind(public_inputs.kind());
    let report = verify(
        declared_kind,
        &public_inputs,
        &mutated_bytes,
        &config,
        &context,
    );

    let err = report.error.expect("version mismatch must error");

    assert!(matches!(err, VerifyError::VersionMismatch { .. }));

    assert_snapshot!(
        "header_rejects_version_bump",
        hex_bytes(&header_bytes(&mutated_bytes))
    );
}

#[test]
fn header_rejects_param_digest_mismatch() {
    let fixture = FailMatrixFixture::new();
    let public_inputs = fixture.public_inputs();
    let config = fixture.config();
    let context = fixture.verifier_context();
    let mutated_bytes = flip_param_digest_byte(&fixture.proof());

    let declared_kind = map_public_to_config_kind(public_inputs.kind());
    let report = verify(
        declared_kind,
        &public_inputs,
        &mutated_bytes,
        &config,
        &context,
    );

    let error = report.error.expect("expected failure");
    assert!(matches!(error, VerifyError::ParamsHashMismatch));

    assert!(
        !report.params_ok,
        "parameter stage must not advance on params hash mismatch"
    );
    assert!(
        !report.public_ok,
        "public stage must remain false when params hash mismatches"
    );
    assert_eq!(
        report.total_bytes,
        mutated_bytes.as_slice().len() as u64,
        "report must record measured proof length",
    );

    assert_snapshot!(
        "header_rejects_param_digest_mismatch",
        hex_bytes(&header_bytes(&mutated_bytes))
    );
}

#[test]
fn header_rejects_public_digest_mismatch() {
    let fixture = FailMatrixFixture::new();
    let public_inputs = fixture.public_inputs();
    let config = fixture.config();
    let context = fixture.verifier_context();
    let mutated_bytes = flip_public_digest_byte(&fixture.proof_bytes());

    let declared_kind = map_public_to_config_kind(public_inputs.kind());
    let report = verify(
        declared_kind,
        &public_inputs,
        &mutated_bytes,
        &config,
        &context,
    );

    let error = report.error.expect("expected failure");
    assert!(matches!(error, VerifyError::PublicDigestMismatch));
    assert!(
        !report.public_ok,
        "public stage must fail when digest mismatches"
    );
    assert!(
        !report.params_ok,
        "params stage should remain false when public digest mismatches"
    );
    assert_eq!(
        report.total_bytes,
        mutated_bytes.as_slice().len() as u64,
        "report must capture measured proof length",
    );

    assert_snapshot!(
        "header_rejects_public_digest_mismatch",
        hex_bytes(&header_bytes(&mutated_bytes))
    );
}

#[test]
fn header_rejects_excessive_proof_size() {
    let fixture = FailMatrixFixture::new();
    let public_inputs = fixture.public_inputs();
    let config = fixture.config();
    let mut context = fixture.verifier_context();
    context.limits.max_proof_size_bytes = 64;
    let proof_bytes = fixture.proof_bytes();

    let declared_kind = map_public_to_config_kind(public_inputs.kind());
    let report = verify(
        declared_kind,
        &public_inputs,
        &proof_bytes,
        &config,
        &context,
    );

    let error = report.error.expect("expected failure");
    assert!(matches!(error, VerifyError::ProofTooLarge { .. }));
    assert!(
        report.params_ok,
        "params stage must succeed before size check"
    );
    assert!(
        report.public_ok,
        "public stage must succeed before size check"
    );
    assert_eq!(
        report.total_bytes,
        proof_bytes.as_slice().len() as u64,
        "report must capture measured proof length",
    );

    assert_snapshot!(
        "header_rejects_excessive_proof_size",
        hex_bytes(&header_bytes(&proof_bytes))
    );
}

#[test]
fn header_rejects_openings_offset_mismatch() {
    let fixture = FailMatrixFixture::new();
    let public_inputs = fixture.public_inputs();
    let config = fixture.config();
    let context = fixture.verifier_context();
    let mutated_bytes = mismatch_openings_offset(&fixture.proof_bytes());

    let declared_kind = map_public_to_config_kind(public_inputs.kind());
    let report = verify(
        declared_kind,
        &public_inputs,
        &mutated_bytes,
        &config,
        &context,
    );

    let error = report.error.expect("expected failure");
    assert!(matches!(
        error,
        VerifyError::Serialization(SerKind::Telemetry)
    ));
    assert!(
        !report.params_ok,
        "params stage must remain false when telemetry handle is invalid"
    );
    assert!(
        !report.public_ok,
        "public stage must remain false when telemetry handle is invalid"
    );
    assert_eq!(
        report.total_bytes,
        mutated_bytes.as_slice().len() as u64,
        "report must capture measured proof length",
    );

    assert_snapshot!(
        "header_rejects_openings_offset_mismatch",
        hex_bytes(&header_bytes(&mutated_bytes))
    );
}

#[test]
fn header_rejects_fri_offset_mismatch() {
    let fixture = FailMatrixFixture::new();
    let public_inputs = fixture.public_inputs();
    let config = fixture.config();
    let context = fixture.verifier_context();
    let mutated_bytes = mismatch_fri_offset(&fixture.proof_bytes());

    let declared_kind = map_public_to_config_kind(public_inputs.kind());
    let report = verify(
        declared_kind,
        &public_inputs,
        &mutated_bytes,
        &config,
        &context,
    );

    let error = report.error.expect("expected failure");
    assert!(matches!(
        error,
        VerifyError::Serialization(SerKind::Telemetry)
    ));
    assert!(
        !report.params_ok,
        "params stage must remain false when telemetry handle is invalid"
    );
    assert!(
        !report.public_ok,
        "public stage must remain false when telemetry handle is invalid"
    );
    assert_eq!(
        report.total_bytes,
        mutated_bytes.as_slice().len() as u64,
        "report must capture measured proof length",
    );

    assert_snapshot!(
        "header_rejects_fri_offset_mismatch",
        hex_bytes(&header_bytes(&mutated_bytes))
    );
}

#[test]
fn header_rejects_telemetry_offset_mismatch() {
    let fixture = FailMatrixFixture::new();
    let Some(mutated_bytes) = mismatch_telemetry_offset(&fixture.proof_bytes()) else {
        eprintln!("fixture does not expose telemetry; skipping test");
        return;
    };

    let public_inputs = fixture.public_inputs();
    let config = fixture.config();
    let context = fixture.verifier_context();

    let declared_kind = map_public_to_config_kind(public_inputs.kind());
    let report = verify(
        declared_kind,
        &public_inputs,
        &mutated_bytes,
        &config,
        &context,
    );

    let error = report.error.expect("expected failure");
    assert!(matches!(
        error,
        VerifyError::Serialization(SerKind::Telemetry)
    ));
    assert!(
        !report.params_ok,
        "params stage must remain false when telemetry handle is invalid"
    );
    assert!(
        !report.public_ok,
        "public stage must remain false when telemetry handle is invalid"
    );
    assert_eq!(
        report.total_bytes,
        mutated_bytes.as_slice().len() as u64,
        "report must capture measured proof length",
    );

    assert_snapshot!(
        "header_rejects_telemetry_offset_mismatch",
        hex_bytes(&header_bytes(&mutated_bytes))
    );
}

#[test]
fn header_rejects_telemetry_flag_mismatch() {
    let fixture = FailMatrixFixture::new();
    let Some(mutated_bytes) = mismatch_telemetry_flag(&fixture.proof_bytes()) else {
        eprintln!("fixture does not expose telemetry; skipping test");
        return;
    };

    let public_inputs = fixture.public_inputs();
    let config = fixture.config();
    let context = fixture.verifier_context();

    let declared_kind = map_public_to_config_kind(public_inputs.kind());
    let report = verify(
        declared_kind,
        &public_inputs,
        &mutated_bytes,
        &config,
        &context,
    );

    let error = report.error.expect("expected failure");
    assert!(matches!(
        error,
        VerifyError::Serialization(SerKind::Openings)
    ));
    assert!(
        !report.params_ok,
        "params stage must remain false when telemetry flag is inconsistent"
    );
    assert!(
        !report.public_ok,
        "public stage must remain false when telemetry flag is inconsistent"
    );
    assert_eq!(
        report.total_bytes,
        mutated_bytes.as_slice().len() as u64,
        "report must capture measured proof length",
    );

    assert_snapshot!(
        "header_rejects_telemetry_flag_mismatch",
        hex_bytes(&header_bytes(&mutated_bytes))
    );
}
