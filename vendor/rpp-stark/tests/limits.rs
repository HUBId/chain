use rpp_stark::proof::ser::map_public_to_config_kind;
use rpp_stark::proof::types::VerifyError;
use rpp_stark::proof::verifier::verify;

#[allow(dead_code)]
#[path = "fail_matrix/fixture.rs"]
mod fail_matrix_fixture;

use fail_matrix_fixture::FailMatrixFixture;

#[test]
fn proof_size_limit_is_enforced() {
    let fixture = FailMatrixFixture::new();
    let public_inputs = fixture.public_inputs();
    let config = fixture.config();
    let mut context = fixture.verifier_context();
    context.limits.max_proof_size_bytes = 64; // enforce a strict budget
    let proof_bytes = fixture.proof_bytes();
    let declared_kind = map_public_to_config_kind(public_inputs.kind());

    let report = verify(
        declared_kind,
        &public_inputs,
        &proof_bytes,
        &config,
        &context,
    );

    assert!(matches!(
        report.error,
        Some(VerifyError::ProofTooLarge { .. })
    ));
}
