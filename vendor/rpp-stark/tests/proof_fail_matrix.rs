mod _fixtures;

use _fixtures::{
    clear_composition_commit_flag, clear_composition_openings_section, flip_composition_root_byte,
    flip_header_version, flip_param_digest_byte, flip_public_digest_byte, flip_trace_root_byte,
    mini_fixture, mismatch_fri_offset, mismatch_telemetry_flag, reencode_proof, FailMatrixFixture,
};
use rpp_stark::proof::public_inputs::PublicInputs;
use rpp_stark::proof::ser::map_public_to_config_kind;
use rpp_stark::proof::types::{MerkleSection, VerifyError};
use rpp_stark::proof::verifier::verify;

fn declared_kind(inputs: &PublicInputs<'_>) -> rpp_stark::config::ProofKind {
    map_public_to_config_kind(inputs.kind())
}

fn tamper_indices_empty(
    fixture: &FailMatrixFixture,
) -> rpp_stark::utils::serialization::ProofBytes {
    let mut proof = fixture.proof();
    proof.openings_mut().trace_mut().indices_mut().clear();
    reencode_proof(&mut proof)
}

fn tamper_indices_unsorted(
    fixture: &FailMatrixFixture,
) -> rpp_stark::utils::serialization::ProofBytes {
    let mut proof = fixture.proof();
    let indices = proof.openings_mut().trace_mut().indices_mut();
    if indices.len() >= 2 {
        indices.swap(0, 1);
    }
    reencode_proof(&mut proof)
}

fn tamper_indices_duplicate(
    fixture: &FailMatrixFixture,
) -> rpp_stark::utils::serialization::ProofBytes {
    let mut proof = fixture.proof();
    let indices = proof.openings_mut().trace_mut().indices_mut();
    if indices.len() >= 2 {
        indices[1] = indices[0];
    }
    reencode_proof(&mut proof)
}

fn tamper_indices_mismatch(
    fixture: &FailMatrixFixture,
) -> rpp_stark::utils::serialization::ProofBytes {
    let mut proof = fixture.proof();
    if let Some(first) = proof.openings_mut().trace_mut().indices_mut().first_mut() {
        *first = first.saturating_add(1);
    }
    reencode_proof(&mut proof)
}

fn tamper_merkle_path(fixture: &FailMatrixFixture) -> rpp_stark::utils::serialization::ProofBytes {
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
    reencode_proof(&mut proof)
}

fn tamper_fold_challenge(
    fixture: &FailMatrixFixture,
) -> rpp_stark::utils::serialization::ProofBytes {
    let mut proof = fixture.proof();
    if let Some(challenge) = proof.fri_proof_mut().fold_challenges.first_mut() {
        challenge.0 ^= 1;
    }
    reencode_proof(&mut proof)
}

fn drop_composition_commit(
    fixture: &FailMatrixFixture,
) -> rpp_stark::utils::serialization::ProofBytes {
    clear_composition_commit_flag(&fixture.proof_bytes())
}

fn drop_composition_openings(
    fixture: &FailMatrixFixture,
) -> rpp_stark::utils::serialization::ProofBytes {
    clear_composition_openings_section(&fixture.proof_bytes())
}

#[test]
fn failure_cases_report_expected_flags() {
    let fixture = mini_fixture();

    // Version mismatch.
    {
        let public_inputs = fixture.public_inputs();
        let report = verify(
            declared_kind(&public_inputs),
            &public_inputs,
            &flip_header_version(&fixture.proof()),
            &fixture.config(),
            &fixture.verifier_context(),
        );
        assert!(matches!(
            report.error,
            Some(VerifyError::VersionMismatch { .. })
        ));
        assert!(
            !report.params_ok
                && !report.public_ok
                && !report.merkle_ok
                && !report.fri_ok
                && !report.composition_ok
        );
    }

    // Parameter digest mismatch.
    {
        let public_inputs = fixture.public_inputs();
        let report = verify(
            declared_kind(&public_inputs),
            &public_inputs,
            &flip_param_digest_byte(&fixture.proof()),
            &fixture.config(),
            &fixture.verifier_context(),
        );
        assert!(matches!(
            report.error,
            Some(VerifyError::ParamsHashMismatch)
        ));
        assert!(
            !report.params_ok
                && !report.public_ok
                && !report.merkle_ok
                && !report.fri_ok
                && !report.composition_ok
        );
    }

    // Public digest mismatch.
    {
        let public_inputs = fixture.public_inputs();
        let report = verify(
            declared_kind(&public_inputs),
            &public_inputs,
            &flip_public_digest_byte(&fixture.proof_bytes()),
            &fixture.config(),
            &fixture.verifier_context(),
        );
        assert!(matches!(
            report.error,
            Some(VerifyError::PublicDigestMismatch)
        ));
        assert!(
            !report.params_ok
                && !report.public_ok
                && !report.merkle_ok
                && !report.fri_ok
                && !report.composition_ok
        );
    }

    // Size gate.
    {
        let public_inputs = fixture.public_inputs();
        let mut context = fixture.verifier_context();
        context.limits.max_proof_size_bytes = 64;
        let report = verify(
            declared_kind(&public_inputs),
            &public_inputs,
            &fixture.proof_bytes(),
            &fixture.config(),
            &context,
        );
        assert!(matches!(
            report.error,
            Some(VerifyError::ProofTooLarge { .. })
        ));
        assert!(report.params_ok, "size gate params flag {:?}", report);
        assert!(report.public_ok, "size gate public flag {:?}", report);
        assert!(report.merkle_ok, "size gate merkle flag {:?}", report);
        assert!(
            report.composition_ok,
            "size gate composition flag {:?}",
            report
        );
        assert!(!report.fri_ok);
    }

    // Indices empty.
    {
        let public_inputs = fixture.public_inputs();
        let report = verify(
            declared_kind(&public_inputs),
            &public_inputs,
            &tamper_indices_empty(fixture),
            &fixture.config(),
            &fixture.verifier_context(),
        );
        assert!(matches!(report.error, Some(VerifyError::EmptyOpenings)));
        assert!(
            report.params_ok && report.public_ok,
            "unexpected report: {:?}",
            report
        );
        assert!(
            !report.merkle_ok && !report.fri_ok && !report.composition_ok,
            "unexpected report: {:?}",
            report
        );
    }

    // Indices unsorted.
    {
        let public_inputs = fixture.public_inputs();
        let report = verify(
            declared_kind(&public_inputs),
            &public_inputs,
            &tamper_indices_unsorted(fixture),
            &fixture.config(),
            &fixture.verifier_context(),
        );
        assert!(matches!(report.error, Some(VerifyError::IndicesNotSorted)));
        assert!(
            report.params_ok && report.public_ok,
            "unexpected report: {:?}",
            report
        );
        assert!(
            !report.merkle_ok && !report.fri_ok && !report.composition_ok,
            "unexpected report: {:?}",
            report
        );
    }

    // Indices duplicate.
    {
        let public_inputs = fixture.public_inputs();
        let report = verify(
            declared_kind(&public_inputs),
            &public_inputs,
            &tamper_indices_duplicate(fixture),
            &fixture.config(),
            &fixture.verifier_context(),
        );
        assert!(matches!(
            report.error,
            Some(VerifyError::IndicesDuplicate { .. })
        ));
        assert!(
            report.params_ok && report.public_ok,
            "unexpected report: {:?}",
            report
        );
        assert!(
            !report.merkle_ok && !report.fri_ok && !report.composition_ok,
            "unexpected report: {:?}",
            report
        );
    }

    // Indices mismatch.
    {
        let public_inputs = fixture.public_inputs();
        let report = verify(
            declared_kind(&public_inputs),
            &public_inputs,
            &tamper_indices_mismatch(fixture),
            &fixture.config(),
            &fixture.verifier_context(),
        );
        assert!(matches!(report.error, Some(VerifyError::IndicesMismatch)));
        assert!(
            report.params_ok && report.public_ok,
            "unexpected report: {:?}",
            report
        );
        assert!(
            !report.merkle_ok && !report.fri_ok && !report.composition_ok,
            "unexpected report: {:?}",
            report
        );
    }

    // Trace root mismatch.
    {
        let public_inputs = fixture.public_inputs();
        let report = verify(
            declared_kind(&public_inputs),
            &public_inputs,
            &flip_trace_root_byte(&fixture.proof_bytes()),
            &fixture.config(),
            &fixture.verifier_context(),
        );
        assert!(matches!(
            report.error,
            Some(VerifyError::RootMismatch {
                section: MerkleSection::TraceCommit,
            })
        ));
        assert!(
            !report.params_ok
                && !report.public_ok
                && !report.merkle_ok
                && !report.fri_ok
                && !report.composition_ok
        );
    }

    // Composition root mismatch.
    {
        let public_inputs = fixture.public_inputs();
        let report = verify(
            declared_kind(&public_inputs),
            &public_inputs,
            &flip_composition_root_byte(&fixture.proof_bytes()),
            &fixture.config(),
            &fixture.verifier_context(),
        );
        assert!(matches!(
            report.error,
            Some(VerifyError::RootMismatch {
                section: MerkleSection::CompositionCommit,
            })
        ));
        assert!(
            !report.params_ok
                && !report.public_ok
                && !report.merkle_ok
                && !report.fri_ok
                && !report.composition_ok
        );
    }

    // Merkle path corruption.
    {
        let public_inputs = fixture.public_inputs();
        let report = verify(
            declared_kind(&public_inputs),
            &public_inputs,
            &tamper_merkle_path(fixture),
            &fixture.config(),
            &fixture.verifier_context(),
        );
        assert!(matches!(
            report.error,
            Some(VerifyError::MerkleVerifyFailed {
                section: MerkleSection::TraceCommit,
            })
        ));
        assert!(
            report.params_ok && report.public_ok,
            "unexpected report: {:?}",
            report
        );
        assert!(
            !report.merkle_ok && !report.fri_ok && !report.composition_ok,
            "unexpected report: {:?}",
            report
        );
    }

    // Telemetry handle corruption should fail before params stage completes.
    if let Some(mutated) = mismatch_telemetry_flag(&fixture.proof_bytes()) {
        let public_inputs = fixture.public_inputs();
        let report = verify(
            declared_kind(&public_inputs),
            &public_inputs,
            &mutated,
            &fixture.config(),
            &fixture.verifier_context(),
        );
        assert!(report.error.is_some());
        assert!(!report.params_ok && !report.public_ok);
    }

    // FRI header mismatch should trip before FRI verification.
    {
        let public_inputs = fixture.public_inputs();
        let report = verify(
            declared_kind(&public_inputs),
            &public_inputs,
            &mismatch_fri_offset(&fixture.proof_bytes()),
            &fixture.config(),
            &fixture.verifier_context(),
        );
        assert!(report.error.is_some());
        assert!(!report.params_ok && !report.public_ok);
    }

    // FRI fold-challenge corruption.
    {
        let public_inputs = fixture.public_inputs();
        let report = verify(
            declared_kind(&public_inputs),
            &public_inputs,
            &tamper_fold_challenge(fixture),
            &fixture.config(),
            &fixture.verifier_context(),
        );
        assert!(matches!(
            report.error,
            Some(VerifyError::FriVerifyFailed { .. })
        ));
        assert!(
            report.params_ok && report.public_ok,
            "unexpected report: {:?}",
            report
        );
        assert!(
            !report.merkle_ok && !report.fri_ok && !report.composition_ok,
            "unexpected report: {:?}",
            report
        );
    }

    // Composition commit removed.
    {
        let public_inputs = fixture.public_inputs();
        let report = verify(
            declared_kind(&public_inputs),
            &public_inputs,
            &drop_composition_commit(fixture),
            &fixture.config(),
            &fixture.verifier_context(),
        );
        assert!(
            matches!(
                report.error,
                Some(VerifyError::CompositionInconsistent { .. })
            ),
            "unexpected report: {:?}",
            report
        );
        assert!(
            !report.params_ok && !report.public_ok,
            "unexpected report: {:?}",
            report
        );
        assert!(
            !report.merkle_ok && !report.fri_ok && !report.composition_ok,
            "unexpected report: {:?}",
            report
        );
    }

    // Composition openings removed.
    {
        let public_inputs = fixture.public_inputs();
        let report = verify(
            declared_kind(&public_inputs),
            &public_inputs,
            &drop_composition_openings(fixture),
            &fixture.config(),
            &fixture.verifier_context(),
        );
        assert!(
            matches!(
                report.error,
                Some(VerifyError::CompositionInconsistent { .. })
            ),
            "unexpected report: {:?}",
            report
        );
        assert!(
            !report.params_ok && !report.public_ok,
            "unexpected report: {:?}",
            report
        );
        assert!(
            !report.merkle_ok && !report.fri_ok && !report.composition_ok,
            "unexpected report: {:?}",
            report
        );
    }
}
