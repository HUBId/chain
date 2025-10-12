#[path = "fail_matrix/fixture.rs"]
mod fail_matrix_fixture;

use fail_matrix_fixture::FailMatrixFixture;
use rpp_stark::proof::public_inputs::ProofKind;
use rpp_stark::proof::ser::serialize_proof;
use rpp_stark::proof::types::{Proof, VerifyError};
use rpp_stark::utils::serialization::ProofBytes;
use rpp_stark::{verify_proof, VerificationVerdict};
use std::collections::BTreeSet;

#[test]
fn indices_not_sorted_err() {
    let fixture = FailMatrixFixture::new();
    let mut proof = fixture.proof();
    {
        let indices = proof.openings_mut().trace_mut().indices_mut();
        assert!(
            indices.len() >= 2,
            "fixture must expose multiple trace indices"
        );
        indices.swap(0, 1);
    }

    assert_rejects_with(&fixture, &proof, VerifyError::IndicesNotSorted);
}

#[test]
fn indices_duplicate_err() {
    let fixture = FailMatrixFixture::new();
    let mut proof = fixture.proof();
    let duplicate_index = {
        let indices = proof.openings_mut().trace_mut().indices_mut();
        assert!(
            indices.len() >= 2,
            "fixture must expose multiple trace indices"
        );
        indices[1] = indices[0];
        indices[0]
    };

    assert_rejects_with(
        &fixture,
        &proof,
        VerifyError::IndicesDuplicate {
            index: duplicate_index,
        },
    );
}

#[test]
fn indices_mismatch_err() {
    let fixture = FailMatrixFixture::new();
    let mut proof = fixture.proof();
    let domain = proof.fri_proof().initial_domain_size as u32;
    assert!(domain > 0, "domain size must be positive");

    {
        let indices = proof.openings_mut().trace_mut().indices_mut();
        assert!(!indices.is_empty(), "fixture must expose trace indices");

        let existing: BTreeSet<u32> = indices.iter().copied().collect();
        let mut candidate = 0u32;
        while existing.contains(&candidate) {
            candidate = candidate
                .checked_add(1)
                .expect("domain search should not overflow");
            assert!(candidate < domain, "domain must contain unused positions");
        }

        indices[0] = candidate;
        indices.sort_unstable();
        assert!(
            indices.windows(2).all(|pair| pair[0] != pair[1]),
            "mutation must keep indices unique"
        );
    }

    assert_rejects_with(&fixture, &proof, VerifyError::IndicesMismatch);
}

fn assert_rejects_with(fixture: &FailMatrixFixture, proof: &Proof, expected: VerifyError) {
    let bytes = serialize_proof(proof).expect("serialize mutated proof");
    let proof_bytes = ProofBytes::new(bytes);
    let public_inputs = fixture.public_inputs();
    let config = fixture.config();
    let context = fixture.verifier_context();

    let verdict = verify_proof(
        ProofKind::Execution,
        &public_inputs,
        &proof_bytes,
        &config,
        &context,
    )
    .expect("verifier invocation");

    match verdict {
        VerificationVerdict::Reject(error) => assert_eq!(error, expected),
        VerificationVerdict::Accept => panic!("verifier unexpectedly accepted mutated proof"),
    }
}
