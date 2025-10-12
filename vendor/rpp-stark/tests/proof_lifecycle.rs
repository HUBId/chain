use std::convert::TryInto;

use rpp_stark::config::{
    build_proof_system_config, build_prover_context, build_verifier_context, compute_param_digest,
    ChunkingPolicy, CommonIdentifiers, ParamDigest, ProfileConfig, ProofSystemConfig,
    ProverContext, ThreadPoolProfile, VerifierContext, COMMON_IDENTIFIERS, PROFILE_STANDARD_CONFIG,
};
use rpp_stark::field::prime_field::{CanonicalSerialize, FieldElementOps};
use rpp_stark::field::FieldElement;
use rpp_stark::proof::public_inputs::{
    ExecutionHeaderV1, ProofKind, PublicInputVersion, PublicInputs,
};
use rpp_stark::proof::ser::{
    compute_integrity_digest, compute_public_digest, map_public_to_config_kind, serialize_proof,
};
use rpp_stark::proof::types::{MerkleSection, Proof, VerifyError, VerifyReport, PROOF_VERSION};
use rpp_stark::utils::serialization::{DigestBytes, ProofBytes, WitnessBlob};
use rpp_stark::{
    batch_verify, generate_proof, verify_proof, BatchProofRecord, BatchVerificationOutcome,
    BlockContext, StarkError, VerificationVerdict,
};

#[allow(dead_code)]
#[path = "fail_matrix/fixture.rs"]
mod fail_matrix_fixture;

use fail_matrix_fixture::FailMatrixFixture;

struct TestSetup {
    config: ProofSystemConfig,
    prover_context: ProverContext,
    verifier_context: VerifierContext,
    header: ExecutionHeaderV1,
    body: Vec<u8>,
    witness: Vec<u8>,
}

impl TestSetup {
    fn new() -> Self {
        let profile: ProfileConfig = PROFILE_STANDARD_CONFIG.clone();
        let common: CommonIdentifiers = COMMON_IDENTIFIERS.clone();
        let param_digest = compute_param_digest(&profile, &common);
        let config = build_proof_system_config(&profile, &param_digest);
        let prover_context = build_prover_context(
            &profile,
            &common,
            &param_digest,
            ThreadPoolProfile::SingleThread,
            ChunkingPolicy {
                min_chunk_items: 4,
                max_chunk_items: 32,
                stride: 1,
            },
        );
        let verifier_context = build_verifier_context(&profile, &common, &param_digest, None);

        let seed = FieldElement::from(3u64);
        let length = 128usize;
        let header = ExecutionHeaderV1 {
            version: PublicInputVersion::V1,
            program_digest: DigestBytes { bytes: [0u8; 32] },
            trace_length: length as u32,
            trace_width: 1,
        };
        let body = seed
            .to_bytes()
            .expect("fixture seed must be canonical")
            .to_vec();
        let witness = build_witness(seed, length);

        Self {
            config,
            prover_context,
            verifier_context,
            header,
            body,
            witness,
        }
    }
}

const LFSR_ALPHA: u64 = 5;
const LFSR_BETA: u64 = 7;

fn build_witness(seed: FieldElement, rows: usize) -> Vec<u8> {
    let alpha = FieldElement::from(LFSR_ALPHA);
    let beta = FieldElement::from(LFSR_BETA);
    let mut column = Vec::with_capacity(rows);
    let mut state = seed;
    column.push(state);
    for _ in 1..rows {
        state = state.mul(&alpha).add(&beta);
        column.push(state);
    }

    let mut bytes = Vec::with_capacity(20 + rows * 8);
    bytes.extend_from_slice(&(rows as u32).to_le_bytes());
    bytes.extend_from_slice(&1u32.to_le_bytes());
    bytes.extend_from_slice(&0u32.to_le_bytes());
    bytes.extend_from_slice(&0u32.to_le_bytes());
    bytes.extend_from_slice(&0u32.to_le_bytes());
    for value in column {
        let encoded = value.to_bytes().expect("fixture values must be canonical");
        bytes.extend_from_slice(&encoded);
    }
    bytes
}

fn make_public_inputs<'a>(header: &'a ExecutionHeaderV1, body: &'a [u8]) -> PublicInputs<'a> {
    PublicInputs::Execution {
        header: header.clone(),
        body,
    }
}

#[test]
fn verify_report_deserializes_with_legacy_payloads() {
    let empty: VerifyReport = serde_json::from_str("{}").expect("empty payload should deserialize");
    assert_eq!(
        empty,
        VerifyReport::default(),
        "empty payload must default fields"
    );

    let legacy_payload = serde_json::json!({
        "params_ok": true,
        "public_ok": true,
        "total_bytes": 99u64,
        "proof": null,
    });
    let legacy: VerifyReport =
        serde_json::from_value(legacy_payload).expect("legacy payload should deserialize");
    assert!(legacy.params_ok, "legacy payload must preserve params flag");
    assert!(legacy.public_ok, "legacy payload must preserve public flag");
    assert_eq!(legacy.total_bytes, 99);
    assert_eq!(legacy.error, None);
    assert!(
        !legacy.merkle_ok && !legacy.fri_ok && !legacy.composition_ok,
        "missing stage flags must default to false",
    );
}

#[test]
fn proof_lifecycle_accepts_valid_inputs() {
    let setup = TestSetup::new();
    let witness = WitnessBlob {
        bytes: &setup.witness,
    };

    let public_inputs = make_public_inputs(&setup.header, &setup.body);
    let proof = generate_proof(
        ProofKind::Execution,
        &public_inputs,
        witness,
        &setup.config,
        &setup.prover_context,
    )
    .expect("proof generation succeeds");
    let decoded = rpp_stark::Proof::from_bytes(proof.as_slice()).expect("decode proof");
    assert_eq!(
        decoded.fri_proof().queries.len(),
        setup.config.profile.fri_queries as usize,
        "unexpected query count"
    );

    let openings = decoded.openings();
    assert_eq!(
        openings.trace().indices().len(),
        openings.trace().leaves().len(),
        "trace openings must align",
    );
    assert!(
        openings
            .trace()
            .leaves()
            .iter()
            .all(|leaf| !leaf.is_empty()),
        "trace leaves must contain bytes",
    );
    let composition = openings
        .composition()
        .expect("composition openings present");
    assert_eq!(
        composition.indices().len(),
        composition.leaves().len(),
        "composition openings must align",
    );
    assert!(
        composition.leaves().iter().all(|leaf| !leaf.is_empty()),
        "composition leaves must contain bytes",
    );

    let verify_inputs = make_public_inputs(&setup.header, &setup.body);
    let verdict = verify_proof(
        ProofKind::Execution,
        &verify_inputs,
        &proof,
        &setup.config,
        &setup.verifier_context,
    )
    .expect("verification verdict");
    match verdict {
        VerificationVerdict::Accept => {}
        VerificationVerdict::Reject(err) => {
            panic!("expected verification to accept, got {:?}", err);
        }
    }
}

fn decode_proof(bytes: &ProofBytes) -> Proof {
    Proof::from_bytes(bytes.as_slice()).expect("decode proof")
}

fn reencode_proof(proof: &mut Proof) -> ProofBytes {
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

    ProofBytes::new(serialize_proof(proof).expect("serialize proof"))
}

#[test]
fn verification_report_records_total_bytes_and_telemetry() {
    let setup = TestSetup::new();
    let witness = WitnessBlob {
        bytes: &setup.witness,
    };

    let public_inputs = make_public_inputs(&setup.header, &setup.body);
    let proof_bytes = generate_proof(
        ProofKind::Execution,
        &public_inputs,
        witness,
        &setup.config,
        &setup.prover_context,
    )
    .expect("proof generation succeeds");

    let declared_kind = map_public_to_config_kind(ProofKind::Execution);
    let report = rpp_stark::proof::verifier::verify(
        declared_kind,
        &public_inputs,
        &proof_bytes,
        &setup.config,
        &setup.verifier_context,
    );

    assert!(
        report.error.is_none(),
        "expected verification to accept, got {:?}",
        report.error
    );
    assert_eq!(
        report.total_bytes as usize,
        proof_bytes.as_slice().len(),
        "reported total bytes must match input length"
    );

    let decoded_proof = decode_proof(&proof_bytes);
    assert!(
        decoded_proof.has_telemetry(),
        "fixture proof should include telemetry"
    );
    let payload = decoded_proof
        .serialize_payload()
        .expect("serialize payload");
    let header = decoded_proof
        .serialize_header(&payload)
        .expect("serialize header");
    let expected_body_length = (payload.len() + 32) as u32;
    assert_eq!(
        decoded_proof.telemetry_frame().body_length(),
        expected_body_length,
        "telemetry body length must match payload"
    );
    let expected_header_length = header.len() as u32;
    assert_eq!(
        decoded_proof.telemetry_frame().header_length(),
        expected_header_length,
        "telemetry header length must match header bytes"
    );
    let telemetry = decoded_proof.telemetry_frame();
    assert_eq!(
        u64::from(telemetry.header_length()) + u64::from(telemetry.body_length()),
        report.total_bytes + 32,
        "telemetry lengths must sum to total bytes plus the integrity digest"
    );

    let mut canonical = decoded_proof.clone_using_parts();
    let canonical_telemetry = canonical.telemetry_frame_mut();
    canonical_telemetry.set_header_length(0);
    canonical_telemetry.set_body_length(0);
    canonical_telemetry.set_integrity_digest(DigestBytes { bytes: [0u8; 32] });
    let canonical_payload = canonical
        .serialize_payload()
        .expect("serialize canonical payload");
    let canonical_header = canonical
        .serialize_header(&canonical_payload)
        .expect("serialize canonical header");
    let expected_digest = compute_integrity_digest(&canonical_header, &canonical_payload);
    assert_eq!(
        decoded_proof.telemetry_frame().integrity_digest().bytes,
        expected_digest,
        "telemetry integrity digest must remain stable"
    );
}

#[test]
fn verification_rejects_tampered_telemetry_fields() {
    let setup = TestSetup::new();
    let witness = WitnessBlob {
        bytes: &setup.witness,
    };
    let public_inputs = make_public_inputs(&setup.header, &setup.body);
    let proof_bytes = generate_proof(
        ProofKind::Execution,
        &public_inputs,
        witness,
        &setup.config,
        &setup.prover_context,
    )
    .expect("proof generation succeeds");

    let declared_kind = map_public_to_config_kind(ProofKind::Execution);

    let mut tampered_header = decode_proof(&proof_bytes);
    {
        let telemetry = tampered_header.telemetry_frame_mut();
        let updated = telemetry.header_length().saturating_add(4);
        telemetry.set_header_length(updated);
    }
    let tampered_header_bytes = ProofBytes::new(
        serialize_proof(&tampered_header).expect("serialize tampered header proof"),
    );
    let header_report = rpp_stark::proof::verifier::verify(
        declared_kind,
        &public_inputs,
        &tampered_header_bytes,
        &setup.config,
        &setup.verifier_context,
    );
    match header_report.error {
        Some(VerifyError::HeaderLengthMismatch { declared, actual }) => {
            assert_eq!(
                declared,
                tampered_header.telemetry_frame().header_length(),
                "report must echo tampered header length"
            );
            assert_ne!(declared, actual, "mismatch must surface differing lengths");
        }
        other => panic!("expected header length mismatch, got {:?}", other),
    }

    let mut tampered_digest = decode_proof(&proof_bytes);
    tampered_digest
        .telemetry_frame_mut()
        .integrity_digest_mut()
        .bytes[0] ^= 0x1;
    let tampered_digest_bytes = ProofBytes::new(
        serialize_proof(&tampered_digest).expect("serialize tampered digest proof"),
    );
    let digest_report = rpp_stark::proof::verifier::verify(
        declared_kind,
        &public_inputs,
        &tampered_digest_bytes,
        &setup.config,
        &setup.verifier_context,
    );
    assert!(matches!(
        digest_report.error,
        Some(VerifyError::IntegrityDigestMismatch)
    ));
}

#[test]
fn verification_report_flags_param_digest_flip() {
    let setup = TestSetup::new();
    let witness = WitnessBlob {
        bytes: &setup.witness,
    };

    let public_inputs = make_public_inputs(&setup.header, &setup.body);
    let proof_bytes = generate_proof(
        ProofKind::Execution,
        &public_inputs,
        witness,
        &setup.config,
        &setup.prover_context,
    )
    .expect("proof generation succeeds");

    let mut proof = decode_proof(&proof_bytes);
    mutate_param_digest(&mut proof);
    let mutated_bytes = reencode_proof(&mut proof);

    let declared_kind = map_public_to_config_kind(ProofKind::Execution);
    let report = rpp_stark::proof::verifier::verify(
        declared_kind,
        &public_inputs,
        &mutated_bytes,
        &setup.config,
        &setup.verifier_context,
    );

    assert!(matches!(
        report.error,
        Some(VerifyError::ParamsHashMismatch)
    ));
    assert!(!report.params_ok, "params stage must fail");
}

#[test]
fn verification_report_marks_header_flags_on_success() {
    let fixture = FailMatrixFixture::new();
    let public_inputs = fixture.public_inputs();
    let config = fixture.config();
    let context = fixture.verifier_context();
    let proof_bytes = fixture.proof_bytes();
    let declared_kind = map_public_to_config_kind(public_inputs.kind());

    let report = rpp_stark::proof::verifier::verify(
        declared_kind,
        &public_inputs,
        &proof_bytes,
        &config,
        &context,
    );

    assert!(report.error.is_none(), "expected proof to succeed");
    assert!(report.params_ok, "params stage should succeed");
    assert!(report.public_ok, "public stage should succeed");
    assert_eq!(
        (report.merkle_ok, report.composition_ok, report.fri_ok),
        (true, true, true),
        "all verifier stages should succeed on a valid proof",
    );
    assert_eq!(
        report.total_bytes as usize,
        proof_bytes.as_slice().len(),
        "report must capture proof length",
    );
}

#[test]
fn verification_report_flags_public_stage_failure() {
    let fixture = FailMatrixFixture::new();
    let public_inputs = fixture.public_inputs();
    let config = fixture.config();
    let context = fixture.verifier_context();
    let mut mutated_proof = fixture.proof();
    if let Some(byte) = mutated_proof.public_inputs_mut().first_mut() {
        *byte ^= 0x01;
    } else {
        panic!("fixture must contain public input bytes");
    }
    let recomputed_digest = compute_public_digest(mutated_proof.public_inputs());
    mutated_proof.public_digest_mut().bytes = recomputed_digest;
    let mutated_bytes = reencode_proof(&mut mutated_proof);
    let declared_kind = map_public_to_config_kind(public_inputs.kind());

    let report = rpp_stark::proof::verifier::verify(
        declared_kind,
        &public_inputs,
        &mutated_bytes,
        &config,
        &context,
    );

    assert!(matches!(
        report.error,
        Some(VerifyError::PublicInputMismatch)
    ));
    assert!(
        report.params_ok,
        "parameter stage should succeed even when public inputs mismatch"
    );
    assert!(!report.public_ok, "public stage must fail");
    assert!(
        !report.merkle_ok,
        "merkle stage should not execute after public failure"
    );
    assert!(
        !report.composition_ok,
        "composition stage should remain false after public failure"
    );
    assert!(
        !report.fri_ok,
        "fri stage should remain false after public failure"
    );
}

fn mutate_header_trace_root(bytes: &ProofBytes) -> ProofBytes {
    let mut mutated = bytes.as_slice().to_vec();
    let offset = header_trace_root_offset(&mutated);
    mutated[offset] ^= 0x1;
    ProofBytes::new(mutated)
}

fn mutate_header_composition_root(bytes: &ProofBytes) -> ProofBytes {
    let mut mutated = bytes.as_slice().to_vec();
    let mut cursor = header_trace_root_offset(&mutated);
    cursor += 32; // trace commitment digest

    let binding_len = u32::from_le_bytes(
        mutated[cursor..cursor + 4]
            .try_into()
            .expect("binding length"),
    ) as usize;
    cursor += 4;

    let mut binding_cursor = cursor;
    binding_cursor += 1; // kind
    binding_cursor += 32; // air spec id
    let public_len = u32::from_le_bytes(
        mutated[binding_cursor..binding_cursor + 4]
            .try_into()
            .expect("public length"),
    ) as usize;
    binding_cursor += 4 + public_len;

    let flag = mutated[binding_cursor];
    assert_eq!(flag, 1, "expected composition commit to be present");
    binding_cursor += 1;
    assert!(
        binding_cursor < cursor + binding_len,
        "composition commit digest missing"
    );
    mutated[binding_cursor] ^= 0x1;
    ProofBytes::new(mutated)
}

fn mutate_param_digest(proof: &mut Proof) {
    let mut updated = *proof.params_hash().as_bytes();
    updated[0] ^= 0x1;
    *proof.params_hash_mut() = ParamDigest(DigestBytes { bytes: updated });
}

fn mutate_public_digest(bytes: &ProofBytes) -> ProofBytes {
    let mut mutated = bytes.as_slice().to_vec();
    let offset = header_trace_root_offset(&mutated) - 32;
    mutated[offset] ^= 0x1;
    ProofBytes::new(mutated)
}

fn header_trace_root_offset(_bytes: &[u8]) -> usize {
    let mut cursor = 0usize;
    cursor += 2; // version
    cursor += 32; // params hash
    cursor += 32; // public digest
    cursor
}

#[test]
fn proof_decode_rejects_public_digest_tampering() {
    let setup = TestSetup::new();
    let witness = WitnessBlob {
        bytes: &setup.witness,
    };
    let public_inputs = make_public_inputs(&setup.header, &setup.body);
    let proof_bytes = generate_proof(
        ProofKind::Execution,
        &public_inputs,
        witness,
        &setup.config,
        &setup.prover_context,
    )
    .expect("proof generation succeeds");

    let mutated = mutate_public_digest(&proof_bytes);
    let decode_error =
        rpp_stark::Proof::from_bytes(mutated.as_slice()).expect_err("decode must fail");
    assert!(matches!(decode_error, VerifyError::PublicDigestMismatch));

    let declared_kind = map_public_to_config_kind(ProofKind::Execution);
    let report = rpp_stark::proof::verifier::verify(
        declared_kind,
        &public_inputs,
        &mutated,
        &setup.config,
        &setup.verifier_context,
    );
    assert!(matches!(
        report.error,
        Some(VerifyError::PublicDigestMismatch)
    ));
    assert!(
        !report.params_ok && !report.public_ok,
        "header digest mismatch should abort before params/public stages"
    );
    assert_eq!(
        report.total_bytes as usize,
        mutated.as_slice().len(),
        "report should still record total input bytes"
    );
}

#[test]
fn verification_rejects_mismatched_public_inputs() {
    let setup = TestSetup::new();
    let witness = WitnessBlob {
        bytes: &setup.witness,
    };
    let public_inputs = make_public_inputs(&setup.header, &setup.body);
    let proof = generate_proof(
        ProofKind::Execution,
        &public_inputs,
        witness,
        &setup.config,
        &setup.prover_context,
    )
    .expect("proof generation succeeds");

    let mut mismatched_header = setup.header.clone();
    mismatched_header.trace_length += 1;
    let bad_inputs = make_public_inputs(&mismatched_header, &setup.body);
    let verdict = verify_proof(
        ProofKind::Execution,
        &bad_inputs,
        &proof,
        &setup.config,
        &setup.verifier_context,
    )
    .expect("verification verdict");
    assert!(matches!(
        verdict,
        VerificationVerdict::Reject(VerifyError::PublicInputMismatch)
    ));

    let record = BatchProofRecord {
        kind: ProofKind::Execution,
        public_inputs: &bad_inputs,
        proof_bytes: &proof,
    };
    let block_context = BlockContext {
        block_height: 7,
        previous_state_root: [1u8; 32],
        network_id: 7,
    };
    let outcome = batch_verify(
        &block_context,
        &[record],
        &setup.config,
        &setup.verifier_context,
    )
    .expect("batch verification");
    assert!(matches!(
        outcome,
        BatchVerificationOutcome::Reject {
            failing_proof_index: 0,
            error: VerifyError::PublicInputMismatch,
        }
    ));
}

#[test]
fn verification_rejects_tampered_header_trace_root() {
    let setup = TestSetup::new();
    let witness = WitnessBlob {
        bytes: &setup.witness,
    };
    let public_inputs = make_public_inputs(&setup.header, &setup.body);
    let proof_bytes = generate_proof(
        ProofKind::Execution,
        &public_inputs,
        witness,
        &setup.config,
        &setup.prover_context,
    )
    .expect("proof generation succeeds");

    let tampered_bytes = mutate_header_trace_root(&proof_bytes);
    let decode_err =
        rpp_stark::Proof::from_bytes(tampered_bytes.as_slice()).expect_err("decode must fail");
    assert!(matches!(
        decode_err,
        VerifyError::RootMismatch {
            section: MerkleSection::TraceCommit
        }
    ));
    let verify_inputs = make_public_inputs(&setup.header, &setup.body);
    let verdict = verify_proof(
        ProofKind::Execution,
        &verify_inputs,
        &tampered_bytes,
        &setup.config,
        &setup.verifier_context,
    );

    match verdict {
        Ok(VerificationVerdict::Reject(VerifyError::RootMismatch {
            section: MerkleSection::TraceCommit,
        })) => {}
        Ok(other) => panic!("unexpected verdict: {other:?}"),
        Err(error) => panic!("unexpected StarkError: {error:?}"),
    }
}

#[test]
fn verification_report_flags_header_trace_root_mismatch() {
    let setup = TestSetup::new();
    let witness = WitnessBlob {
        bytes: &setup.witness,
    };
    let public_inputs = make_public_inputs(&setup.header, &setup.body);
    let proof_bytes = generate_proof(
        ProofKind::Execution,
        &public_inputs,
        witness,
        &setup.config,
        &setup.prover_context,
    )
    .expect("proof generation succeeds");

    let tampered = mutate_header_trace_root(&proof_bytes);
    let declared_kind = map_public_to_config_kind(ProofKind::Execution);
    let report = rpp_stark::proof::verifier::verify(
        declared_kind,
        &public_inputs,
        &tampered,
        &setup.config,
        &setup.verifier_context,
    );
    let err = report
        .error
        .as_ref()
        .expect("root mismatch must abort decoding");
    assert!(matches!(
        err,
        VerifyError::RootMismatch {
            section: MerkleSection::TraceCommit
        }
    ));
}

#[test]
fn verification_rejects_tampered_header_composition_root() {
    let setup = TestSetup::new();
    let witness = WitnessBlob {
        bytes: &setup.witness,
    };
    let public_inputs = make_public_inputs(&setup.header, &setup.body);
    let proof_bytes = generate_proof(
        ProofKind::Execution,
        &public_inputs,
        witness,
        &setup.config,
        &setup.prover_context,
    )
    .expect("proof generation succeeds");

    let tampered_bytes = mutate_header_composition_root(&proof_bytes);
    let decode_err =
        rpp_stark::Proof::from_bytes(tampered_bytes.as_slice()).expect_err("decode must fail");
    assert!(matches!(
        decode_err,
        VerifyError::RootMismatch {
            section: MerkleSection::CompositionCommit
        }
    ));
    let verify_inputs = make_public_inputs(&setup.header, &setup.body);
    let verdict = verify_proof(
        ProofKind::Execution,
        &verify_inputs,
        &tampered_bytes,
        &setup.config,
        &setup.verifier_context,
    );

    match verdict {
        Ok(VerificationVerdict::Reject(VerifyError::RootMismatch {
            section: MerkleSection::CompositionCommit,
        })) => {}
        Ok(other) => panic!("unexpected verdict: {other:?}"),
        Err(error) => panic!("unexpected StarkError: {error:?}"),
    }
}

#[test]
fn verification_report_flags_header_composition_root_mismatch() {
    let setup = TestSetup::new();
    let witness = WitnessBlob {
        bytes: &setup.witness,
    };
    let public_inputs = make_public_inputs(&setup.header, &setup.body);
    let proof_bytes = generate_proof(
        ProofKind::Execution,
        &public_inputs,
        witness,
        &setup.config,
        &setup.prover_context,
    )
    .expect("proof generation succeeds");

    let tampered = mutate_header_composition_root(&proof_bytes);
    let declared_kind = map_public_to_config_kind(ProofKind::Execution);
    let report = rpp_stark::proof::verifier::verify(
        declared_kind,
        &public_inputs,
        &tampered,
        &setup.config,
        &setup.verifier_context,
    );
    let err = report
        .error
        .as_ref()
        .expect("composition root mismatch must abort decoding");
    assert!(matches!(
        err,
        VerifyError::RootMismatch {
            section: MerkleSection::CompositionCommit
        }
    ));
}

#[test]
fn batch_verify_accepts_empty_batch() {
    let setup = TestSetup::new();
    let block_context = BlockContext {
        block_height: 0,
        previous_state_root: [0u8; 32],
        network_id: 0,
    };
    let outcome = batch_verify(&block_context, &[], &setup.config, &setup.verifier_context)
        .expect("empty batch should succeed");
    assert_eq!(outcome, BatchVerificationOutcome::Accept);
}

#[test]
fn generate_proof_propagates_param_digest_mismatch() {
    let setup = TestSetup::new();
    let mut wrong_config = setup.config.clone();
    wrong_config.param_digest = ParamDigest(DigestBytes { bytes: [1u8; 32] });

    let witness = WitnessBlob {
        bytes: &setup.witness,
    };
    let public_inputs = make_public_inputs(&setup.header, &setup.body);

    let error = generate_proof(
        ProofKind::Execution,
        &public_inputs,
        witness,
        &wrong_config,
        &setup.prover_context,
    )
    .expect_err("params hash mismatch propagates");
    assert!(matches!(
        error,
        StarkError::InvalidInput("prover_params_hash_mismatch")
    ));
}

#[test]
fn verify_proof_reports_decode_failures() {
    let setup = TestSetup::new();
    let witness = WitnessBlob {
        bytes: &setup.witness,
    };
    let public_inputs = make_public_inputs(&setup.header, &setup.body);
    let proof = generate_proof(
        ProofKind::Execution,
        &public_inputs,
        witness,
        &setup.config,
        &setup.prover_context,
    )
    .expect("proof generation succeeds");

    let mut corrupted_bytes = proof.as_slice().to_vec();
    if let Some(first) = corrupted_bytes.first_mut() {
        *first ^= 0xFF;
    }
    let corrupted = ProofBytes::new(corrupted_bytes);
    let verify_inputs = make_public_inputs(&setup.header, &setup.body);
    let result = verify_proof(
        ProofKind::Execution,
        &verify_inputs,
        &corrupted,
        &setup.config,
        &setup.verifier_context,
    );

    let verdict = result.expect("verification should yield a verdict");
    match verdict {
        VerificationVerdict::Reject(VerifyError::VersionMismatch { expected, actual }) => {
            assert_eq!(expected, PROOF_VERSION);
            assert_ne!(expected, actual, "the envelope must report a mismatch");
        }
        VerificationVerdict::Reject(other) => {
            panic!("unexpected rejection error: {other:?}");
        }
        VerificationVerdict::Accept => panic!("corrupted proof must be rejected"),
    }

    assert_eq!(PROOF_VERSION, setup.config.proof_version.0 as u16);
}

#[test]
fn verification_report_flags_proof_size_overflow() {
    let setup = TestSetup::new();
    let witness = WitnessBlob {
        bytes: &setup.witness,
    };
    let public_inputs = make_public_inputs(&setup.header, &setup.body);
    let proof_bytes = generate_proof(
        ProofKind::Execution,
        &public_inputs,
        witness,
        &setup.config,
        &setup.prover_context,
    )
    .expect("proof generation succeeds");

    let declared_kind = map_public_to_config_kind(ProofKind::Execution);
    let mut tight_context = setup.verifier_context.clone();
    tight_context.limits.max_proof_size_bytes = 64; // enforce a strict budget

    let report = rpp_stark::proof::verifier::verify(
        declared_kind,
        &public_inputs,
        &proof_bytes,
        &setup.config,
        &tight_context,
    );

    match report.error {
        Some(VerifyError::ProofTooLarge { max_kb, got_kb }) => {
            assert!(got_kb > max_kb, "reported overflow must exceed budget");
        }
        other => panic!("unexpected verification outcome: {other:?}"),
    }
}
