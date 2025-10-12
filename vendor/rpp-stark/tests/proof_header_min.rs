use rpp_stark::config::{
    build_proof_system_config, build_verifier_context, compute_param_digest, ProfileConfig,
    ProofSystemConfig, VerifierContext, COMMON_IDENTIFIERS, PROFILE_STANDARD_CONFIG,
};
use rpp_stark::field::prime_field::CanonicalSerialize;
use rpp_stark::field::FieldElement;
use rpp_stark::proof::public_inputs::{
    ExecutionHeaderV1, ProofKind as PublicProofKind, PublicInputVersion, PublicInputs,
};
use rpp_stark::proof::ser::{deserialize_proof_header, map_public_to_config_kind};
use rpp_stark::proof::types::{Proof, VerifyError, VerifyReport, PROOF_VERSION};
use rpp_stark::proof::verifier::verify;
use rpp_stark::utils::serialization::{DigestBytes, ProofBytes};

const TRACE_LENGTH: u32 = 128;
const TRACE_WIDTH: u32 = 1;
const SEED_VALUE: u64 = 3;

#[path = "fixtures/mod.rs"]
mod fixtures;

const MINI_PROOF_BYTES: &[u8] = &fixtures::mini_proof::MINI_PROOF_BYTES;

fn mini_proof_vec() -> Vec<u8> {
    MINI_PROOF_BYTES.to_vec()
}

struct MiniFixture {
    config: ProofSystemConfig,
    verifier_context: VerifierContext,
    header: ExecutionHeaderV1,
    body: Vec<u8>,
}

impl MiniFixture {
    fn new() -> Self {
        let profile: ProfileConfig = PROFILE_STANDARD_CONFIG.clone();
        let common = COMMON_IDENTIFIERS.clone();
        let param_digest = compute_param_digest(&profile, &common);
        let config = build_proof_system_config(&profile, &param_digest);
        let verifier_context = build_verifier_context(&profile, &common, &param_digest, None);

        let header = ExecutionHeaderV1 {
            version: PublicInputVersion::V1,
            program_digest: DigestBytes { bytes: [0u8; 32] },
            trace_length: TRACE_LENGTH,
            trace_width: TRACE_WIDTH,
        };

        let seed = FieldElement::from(SEED_VALUE);
        let body = seed.to_bytes().expect("seed encodes canonically").to_vec();

        Self {
            config,
            verifier_context,
            header,
            body,
        }
    }

    fn public_inputs(&self) -> PublicInputs<'_> {
        PublicInputs::Execution {
            header: self.header.clone(),
            body: &self.body,
        }
    }
}

fn verify_with_context(
    setup: &MiniFixture,
    context: &VerifierContext,
    bytes: Vec<u8>,
) -> VerifyReport {
    let proof_bytes = ProofBytes::new(bytes);
    let public_inputs = setup.public_inputs();
    let declared_kind = map_public_to_config_kind(PublicProofKind::Execution);
    verify(
        declared_kind,
        &public_inputs,
        &proof_bytes,
        &setup.config,
        context,
    )
}

#[test]
fn roundtrip_ok() {
    let header_view = deserialize_proof_header(&MINI_PROOF_BYTES).expect("header view");
    let header_len = header_view.payload_offset;
    let header_bytes = &MINI_PROOF_BYTES[..header_len];

    let proof = Proof::from_bytes(&MINI_PROOF_BYTES).expect("decode proof");
    let payload = proof
        .serialize_payload()
        .expect("serialize canonical payload");
    let header = proof
        .serialize_header(&payload)
        .expect("serialize canonical header");

    assert_eq!(
        header.as_slice(),
        header_bytes,
        "header roundtrip must match bytes"
    );

    let telemetry_len = header_view.telemetry_len.unwrap_or(0);
    let expected_payload_len = header_view.openings_len + header_view.fri_len + telemetry_len;
    assert_eq!(
        payload.len(),
        expected_payload_len,
        "payload serialization matches header view lengths",
    );
}

#[test]
fn verify_ok_headers() {
    let setup = MiniFixture::new();
    let report = verify_with_context(&setup, &setup.verifier_context, mini_proof_vec());

    assert!(
        report.error.is_none(),
        "expected verification to accept canonical proof"
    );
    assert!(report.params_ok, "parameter digest stage must succeed");
    assert!(report.public_ok, "public input stage must succeed");
    assert!(report.merkle_ok, "merkle stage must succeed");
    assert!(report.fri_ok, "fri stage must succeed");
    assert!(
        report.total_bytes as usize == MINI_PROOF_BYTES.len(),
        "reported byte length matches canonical proof",
    );
    assert!(
        report.proof.is_some(),
        "handles should be available on success"
    );
}

#[test]
fn version_mismatch_err() {
    let setup = MiniFixture::new();
    let mut bytes = mini_proof_vec();
    bytes[0] = bytes[0].wrapping_add(1);

    let report = verify_with_context(&setup, &setup.verifier_context, bytes);
    match report.error {
        Some(VerifyError::VersionMismatch { expected, actual }) => {
            assert_eq!(
                expected, PROOF_VERSION,
                "error must surface canonical version"
            );
            assert_ne!(expected, actual, "tampering must change advertised version");
        }
        other => panic!("expected version mismatch, got {:?}", other),
    }
}

#[test]
fn params_hash_mismatch_err() {
    let setup = MiniFixture::new();
    let mut bytes = mini_proof_vec();
    let params_offset = 2; // version occupies two bytes
    bytes[params_offset] ^= 0x01;

    let report = verify_with_context(&setup, &setup.verifier_context, bytes);
    assert!(
        matches!(report.error, Some(VerifyError::ParamsHashMismatch)),
        "tampering the parameter digest must be detected",
    );
}

#[test]
fn public_digest_mismatch_err() {
    let setup = MiniFixture::new();
    let mut bytes = mini_proof_vec();
    let public_offset = 2 + 32; // version + params hash
    bytes[public_offset] ^= 0x01;

    let report = verify_with_context(&setup, &setup.verifier_context, bytes);
    assert!(
        matches!(report.error, Some(VerifyError::PublicDigestMismatch)),
        "tampering the public digest must be detected",
    );
}

#[test]
fn proof_too_large_err() {
    let setup = MiniFixture::new();
    let mut context = setup.verifier_context.clone();
    let limit = MINI_PROOF_BYTES.len() - 1;
    context.limits.max_proof_size_bytes = limit as u32;

    let report = verify_with_context(&setup, &context, mini_proof_vec());
    match report.error {
        Some(VerifyError::ProofTooLarge { max_kb, got_kb }) => {
            assert!(
                got_kb >= max_kb,
                "reported size must meet or exceed configured limit"
            );
            assert!(
                report.total_bytes as usize > context.limits.max_proof_size_bytes as usize,
                "report must reflect byte length exceeding configured limit",
            );
        }
        other => panic!("expected proof too large error, got {:?}", other),
    }
}
