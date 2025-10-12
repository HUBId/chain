use rpp_stark::config::{
    build_proof_system_config, build_prover_context, build_verifier_context, compute_param_digest,
    ChunkingPolicy, ProofSystemConfig, ProverContext, ThreadPoolProfile, VerifierContext,
    COMMON_IDENTIFIERS_ARITY4, PROFILE_STANDARD_ARITY4_CONFIG,
};
use rpp_stark::field::prime_field::{CanonicalSerialize, FieldElementOps};
use rpp_stark::field::FieldElement;
use rpp_stark::proof::public_inputs::{
    ExecutionHeaderV1, ProofKind, PublicInputVersion, PublicInputs,
};
use rpp_stark::proof::ser::serialize_proof;
use rpp_stark::proof::types::{MerkleSection, VerifyError};
use rpp_stark::utils::serialization::{DigestBytes, ProofBytes, WitnessBlob};
use rpp_stark::{generate_proof, verify_proof, Proof, VerificationVerdict};

const LFSR_ALPHA: u64 = 5;
const LFSR_BETA: u64 = 7;

fn build_setup() -> (
    ProofSystemConfig,
    ProverContext,
    VerifierContext,
    ExecutionHeaderV1,
    Vec<u8>,
    Vec<u8>,
) {
    let profile = PROFILE_STANDARD_ARITY4_CONFIG.clone();
    let common = COMMON_IDENTIFIERS_ARITY4;
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

    (
        config,
        prover_context,
        verifier_context,
        header,
        body,
        witness,
    )
}

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
fn quaternary_profile_roundtrip_accepts() {
    let (config, prover_context, verifier_context, header, body, witness) = build_setup();
    let witness_blob = WitnessBlob { bytes: &witness };
    let public_inputs = make_public_inputs(&header, &body);

    let proof_bytes = generate_proof(
        ProofKind::Execution,
        &public_inputs,
        witness_blob,
        &config,
        &prover_context,
    )
    .expect("proof generation succeeds");

    let verdict = verify_proof(
        ProofKind::Execution,
        &public_inputs,
        &proof_bytes,
        &config,
        &verifier_context,
    )
    .expect("verification executes");

    assert!(matches!(verdict, VerificationVerdict::Accept));
}

#[test]
fn quaternary_profile_merkle_tamper_rejected() {
    let (config, prover_context, verifier_context, header, body, witness) = build_setup();
    let public_inputs = make_public_inputs(&header, &body);
    let proof_bytes = generate_proof(
        ProofKind::Execution,
        &public_inputs,
        WitnessBlob { bytes: &witness },
        &config,
        &prover_context,
    )
    .expect("proof generation succeeds");

    let mut proof = Proof::from_bytes(proof_bytes.as_slice()).expect("decode proof");
    if let Some(path) = proof.openings_mut().trace_mut().paths_mut().first_mut() {
        if let Some(node) = path.nodes_mut().get_mut(1) {
            node.sibling[0] ^= 0x01;
        }
    }
    let tampered_bytes =
        ProofBytes::new(serialize_proof(&proof).expect("serialize tampered proof"));

    let verdict = verify_proof(
        ProofKind::Execution,
        &public_inputs,
        &tampered_bytes,
        &config,
        &verifier_context,
    )
    .expect("verification executes");

    match verdict {
        VerificationVerdict::Reject(error) => {
            assert!(matches!(
                error,
                VerifyError::MerkleVerifyFailed {
                    section: MerkleSection::TraceCommit
                }
            ));
        }
        other => panic!("expected rejection, got {:?}", other),
    }
}
