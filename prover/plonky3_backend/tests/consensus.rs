use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::Engine;
use blake3::hash;
use flate2::read::GzDecoder;
use flate2::write::GzEncoder;
use flate2::Compression;
use p3_baby_bear::BabyBear;
use p3_field::PrimeField32;
use p3_field::QuotientMap;
use p3_matrix::Matrix;
use p3_symmetric::Hash as CircuitHash;
use plonky3_backend::circuits::consensus::load_consensus_trace_layout;
use plonky3_backend::{
    compute_commitment_and_inputs, decode_consensus_instance, encode_consensus_public_inputs,
    prove_consensus, require_circuit_air_metadata, validate_consensus_public_inputs,
    verify_consensus, AirMetadata, BackendError, CircuitStarkConfig, CircuitStarkProvingKey,
    CircuitStarkVerifyingKey, ConsensusCircuit, ConsensusProof, ConsensusVrfEntry,
    ConsensusVrfPoseidonInput, ConsensusWitness, Proof, ProofMetadata, ProofParts, ProverContext,
    ProvingKey, ToolchainAir, VerifierContext, VerifyingKey, VotePower, VRF_PREOUTPUT_LENGTH,
    VRF_PROOF_LENGTH,
};
use serde::Deserialize;
use serde_json::json;
use serde_json::{Map, Value};
use std::fs;
use std::io::{Read, Write};
use std::sync::Arc;

fn hash_commitment_to_bytes(hash: &CircuitHash<BabyBear, BabyBear, 8>) -> [u8; 32] {
    let mut bytes = [0u8; 32];
    for (index, element) in hash.as_ref().iter().enumerate() {
        let offset = index * 4;
        bytes[offset..offset + 4].copy_from_slice(&element.as_canonical_u32().to_le_bytes());
    }
    bytes
}

fn decode_fixture_key_bytes(label: &str, key: &FixtureKey) -> Vec<u8> {
    let decoded = match key.encoding.as_str() {
        "base64" => BASE64_STANDARD
            .decode(key.value.as_bytes())
            .expect("decode base64 fixture"),
        other => panic!("unsupported fixture encoding: {other}"),
    };
    let decompressed = match key.compression.as_deref() {
        Some("gzip") => {
            let mut decoder = GzDecoder::new(decoded.as_slice());
            let mut decompressed = Vec::new();
            decoder
                .read_to_end(&mut decompressed)
                .expect("decompress fixture payload");
            decompressed
        }
        Some("none") | None => decoded,
        Some(other) => panic!("unsupported fixture compression: {other}"),
    };
    assert!(
        key.byte_length > 0,
        "{label} key fixture must advertise a non-zero payload length",
    );
    assert_eq!(
        decompressed.len(),
        key.byte_length,
        "{label} key fixture decompressed length must match byte_length",
    );
    if let Some(expected_hash) = &key.hash_blake3 {
        let expected =
            hex::decode(expected_hash).expect("fixture hash must be valid hexadecimal digest");
        assert_eq!(
            expected.as_slice(),
            hash(&decompressed).as_bytes(),
            "{label} key fixture digest must match decoded payload",
        );
    }
    decompressed
}

fn encode_fixture_key_bytes(bytes: &[u8], key: &FixtureKey) -> String {
    let compressed = match key.compression.as_deref() {
        Some("gzip") => {
            let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
            encoder.write_all(bytes).expect("compress fixture payload");
            encoder.finish().expect("finalize gzip payload")
        }
        Some("none") | None => bytes.to_vec(),
        Some(other) => panic!("unsupported fixture compression: {other}"),
    };
    match key.encoding.as_str() {
        "base64" => BASE64_STANDARD.encode(&compressed),
        other => panic!("unsupported fixture encoding: {other}"),
    }
}

fn retarget_fixture_metadata(metadata: &AirMetadata, module: &str, name: &str) -> AirMetadata {
    let mut value = serde_json::to_value(metadata).expect("serialize metadata to value");
    let version = metadata
        .air_field("version")
        .and_then(Value::as_str)
        .unwrap_or("0.1.0");
    let identity_air = json!({
        "module": module,
        "name": name,
        "version": version,
    });
    match value {
        Value::Object(ref mut root) => {
            root.insert("air".into(), identity_air);
        }
        _ => {
            value = json!({ "air": identity_air });
        }
    }
    serde_json::from_value(value).expect("rebuild metadata object")
}

fn assert_stark_proof_matches_metadata(proof: &Proof) -> p3_uni_stark::Proof<CircuitStarkConfig> {
    let metadata = proof.metadata();
    let serialized = proof.serialized_proof();
    assert!(
        !serialized.is_empty(),
        "proof payload must include serialized STARK proof"
    );

    let decoded: p3_uni_stark::Proof<CircuitStarkConfig> =
        bincode::deserialize(serialized).expect("deserialize backend proof");
    assert_eq!(
        hash_commitment_to_bytes(&decoded.commitments.trace),
        metadata.trace_commitment(),
        "trace commitment must match metadata"
    );
    assert_eq!(
        hash_commitment_to_bytes(&decoded.commitments.quotient_chunks),
        metadata.quotient_commitment(),
        "quotient commitment must match metadata"
    );
    assert!(
        metadata.random_commitment().is_none(),
        "consensus proofs do not enable random commitments"
    );
    let fri_commitments: Vec<[u8; 32]> = decoded
        .opening_proof
        .commit_phase_commits
        .iter()
        .map(hash_commitment_to_bytes)
        .collect();
    assert_eq!(
        fri_commitments,
        metadata.fri_commitments(),
        "fri commit-phase commitments must match metadata"
    );
    assert!(
        !metadata.challenger_digests().is_empty(),
        "challenger checkpoints must be captured"
    );
    assert!(
        metadata.derived_security_bits() >= metadata.security_bits(),
        "derived security bits should not undercut negotiated security"
    );

    let reserialized = bincode::serialize(&decoded).expect("reserialize backend proof");
    assert_eq!(
        serialized,
        reserialized.as_slice(),
        "serialized proof must remain stable"
    );

    assert!(
        proof.auxiliary_payloads().is_empty(),
        "auxiliary payloads must round-trip"
    );

    decoded
}

fn sample_vote(label: &str, weight: u64) -> VotePower {
    VotePower {
        voter: label.to_string(),
        weight,
    }
}

#[derive(Deserialize)]
struct FixtureKey {
    encoding: String,
    byte_length: usize,
    value: String,
    #[serde(default)]
    compression: Option<String>,
    #[serde(default)]
    hash_blake3: Option<String>,
}

#[derive(Deserialize)]
struct FixtureDoc {
    circuit: String,
    verifying_key: FixtureKey,
    proving_key: FixtureKey,
}

fn sample_witness() -> ConsensusWitness {
    let block_hash = "11".repeat(32);
    ConsensusWitness {
        block_hash: block_hash.clone(),
        round: 7,
        epoch: 3,
        slot: 9,
        leader_proposal: "22".repeat(32),
        quorum_threshold: 2,
        pre_votes: vec![sample_vote("validator-a", 2)],
        pre_commits: vec![sample_vote("validator-a", 2)],
        commit_votes: vec![sample_vote("validator-a", 2)],
        quorum_bitmap_root: "33".repeat(32),
        quorum_signature_root: "44".repeat(32),
        vrf_entries: vec![ConsensusVrfEntry {
            randomness: "55".repeat(32),
            pre_output: "66".repeat(VRF_PREOUTPUT_LENGTH),
            proof: "77".repeat(VRF_PROOF_LENGTH),
            public_key: "88".repeat(32),
            poseidon: ConsensusVrfPoseidonInput {
                digest: "99".repeat(32),
                last_block_header: block_hash,
                epoch: "3".to_string(),
                tier_seed: "aa".repeat(32),
            },
        }],
        witness_commitments: vec!["bb".repeat(32)],
        reputation_roots: vec!["cc".repeat(32)],
    }
}

fn sample_keys() -> (VerifyingKey, ProvingKey) {
    let contents =
        fs::read_to_string("config/plonky3/setup/consensus.json").expect("read consensus fixture");
    let fixture: FixtureDoc = serde_json::from_str(&contents).expect("parse consensus fixture");
    let verifying_key = VerifyingKey::from_encoded_parts(
        &fixture.verifying_key.value,
        &fixture.verifying_key.encoding,
        fixture.verifying_key.compression.as_deref(),
        &fixture.circuit,
    )
    .expect("verifying key constructs");
    let proving_key = ProvingKey::from_encoded_parts(
        &fixture.proving_key.value,
        &fixture.proving_key.encoding,
        fixture.proving_key.compression.as_deref(),
        &fixture.circuit,
        Some(verifying_key.air_metadata()),
    )
    .expect("proving key constructs");
    let verifying_typed = verifying_key.typed();
    let verifying_typed_again = verifying_key.typed();
    assert_eq!(verifying_typed.air(), verifying_typed_again.air());
    assert!(Arc::ptr_eq(
        &verifying_typed.key(),
        &verifying_typed_again.key()
    ));
    let proving_typed = proving_key.typed();
    let proving_typed_again = proving_key.typed();
    assert_eq!(proving_typed.air(), proving_typed_again.air());
    assert!(Arc::ptr_eq(
        &proving_typed.key(),
        &proving_typed_again.key()
    ));
    (verifying_key, proving_key)
}

fn sample_contexts() -> (ProverContext, VerifierContext) {
    let (verifying_key, proving_key) = sample_keys();
    let prover = ProverContext::new("consensus", verifying_key.clone(), proving_key, 64, false)
        .expect("prover context builds");
    let verifier = prover.verifier();
    let prover_metadata = prover.verifying_metadata();
    let proving_metadata = prover.proving_metadata();
    assert!(
        Arc::ptr_eq(&prover_metadata, &proving_metadata),
        "prover context must share metadata Arc"
    );
    assert_eq!(
        prover_metadata.as_ref(),
        verifier.metadata().as_ref(),
        "verifier must reuse prover metadata"
    );
    (prover, verifier)
}

fn prove_sample_witness() -> (ConsensusProof, VerifierContext) {
    let (prover, verifier) = sample_contexts();
    let witness = sample_witness();
    let circuit = ConsensusCircuit::new(witness).expect("consensus circuit");
    let proof = prove_consensus(&prover, &circuit).expect("consensus proving succeeds");
    (proof, verifier)
}

fn rebuild_proof_with_metadata<F>(proof: &Proof, circuit: &str, mutate: F) -> Proof
where
    F: FnOnce(&ProofMetadata) -> ProofMetadata,
{
    let ProofParts {
        serialized_proof,
        metadata,
        auxiliary_payloads,
    } = proof.clone().into_parts();
    let updated_metadata = mutate(&metadata);
    Proof::from_parts(
        circuit,
        ProofParts::new(serialized_proof, updated_metadata, auxiliary_payloads),
    )
    .expect("rebuild proof with modified metadata")
}

#[test]
fn consensus_prover_context_serializes_stark_proof() {
    let (prover, _) = sample_contexts();
    let circuit = ConsensusCircuit::new(sample_witness()).expect("consensus circuit");
    let public_inputs = circuit
        .public_inputs_value()
        .expect("encode consensus public inputs");
    let (_, proof) = prover
        .prove(&public_inputs)
        .expect("ProverContext proves consensus witness");
    assert_stark_proof_matches_metadata(&proof);
}

#[test]
fn consensus_verifying_key_participates_in_uni_stark_verify() {
    let (prover, verifier) = sample_contexts();
    let witness = sample_witness();
    let circuit = ConsensusCircuit::new(witness).expect("consensus circuit");
    let public_inputs = circuit
        .public_inputs_value()
        .expect("encode consensus public inputs");
    let (commitment, proof) = prover
        .prove(&public_inputs)
        .expect("consensus proving succeeds");
    let stark_proof = assert_stark_proof_matches_metadata(&proof);
    let (expected_commitment, _, canonical_inputs) =
        compute_commitment_and_inputs(&public_inputs).expect("canonical encode public inputs");
    assert_eq!(commitment, expected_commitment);
    let canonical_value: Value =
        serde_json::from_slice(&canonical_inputs).expect("decode canonical public inputs");
    let (_, _, public_values) = decode_consensus_instance::<CircuitStarkConfig>(&canonical_value)
        .expect("decode consensus instance");

    let metadata = verifier.metadata();
    let config =
        build_circuit_stark_config(metadata.as_ref()).expect("build consensus Stark config");
    let typed_key = verifier.verifying_key().typed();
    let stark_key = typed_key.key();
    let air = stark_key.air();

    p3_uni_stark::verify(&config, air.as_ref(), &stark_proof, &public_values)
        .expect("direct uni-stark verification succeeds");
}

#[test]
fn consensus_proof_metadata_tracks_commitment_digest() {
    let (prover, _) = sample_contexts();
    let circuit = ConsensusCircuit::new(sample_witness()).expect("consensus circuit");
    let public_inputs = circuit
        .public_inputs_value()
        .expect("encode consensus public inputs");
    let (commitment, proof) = prover
        .prove(&public_inputs)
        .expect("consensus proving succeeds");
    let (expected_commitment, expected_digest, _) =
        compute_commitment_and_inputs(&public_inputs).expect("canonical commitment computation");
    assert_eq!(commitment, expected_commitment);
    assert_eq!(proof.metadata().public_inputs_hash(), &expected_digest);
    assert_eq!(
        hex::encode(proof.metadata().public_inputs_hash()),
        commitment
    );
}

#[test]
fn consensus_prover_reports_trace_height_mismatch() {
    let (prover, _) = sample_contexts();
    let layout = load_consensus_trace_layout().expect("consensus layout");
    let vrf_segment = layout
        .segment("vrf_outputs")
        .expect("vrf_outputs segment metadata");
    let overflow_len = vrf_segment.height() + 1;

    let mut witness = sample_witness();
    let base_entry = witness
        .vrf_entries
        .first()
        .cloned()
        .expect("sample witness vrf entry");
    witness.vrf_entries = (0..overflow_len)
        .map(|index| {
            let mut entry = base_entry.clone();
            let byte = (index & 0xff) as u8;
            entry.randomness = format!("{:02x}", byte).repeat(32);
            entry.pre_output = format!("{:02x}", byte.wrapping_add(1)).repeat(VRF_PREOUTPUT_LENGTH);
            entry.proof = format!("{:02x}", byte.wrapping_add(2)).repeat(VRF_PROOF_LENGTH);
            entry.public_key = format!("{:02x}", byte.wrapping_add(3)).repeat(32);
            entry.poseidon.digest = format!("{:02x}", byte.wrapping_add(4)).repeat(32);
            entry.poseidon.tier_seed = format!("{:02x}", byte.wrapping_add(5)).repeat(32);
            entry
        })
        .collect();

    let circuit = ConsensusCircuit::new(witness).expect("expanded consensus circuit");
    let public_inputs = circuit
        .public_inputs_value()
        .expect("encode consensus public inputs");

    let err = prover
        .prove(&public_inputs)
        .expect_err("trace height mismatch must fail");

    match err {
        BackendError::ProverFailure {
            circuit,
            context,
            source,
        } => {
            assert_eq!(circuit, "consensus");
            assert!(
                context.contains("decode"),
                "unexpected prover failure context: {context}"
            );
            match *source {
                BackendError::InvalidWitness { circuit, message } => {
                    assert_eq!(circuit, "consensus");
                    assert!(
                        message.contains("vrf_outputs") && message.contains("metadata allows"),
                        "unexpected witness error: {message}"
                    );
                }
                other => panic!("unexpected prover failure source: {other:?}"),
            }
        }
        other => panic!("expected prover failure, found {other:?}"),
    }
}

#[test]
fn consensus_prover_context_rejects_retargeted_air() {
    let contents =
        fs::read_to_string("config/plonky3/setup/consensus.json").expect("read consensus fixture");
    let fixture: FixtureDoc = serde_json::from_str(&contents).expect("parse consensus fixture");

    let verifying_raw = decode_fixture_key_bytes("verifying", &fixture.verifying_key);
    let (metadata, verifying_key_raw): (AirMetadata, CircuitStarkVerifyingKey) =
        bincode::deserialize(&verifying_raw).expect("decode verifying key payload");
    let proving_raw = decode_fixture_key_bytes("proving", &fixture.proving_key);
    let (_, proving_key_raw): (AirMetadata, CircuitStarkProvingKey) =
        bincode::deserialize(&proving_raw).expect("decode proving key payload");

    let retargeted_metadata =
        retarget_fixture_metadata(&metadata, "toolchain::identity", "IdentityAir");
    let verifying_serialized =
        bincode::serialize(&(retargeted_metadata.clone(), &verifying_key_raw))
            .expect("serialize retargeted verifying key");
    let proving_serialized = bincode::serialize(&(retargeted_metadata.clone(), &proving_key_raw))
        .expect("serialize retargeted proving key");

    let verifying_encoded = encode_fixture_key_bytes(&verifying_serialized, &fixture.verifying_key);
    let proving_encoded = encode_fixture_key_bytes(&proving_serialized, &fixture.proving_key);

    let verifying_key = VerifyingKey::from_encoded_parts(
        &verifying_encoded,
        &fixture.verifying_key.encoding,
        fixture.verifying_key.compression.as_deref(),
        &fixture.circuit,
    )
    .expect("retargeted verifying key decodes");
    let verifying_metadata = verifying_key.air_metadata();

    let proving_key = ProvingKey::from_encoded_parts(
        &proving_encoded,
        &fixture.proving_key.encoding,
        fixture.proving_key.compression.as_deref(),
        &fixture.circuit,
        Some(verifying_metadata),
    )
    .expect("retargeted proving key decodes");

    let prover = ProverContext::new(&fixture.circuit, verifying_key, proving_key, 64, false)
        .expect("ProverContext builds with retargeted AIR");
    let circuit = ConsensusCircuit::new(sample_witness()).expect("consensus circuit");
    let public_inputs = circuit
        .public_inputs_value()
        .expect("encode consensus public inputs");

    let err = prover
        .prove(&public_inputs)
        .expect_err("retargeted AIR must be unsupported");
    match err {
        BackendError::UnsupportedProvingAir { air, .. } => {
            assert_eq!(air, ToolchainAir::Identity);
        }
        other => panic!("unexpected error: {other:?}"),
    }
}

#[test]
fn consensus_proof_commitments_match_metadata() {
    let (proof, _) = prove_sample_witness();
    assert_stark_proof_matches_metadata(&proof.proof);
}

#[test]
fn consensus_public_inputs_round_trip() {
    let witness = sample_witness();
    let circuit = ConsensusCircuit::new(witness.clone()).expect("valid witness");
    let public_inputs = circuit.public_inputs_value().expect("encode public inputs");
    assert_eq!(
        public_inputs
            .get("block_height")
            .and_then(Value::as_u64)
            .expect("block height"),
        witness.round,
    );
    let vrf_entries = public_inputs
        .get("vrf_entries")
        .and_then(Value::as_array)
        .expect("vrf entries array");
    assert_eq!(vrf_entries.len(), witness.vrf_entries.len());
    let randomness = vrf_entries[0]
        .get("randomness")
        .and_then(Value::as_array)
        .expect("randomness array");
    assert_eq!(randomness.len(), 32);
    let proof_bytes = vrf_entries[0]
        .get("proof")
        .and_then(Value::as_array)
        .expect("proof array");
    assert_eq!(proof_bytes.len(), VRF_PROOF_LENGTH);
    validate_consensus_public_inputs(&public_inputs).expect("validate public inputs");
    let decoded = ConsensusCircuit::from_public_inputs_value(&public_inputs)
        .expect("decode circuit from inputs");
    assert_eq!(decoded.witness().round, witness.round);
    assert_eq!(decoded.vrf_entries().len(), witness.vrf_entries.len());
    assert_eq!(decoded.bindings().quorum_bitmap.len(), 64);
}

#[test]
fn consensus_verification_rejects_tampered_vrf_randomness() {
    let (proof, verifier) = prove_sample_witness();
    verify_consensus(&verifier, &proof).expect("baseline verification succeeds");

    let mut tampered = proof.clone();
    if let Value::Object(ref mut root) = tampered.public_inputs {
        if let Some(Value::Array(ref mut entries)) = root.get_mut("vrf_entries") {
            if let Some(Value::Object(entry)) = entries.first_mut() {
                if let Some(Value::Array(randomness)) = entry.get_mut("randomness") {
                    randomness[0] = json!(255u64);
                }
            }
        }
    }

    let err = verify_consensus(&verifier, &tampered).expect_err("tampered VRF must fail");
    assert!(matches!(
        err,
        plonky3_backend::BackendError::InvalidPublicInputs { .. }
    ));
}

#[test]
fn consensus_verification_rejects_tampered_quorum_digest() {
    let (proof, verifier) = prove_sample_witness();
    verify_consensus(&verifier, &proof).expect("baseline verification succeeds");

    let mut tampered = proof.clone();
    if let Value::Object(ref mut root) = tampered.public_inputs {
        if let Some(Value::Object(bindings)) = root.get_mut("bindings") {
            bindings.insert("quorum_bitmap".into(), json!("deadbeef"));
        }
    }

    let err = verify_consensus(&verifier, &tampered).expect_err("tampered quorum must fail");
    assert!(matches!(
        err,
        plonky3_backend::BackendError::InvalidPublicInputs { .. }
    ));
}

#[test]
fn consensus_rejects_invalid_vrf_proof_length() {
    let mut witness = sample_witness();
    witness.vrf_entries[0].proof.push_str("ff");
    assert!(ConsensusCircuit::new(witness).is_err());
}

#[test]
fn consensus_rejects_invalid_poseidon_digest_length() {
    let mut witness = sample_witness();
    witness.vrf_entries[0].poseidon.digest = "dd".repeat(31);
    assert!(ConsensusCircuit::new(witness).is_err());
}

#[test]
fn consensus_rejects_invalid_poseidon_epoch() {
    let mut witness = sample_witness();
    witness.vrf_entries[0].poseidon.epoch = "".into();
    assert!(ConsensusCircuit::new(witness).is_err());
}

#[test]
fn consensus_rejects_poseidon_epoch_mismatch() {
    let mut witness = sample_witness();
    witness.vrf_entries[0].poseidon.epoch = "999".into();
    assert!(ConsensusCircuit::new(witness).is_err());
}

#[test]
fn consensus_rejects_poseidon_last_block_header_mismatch() {
    let mut witness = sample_witness();
    witness.vrf_entries[0].poseidon.last_block_header = "aa".repeat(32);
    assert!(ConsensusCircuit::new(witness).is_err());
}

#[test]
fn consensus_rejects_binding_tampering() {
    let witness = sample_witness();
    let mut public_inputs = encode_consensus_public_inputs(witness).expect("encode inputs");
    let bindings = public_inputs
        .get_mut("bindings")
        .and_then(Value::as_object_mut)
        .expect("bindings object");
    bindings.insert("quorum_bitmap".into(), Value::String("99".repeat(32)));
    assert!(validate_consensus_public_inputs(&public_inputs).is_err());
}

#[test]
fn consensus_prover_context_rejects_metadata_mismatch() {
    let (verifying_key, proving_key) = sample_keys();
    let tampered: AirMetadata = serde_json::from_value(json!({
        "air": {"log_blowup": 8},
        "generator": "poseidon",
    }))
    .expect("metadata parses");
    let tampered = Arc::new(tampered);
    let verifying_key = verifying_key.with_metadata(Arc::clone(&tampered));

    let err = ProverContext::new("consensus", verifying_key, proving_key, 64, false)
        .expect_err("metadata mismatch must fail");
    match err {
        BackendError::InvalidKeyEncoding { kind, message, .. } => {
            assert_eq!(kind, "proving key");
            assert!(
                message.contains("metadata digest"),
                "unexpected mismatch message: {message}"
            );
        }
        other => panic!("unexpected error: {other:?}"),
    }
}

#[test]
fn consensus_instance_decoding_matches_metadata_layout() {
    use plonky3_backend::circuits::consensus::ConsensusTraceLayout;

    fn parse_numeric_dimension(map: &Map<String, Value>, keys: &[&str]) -> Option<usize> {
        for key in keys {
            if let Some(Value::Number(value)) = map.get(*key) {
                if let Some(dimension) = value.as_u64() {
                    return Some(dimension as usize);
                }
            }
        }
        None
    }

    fn parse_log_dimension(map: &Map<String, Value>, keys: &[&str]) -> Option<usize> {
        for key in keys {
            if let Some(Value::Number(value)) = map.get(*key) {
                if let Some(log_length) = value.as_u64() {
                    return Some(1usize << log_length);
                }
            }
        }
        None
    }

    fn parse_dimension(
        air: &Map<String, Value>,
        trace_obj: Option<&Map<String, Value>>,
        direct_keys: &[&str],
        trace_keys: &[&str],
        log_keys: &[&str],
        trace_log_keys: &[&str],
        label: &str,
    ) -> usize {
        if let Some(dimension) = parse_numeric_dimension(air, direct_keys) {
            return dimension;
        }
        if let Some(dimension) = parse_log_dimension(air, log_keys) {
            return dimension;
        }
        if let Some(trace) = trace_obj {
            if let Some(dimension) = parse_numeric_dimension(trace, trace_keys) {
                return dimension;
            }
            if let Some(dimension) = parse_log_dimension(trace, trace_log_keys) {
                return dimension;
            }
        }
        panic!("missing {label} in consensus AIR metadata");
    }

    fn bytes_to_babybear(bytes: &[u8]) -> BabyBear {
        let mut acc = BabyBear::ZERO;
        let base = <BabyBear as QuotientMap<u16>>::from_int(256);
        for &byte in bytes {
            let digit = <BabyBear as QuotientMap<u8>>::from_int(byte);
            acc = acc * base + digit;
        }
        acc
    }

    fn hex_to_babybear(value: &str) -> BabyBear {
        let bytes = hex::decode(value).expect("decode hex digest");
        bytes_to_babybear(&bytes)
    }

    fn trace_index(layout: &ConsensusTraceLayout, row: usize, column: usize) -> usize {
        row * layout.width + column
    }

    fn assert_zero_padding(
        layout: &ConsensusTraceLayout,
        trace: &[BabyBear],
        segment: &plonky3_backend::circuits::consensus::ConsensusTraceSegment,
        populated_rows: usize,
    ) {
        if populated_rows >= segment.height() {
            return;
        }
        for row in segment.row_range.start + populated_rows..segment.row_range.end {
            let start = trace_index(layout, row, segment.column_range.start);
            let end = trace_index(layout, row, segment.column_range.end);
            assert!(
                trace[start..end]
                    .iter()
                    .all(|value| *value == BabyBear::ZERO),
                "segment '{}' row {} must remain zero padded",
                segment.label,
                row
            );
        }
    }

    let witness = sample_witness();
    let baseline = ConsensusCircuit::new(witness).expect("construct consensus circuit");
    let public_inputs = baseline
        .public_inputs_value()
        .expect("encode consensus public inputs");
    let (baseline_commitment, baseline_digest, canonical_bytes) =
        compute_commitment_and_inputs(&public_inputs).expect("canonical commitment computation");
    let canonical_inputs: Value =
        serde_json::from_slice(&canonical_bytes).expect("canonical public inputs decode");

    let (decoded, trace, flattened_inputs) =
        decode_consensus_instance::<plonky3_backend::CircuitStarkConfig>(&canonical_inputs)
            .expect("decode consensus instance");

    assert_eq!(
        decoded.witness(),
        baseline.witness(),
        "witness must round-trip"
    );
    assert_eq!(
        decoded.bindings(),
        baseline.bindings(),
        "bindings must round-trip"
    );
    assert_eq!(
        decoded.vrf_entries(),
        baseline.vrf_entries(),
        "VRF entries must round-trip"
    );

    let (expected_inputs, input_layout) = baseline
        .flatten_public_inputs_for_config::<plonky3_backend::CircuitStarkConfig>()
        .expect("flatten baseline inputs");
    assert_eq!(
        flattened_inputs, expected_inputs,
        "public inputs must match baseline"
    );
    assert_eq!(input_layout.total_values, flattened_inputs.len());

    let (decoded_inputs, decoded_layout) = decoded
        .flatten_public_inputs_for_config::<plonky3_backend::CircuitStarkConfig>()
        .expect("flatten decoded inputs");
    assert_eq!(decoded_inputs, flattened_inputs);
    assert_eq!(decoded_layout.total_values, flattened_inputs.len());

    let (round_trip_commitment, round_trip_digest, round_trip_bytes) =
        compute_commitment_and_inputs(&canonical_inputs).expect("round-trip canonical encoding");
    assert_eq!(round_trip_commitment, baseline_commitment);
    assert_eq!(round_trip_digest, baseline_digest);
    assert_eq!(round_trip_bytes, canonical_bytes);

    let recovered_public_inputs = decoded
        .public_inputs_value()
        .expect("re-encode public inputs");
    let (recovered_commitment, recovered_digest, recovered_bytes) =
        compute_commitment_and_inputs(&recovered_public_inputs)
            .expect("recovered canonical encoding");
    assert_eq!(recovered_commitment, baseline_commitment);
    assert_eq!(recovered_digest, baseline_digest);
    assert_eq!(recovered_bytes, canonical_bytes);

    let (verifying_key, _) = sample_keys();
    let metadata = verifying_key.air_metadata();
    let air = metadata.air().expect("consensus AIR descriptor");
    let trace_obj = air.get("trace").and_then(Value::as_object);
    let declared_height = parse_dimension(
        air,
        trace_obj,
        &["trace_height", "trace_length", "trace_len"],
        &["height", "length", "rows"],
        &["log_trace_length", "log_trace_height"],
        &["log_length"],
        "trace height",
    );
    let declared_width = parse_dimension(
        air,
        trace_obj,
        &["trace_width", "column_count", "columns"],
        &["width", "columns"],
        &[],
        &[],
        "trace width",
    );

    assert_eq!(
        trace.height(),
        declared_height,
        "trace height must match metadata"
    );
    assert_eq!(
        trace.width(),
        declared_width,
        "trace width must match metadata"
    );
    assert_eq!(trace.values.len(), declared_height * declared_width);

    let layout = load_consensus_trace_layout().expect("consensus trace layout");
    assert_eq!(layout.height, declared_height);
    assert_eq!(layout.width, declared_width);

    let mut previous_end = 0usize;
    for segment in &layout.segments {
        assert!(
            segment.column_range.start >= previous_end,
            "segment '{}' must not overlap previous columns",
            segment.label
        );
        assert!(
            segment.column_range.end <= layout.width,
            "segment '{}' exceeds matrix width",
            segment.label
        );
        assert!(
            segment.row_range.end <= layout.height,
            "segment '{}' exceeds matrix height",
            segment.label
        );
        previous_end = segment.column_range.end;
    }
    assert!(previous_end <= layout.width);

    let vrf_outputs = layout
        .segment("vrf_outputs")
        .expect("metadata defines vrf_outputs segment");
    assert!(
        !decoded.vrf_entries().is_empty(),
        "sample witness must include VRF entries"
    );
    let randomness_index = trace_index(
        &layout,
        vrf_outputs.row_range.start,
        vrf_outputs.column_range.start,
    );
    let expected_randomness = bytes_to_babybear(&decoded.vrf_entries()[0].randomness);
    assert_eq!(
        trace.values[randomness_index], expected_randomness,
        "first VRF randomness cell must match sanitized entry",
    );

    let pre_votes = layout
        .segment("pre_votes")
        .expect("metadata defines pre_votes segment");
    assert!(
        !baseline.witness().pre_votes.is_empty(),
        "sample witness must include pre-votes"
    );
    let cumulative_index = trace_index(
        &layout,
        pre_votes.row_range.start,
        pre_votes.column_range.start + 2,
    );
    let expected_cumulative =
        <BabyBear as QuotientMap<u128>>::from_int(baseline.witness().pre_votes[0].weight as u128);
    assert_eq!(
        trace.values[cumulative_index], expected_cumulative,
        "pre-vote cumulative sum must match STWO accumulation",
    );

    let witness_commitments = layout
        .segment("witness_commitments")
        .expect("metadata defines witness_commitments segment");
    assert!(
        !baseline.witness().witness_commitments.is_empty(),
        "sample witness must include witness commitments"
    );
    let binding_row =
        witness_commitments.row_range.start + baseline.witness().witness_commitments.len() - 1;
    let binding_index = trace_index(
        &layout,
        binding_row,
        witness_commitments.column_range.end - 1,
    );
    let expected_binding = hex_to_babybear(&decoded.bindings().witness_commitments);
    assert_eq!(
        trace.values[binding_index], expected_binding,
        "binding segment must expose cached digest",
    );

    let mut saw_padding = false;
    for segment in &layout.segments {
        let populated_rows = match segment.label.as_str() {
            "pre_votes" => baseline.witness().pre_votes.len(),
            "pre_commits" => baseline.witness().pre_commits.len(),
            "commits" => baseline.witness().commit_votes.len(),
            "vrf_outputs" | "vrf_proofs" | "vrf_transcripts" => decoded.vrf_entries().len(),
            "witness_commitments" => baseline.witness().witness_commitments.len(),
            "reputation_roots" => baseline.witness().reputation_roots.len(),
            "quorum_bitmap_binding" | "quorum_signature_binding" | "summary" => 1,
            _ => continue,
        };
        if segment.height() > populated_rows {
            saw_padding = true;
            assert_zero_padding(&layout, &trace.values, segment, populated_rows);
        }
    }
    assert!(
        saw_padding,
        "expected at least one zero-padded segment in trace"
    );
}

#[test]
fn consensus_instance_decoding_rejects_malformed_inputs() {
    let malformed = Value::Null;
    let err = decode_consensus_instance::<plonky3_backend::CircuitStarkConfig>(&malformed)
        .expect_err("malformed inputs must fail");
    assert!(matches!(err, BackendError::InvalidPublicInputs { .. }));

    let mut invalid_bindings = sample_witness();
    invalid_bindings.quorum_bitmap_root = "".into();
    let payload = json!({
        "witness": invalid_bindings,
        "bindings": json!({"quorum_bitmap": "00"}),
        "vrf_entries": [],
    });
    let err = decode_consensus_instance::<plonky3_backend::CircuitStarkConfig>(&payload)
        .expect_err("invalid payload must fail");
    assert!(matches!(err, BackendError::InvalidPublicInputs { .. }));
}

#[test]
fn consensus_verifier_accepts_round_trip_proof_parts() {
    let (proof_bundle, verifier) = prove_sample_witness();
    let ConsensusProof {
        commitment,
        public_inputs,
        proof,
    } = proof_bundle;

    let rebuilt = Proof::from_parts(verifier.circuit(), proof.clone().into_parts())
        .expect("rebuild consensus proof from parts");

    verifier
        .verify(&commitment, &public_inputs, &rebuilt)
        .expect("verifier accepts round-tripped proof");
}

#[test]
fn consensus_verifier_rejects_security_metadata_mismatch() {
    let (proof_bundle, verifier) = prove_sample_witness();
    let ConsensusProof {
        commitment,
        public_inputs,
        proof,
    } = proof_bundle;

    let tampered = rebuild_proof_with_metadata(&proof, verifier.circuit(), |metadata| {
        let security_bits = metadata.security_bits() ^ 1;
        ProofMetadata::assemble(
            *metadata.trace_commitment(),
            *metadata.quotient_commitment(),
            metadata.random_commitment().copied(),
            metadata.fri_commitments().to_vec(),
            *metadata.public_inputs_hash(),
            metadata.challenger_digests().to_vec(),
            metadata.hash_format(),
            security_bits,
            metadata.derived_security_bits(),
            metadata.use_gpu(),
        )
    });

    let err = verifier
        .verify(&commitment, &public_inputs, &tampered)
        .expect_err("verifier must reject modified security bits");
    assert!(
        matches!(err, BackendError::SecurityParameterMismatch(circuit) if circuit == verifier.circuit())
    );
}

#[test]
fn consensus_verifier_rejects_public_input_hash_mismatch() {
    let (proof_bundle, verifier) = prove_sample_witness();
    let ConsensusProof {
        commitment,
        public_inputs,
        proof,
    } = proof_bundle;

    let tampered = rebuild_proof_with_metadata(&proof, verifier.circuit(), |metadata| {
        let mut hash = *metadata.public_inputs_hash();
        hash[0] ^= 0x01;
        ProofMetadata::assemble(
            *metadata.trace_commitment(),
            *metadata.quotient_commitment(),
            metadata.random_commitment().copied(),
            metadata.fri_commitments().to_vec(),
            hash,
            metadata.challenger_digests().to_vec(),
            metadata.hash_format(),
            metadata.security_bits(),
            metadata.derived_security_bits(),
            metadata.use_gpu(),
        )
    });

    let err = verifier
        .verify(&commitment, &public_inputs, &tampered)
        .expect_err("verifier must reject modified public input hash");
    assert!(
        matches!(err, BackendError::PublicInputDigestMismatch(circuit) if circuit == verifier.circuit())
    );
}

#[test]
fn consensus_verifier_rejects_gpu_flag_mismatch() {
    let (proof_bundle, verifier) = prove_sample_witness();
    let ConsensusProof {
        commitment,
        public_inputs,
        proof,
    } = proof_bundle;

    let tampered = rebuild_proof_with_metadata(&proof, verifier.circuit(), |metadata| {
        ProofMetadata::assemble(
            *metadata.trace_commitment(),
            *metadata.quotient_commitment(),
            metadata.random_commitment().copied(),
            metadata.fri_commitments().to_vec(),
            *metadata.public_inputs_hash(),
            metadata.challenger_digests().to_vec(),
            metadata.hash_format(),
            metadata.security_bits(),
            metadata.derived_security_bits(),
            !metadata.use_gpu(),
        )
    });

    let err = verifier
        .verify(&commitment, &public_inputs, &tampered)
        .expect_err("verifier must reject modified GPU flag");
    assert!(matches!(err, BackendError::GpuModeMismatch(circuit) if circuit == verifier.circuit()));
}

#[test]
fn consensus_verifier_rejects_challenger_digest_mismatch() {
    let (proof_bundle, verifier) = prove_sample_witness();
    let ConsensusProof {
        commitment,
        public_inputs,
        proof,
    } = proof_bundle;

    let tampered = rebuild_proof_with_metadata(&proof, verifier.circuit(), |metadata| {
        let mut digests = metadata.challenger_digests().to_vec();
        digests
            .first_mut()
            .expect("metadata exposes challenger digests")[0] ^= 0x01;
        ProofMetadata::assemble(
            *metadata.trace_commitment(),
            *metadata.quotient_commitment(),
            metadata.random_commitment().copied(),
            metadata.fri_commitments().to_vec(),
            *metadata.public_inputs_hash(),
            digests,
            metadata.hash_format(),
            metadata.security_bits(),
            metadata.derived_security_bits(),
            metadata.use_gpu(),
        )
    });

    let err = verifier
        .verify(&commitment, &public_inputs, &tampered)
        .expect_err("verifier must reject modified challenger digests");
    assert!(
        matches!(err, BackendError::FriDigestMismatch(circuit) if circuit == verifier.circuit())
    );
}
