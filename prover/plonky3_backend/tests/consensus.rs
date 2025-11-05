use p3_baby_bear::BabyBear;
use p3_field::QuotientMap;
use p3_matrix::Matrix;
use plonky3_backend::circuits::consensus::load_consensus_trace_layout;
use plonky3_backend::{
    compute_commitment_and_inputs, decode_consensus_instance, encode_consensus_public_inputs,
    prove_consensus, require_circuit_air_metadata, validate_consensus_public_inputs,
    verify_consensus, AirMetadata, BackendError, ConsensusCircuit, ConsensusProof,
    ConsensusVrfEntry, ConsensusVrfPoseidonInput, ConsensusWitness, ProverContext, ProvingKey,
    VerifierContext, VerifyingKey, VotePower, VRF_PREOUTPUT_LENGTH, VRF_PROOF_LENGTH,
};
use serde::Deserialize;
use serde_json::json;
use serde_json::{Map, Value};
use std::fs;
use std::sync::Arc;

fn sample_vote(label: &str, weight: u64) -> VotePower {
    VotePower {
        voter: label.to_string(),
        weight,
    }
}

#[derive(Deserialize)]
struct FixtureKey {
    encoding: String,
    value: String,
    #[serde(default)]
    compression: Option<String>,
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
    let (baseline_commitment, canonical_bytes) =
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

    let (round_trip_commitment, round_trip_bytes) =
        compute_commitment_and_inputs(&canonical_inputs).expect("round-trip canonical encoding");
    assert_eq!(round_trip_commitment, baseline_commitment);
    assert_eq!(round_trip_bytes, canonical_bytes);

    let recovered_public_inputs = decoded
        .public_inputs_value()
        .expect("re-encode public inputs");
    let (recovered_commitment, recovered_bytes) =
        compute_commitment_and_inputs(&recovered_public_inputs)
            .expect("recovered canonical encoding");
    assert_eq!(recovered_commitment, baseline_commitment);
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
