use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::Engine;
use blake3::hash;
use flate2::read::GzDecoder;
use flate2::write::GzEncoder;
use flate2::Compression;
use hex::decode as hex_decode;
use plonky3_backend::{
    resolve_toolchain_air, AirMetadata, BackendError, CircuitBaseField, CircuitConfigBuilder,
    CircuitStarkProvingKey, CircuitStarkVerifyingKey, ProofMetadata, ProverContext, ProvingKey,
    ToolchainAir, VerifyingKey,
};
use serde::Deserialize;
use serde_json::json;
use std::fs;
use std::io::{Read, Write};
use std::sync::Arc;

#[derive(Deserialize)]
struct FixtureKey {
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

fn load_consensus_fixture() -> FixtureDoc {
    let contents =
        fs::read_to_string("config/plonky3/setup/consensus.json").expect("read consensus fixture");
    serde_json::from_str(&contents).expect("parse consensus fixture")
}

fn decode_base64(value: &str) -> Vec<u8> {
    BASE64_STANDARD
        .decode(value.as_bytes())
        .expect("decode base64 value")
}

fn decode_fixture_key_bytes(key: &FixtureKey) -> Vec<u8> {
    let decoded = decode_base64(&key.value);
    match key.compression.as_deref() {
        Some("gzip") => decompress_gzip(&decoded),
        Some("none") | None => decoded,
        Some(other) => panic!("unsupported fixture compression: {other}"),
    }
}

fn decompress_gzip(bytes: &[u8]) -> Vec<u8> {
    let mut decoder = GzDecoder::new(bytes);
    let mut decompressed = Vec::new();
    decoder
        .read_to_end(&mut decompressed)
        .expect("decompress gzip payload");
    decompressed
}

fn compress_gzip(bytes: &[u8]) -> Vec<u8> {
    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(bytes).expect("compress gzip payload");
    encoder.finish().expect("finalize gzip payload")
}

#[test]
fn consensus_fixture_descriptor_decodes_typed_keys() {
    let fixture = load_consensus_fixture();

    assert_ne!(
        fixture.verifying_key.byte_length, 0,
        "consensus verifying fixture must advertise a non-zero payload length",
    );
    let verifying_fixture_raw = decode_fixture_key_bytes(&fixture.verifying_key);
    assert_eq!(
        verifying_fixture_raw.len(),
        fixture.verifying_key.byte_length,
        "decompressed verifying payload length must match advertised byte_length",
    );
    let expected_verifying_hash = fixture
        .verifying_key
        .hash_blake3
        .as_ref()
        .expect("consensus verifying fixture must include BLAKE3 digest");
    let expected_verifying_hash =
        hex_decode(expected_verifying_hash).expect("consensus verifying hash must be valid hex");
    assert_eq!(
        expected_verifying_hash.as_slice(),
        hash(&verifying_fixture_raw).as_bytes(),
        "verifying key payload digest must match fixture hash",
    );
    let (fixture_metadata, fixture_verifying_key): (AirMetadata, CircuitStarkVerifyingKey) =
        bincode::deserialize(&verifying_fixture_raw).expect("parse verifying key fixture");

    assert_ne!(
        fixture.proving_key.byte_length, 0,
        "consensus proving fixture must advertise a non-zero payload length",
    );
    let proving_fixture_raw = decode_fixture_key_bytes(&fixture.proving_key);
    assert_eq!(
        proving_fixture_raw.len(),
        fixture.proving_key.byte_length,
        "decompressed proving payload length must match advertised byte_length",
    );
    if let Some(expected_hash) = &fixture.proving_key.hash_blake3 {
        let expected_hash =
            hex_decode(expected_hash).expect("consensus proving hash must be valid hex");
        assert_eq!(
            expected_hash.as_slice(),
            hash(&proving_fixture_raw).as_bytes(),
            "proving key payload digest must match fixture hash",
        );
    }
    let (proving_metadata, fixture_proving_key): (AirMetadata, CircuitStarkProvingKey) =
        bincode::deserialize(&proving_fixture_raw).expect("parse proving key fixture");
    assert_eq!(fixture_metadata, proving_metadata);
    let metadata = fixture_metadata;

    let verifying_raw = bincode::serialize(&(metadata.clone(), &fixture_verifying_key))
        .expect("serialize verifying tuple");
    let verifying_compressed = match fixture.verifying_key.compression.as_deref() {
        Some("gzip") => compress_gzip(&verifying_raw),
        Some("none") | None => verifying_raw.clone(),
        Some(other) => panic!("unsupported fixture compression: {other}"),
    };
    let verifying_base64 = BASE64_STANDARD.encode(verifying_compressed.as_slice());

    let verifying_key = VerifyingKey::from_encoded_parts(
        &verifying_base64,
        "base64",
        fixture.verifying_key.compression.as_deref(),
        &fixture.circuit,
    )
    .expect("verifying key decodes");
    assert_eq!(verifying_key.bytes(), verifying_raw.as_slice());
    assert_eq!(verifying_key.bytes().len(), verifying_raw.len());
    assert_eq!(
        verifying_key.hash(),
        *hash(&verifying_compressed).as_bytes()
    );

    let verifying_stark = verifying_key.stark_key();
    assert_eq!(verifying_stark.air(), ToolchainAir::Consensus);
    assert_eq!(verifying_stark.len(), verifying_raw.len());
    let verifying_stark_again = verifying_key.stark_key();
    assert!(Arc::ptr_eq(verifying_stark, verifying_stark_again));

    let verifying_typed = verifying_key.typed();
    assert_eq!(verifying_typed.air(), ToolchainAir::Consensus);
    let verifying_typed_again = verifying_key.typed();
    assert_eq!(verifying_typed.air(), verifying_typed_again.air());
    assert!(Arc::ptr_eq(
        &verifying_typed.key(),
        &verifying_typed_again.key()
    ));

    let verifying_metadata = verifying_key.air_metadata();
    assert_eq!(
        verifying_metadata.digest().is_some(),
        !verifying_metadata.is_empty()
    );
    assert_eq!(verifying_metadata.as_ref(), &metadata);
    let verifying_metadata_again = verifying_key.air_metadata();
    assert!(Arc::ptr_eq(verifying_metadata, verifying_metadata_again));

    let verifying_reserialized =
        bincode::serialize(&(verifying_metadata.as_ref(), verifying_typed.key().as_ref()))
            .expect("reserialize verifying tuple");
    assert_eq!(verifying_reserialized, verifying_raw);

    let verifying_metadata_arc = Arc::clone(verifying_metadata);

    let proving_raw = bincode::serialize(&(metadata.clone(), &fixture_proving_key))
        .expect("serialize proving tuple");
    let proving_base64 = BASE64_STANDARD.encode(proving_raw.as_slice());

    let proving_key = ProvingKey::from_encoded_parts(
        &proving_base64,
        "base64",
        Some("none"),
        &fixture.circuit,
        Some(&verifying_metadata_arc),
    )
    .expect("proving key decodes");
    assert_eq!(proving_key.bytes(), proving_raw.as_slice());
    assert_eq!(proving_key.bytes().len(), proving_raw.len());
    assert_eq!(proving_key.hash(), *hash(&proving_raw).as_bytes());

    let proving_stark = proving_key.stark_key();
    assert_eq!(proving_stark.air(), ToolchainAir::Consensus);
    assert_eq!(proving_stark.len(), proving_raw.len());
    let proving_stark_again = proving_key.stark_key();
    assert!(Arc::ptr_eq(proving_stark, proving_stark_again));

    let proving_typed = proving_key.typed();
    assert_eq!(proving_typed.air(), ToolchainAir::Consensus);
    let proving_typed_again = proving_key.typed();
    assert_eq!(proving_typed.air(), proving_typed_again.air());
    assert!(Arc::ptr_eq(
        &proving_typed.key(),
        &proving_typed_again.key()
    ));

    let proving_metadata = proving_key.air_metadata();
    assert!(Arc::ptr_eq(verifying_metadata, proving_metadata));

    let proving_reserialized =
        bincode::serialize(&(proving_metadata.as_ref(), proving_typed.key().as_ref()))
            .expect("reserialize proving tuple");
    assert_eq!(proving_reserialized, proving_raw);
}

#[test]
fn metadata_dispatch_selects_consensus_air() {
    let metadata: AirMetadata = serde_json::from_value(json!({
        "air": {
            "module": "toolchain::consensus",
            "name": "ConsensusAir",
            "version": "0.1.0",
        }
    }))
    .expect("metadata deserialises");

    let air = resolve_toolchain_air("consensus", &metadata).expect("air resolves");
    assert_eq!(air, ToolchainAir::Consensus);
}

#[test]
fn malformed_key_payloads_surface_encoding_errors() {
    let circuit = "sample";
    let invalid_payload = vec![0xde, 0xad, 0xbe, 0xef];
    let invalid_base64 = BASE64_STANDARD.encode(invalid_payload);

    let verifying_error =
        VerifyingKey::from_encoded_parts(&invalid_base64, "base64", None, circuit)
            .expect_err("invalid verifying key must error");
    match verifying_error {
        BackendError::InvalidKeyEncoding {
            circuit: err_circuit,
            kind,
            ..
        } => {
            assert_eq!(err_circuit, circuit);
            assert_eq!(kind, "verifying key");
        }
        other => panic!("unexpected error: {other:?}"),
    }

    let proving_error =
        ProvingKey::from_encoded_parts(&invalid_base64, "base64", None, circuit, None)
            .expect_err("invalid proving key must error");
    match proving_error {
        BackendError::InvalidKeyEncoding {
            circuit: err_circuit,
            kind,
            ..
        } => {
            assert_eq!(err_circuit, circuit);
            assert_eq!(kind, "proving key");
        }
        other => panic!("unexpected error: {other:?}"),
    }
}

#[test]
fn contexts_debug_and_clone_preserve_metadata() {
    let fixture = load_consensus_fixture();

    let verifying_key = VerifyingKey::from_encoded_parts(
        &fixture.verifying_key.value,
        "base64",
        fixture.verifying_key.compression.as_deref(),
        &fixture.circuit,
    )
    .expect("verifying key decodes");
    let verifying_metadata = Arc::clone(verifying_key.air_metadata());
    let proving_key = ProvingKey::from_encoded_parts(
        &fixture.proving_key.value,
        "base64",
        fixture.proving_key.compression.as_deref(),
        &fixture.circuit,
        Some(verifying_key.air_metadata()),
    )
    .expect("proving key decodes");

    let prover = ProverContext::new(
        &fixture.circuit,
        verifying_key.clone(),
        proving_key.clone(),
        64,
        false,
    )
    .expect("prover context builds");
    let prover_debug = format!("{prover:?}");
    assert!(prover_debug.contains("ProverContext"));
    let prover_verifying_metadata = prover.verifying_metadata();
    let prover_proving_metadata = prover.proving_metadata();
    assert!(Arc::ptr_eq(
        &prover_verifying_metadata,
        &prover_proving_metadata
    ));
    assert!(Arc::ptr_eq(&prover_verifying_metadata, &verifying_metadata));

    let verifier = prover.verifier();
    let verifier_debug = format!("{verifier:?}");
    assert!(verifier_debug.contains("VerifierContext"));
    let verifier_clone = verifier.clone();
    let verifier_metadata = verifier.metadata();
    let verifier_clone_metadata = verifier_clone.metadata();
    assert!(Arc::ptr_eq(&verifier_metadata, &verifier_clone_metadata));
    assert_eq!(
        verifier_metadata.as_ref(),
        prover_verifying_metadata.as_ref()
    );
}

#[test]
fn json_schemas_are_deterministic() {
    let verifying = VerifyingKey::json_schema();
    let expected_verifying = json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "title": "Plonky3 Verifying Key",
        "type": "object",
        "description": "Descriptor for a verifying key artifact",
        "properties": {
            "encoding": {
                "type": "string",
                "enum": ["base64"],
                "description": "Encoding applied to the inline key material."
            },
            "value": {
                "type": "string",
                "contentEncoding": "base64",
                "description": "Base64 payload containing the raw key bytes (compressed or raw)."
            },
            "byte_length": {
                "type": "integer",
                "minimum": 1,
                "description": "Length of the decoded key in bytes."
            },
            "compression": {
                "type": "string",
                "enum": ["gzip", "none"],
                "description": "Compression applied before encoding; omit or set to 'none' when the payload is raw."
            },
            "hash_blake3": {
                "type": "string",
                "pattern": "^[0-9a-fA-F]{64}$",
                "description": "Optional BLAKE3 digest of the decoded key, useful for diagnostics."
            }
        },
        "required": ["encoding", "value", "byte_length"],
        "additionalProperties": false
    });
    assert_eq!(verifying, expected_verifying);

    let proving = ProvingKey::json_schema();
    let expected_proving = json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "title": "Plonky3 Proving Key",
        "type": "object",
        "description": "Descriptor for a proving key artifact",
        "properties": {
            "encoding": {
                "type": "string",
                "enum": ["base64"],
                "description": "Encoding applied to the inline key material."
            },
            "value": {
                "type": "string",
                "contentEncoding": "base64",
                "description": "Base64 payload containing the raw key bytes (compressed or raw)."
            },
            "byte_length": {
                "type": "integer",
                "minimum": 1,
                "description": "Length of the decoded key in bytes."
            },
            "compression": {
                "type": "string",
                "enum": ["gzip", "none"],
                "description": "Compression applied before encoding; omit or set to 'none' when the payload is raw."
            },
            "hash_blake3": {
                "type": "string",
                "pattern": "^[0-9a-fA-F]{64}$",
                "description": "Optional BLAKE3 digest of the decoded key, useful for diagnostics."
            }
        },
        "required": ["encoding", "value", "byte_length"],
        "additionalProperties": false
    });
    assert_eq!(proving, expected_proving);

    let metadata = ProofMetadata::json_schema();
    let expected_metadata = json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "title": "Plonky3 Proof Metadata",
        "type": "object",
        "description": "Transcript commitments, challenger digests, and security parameters embedded in a Plonky3 proof payload.",
        "properties": {
            "trace_commitment": {
                "type": "string",
                "pattern": "^[0-9a-fA-F]{64}$",
                "description": "Poseidon Merkle cap commitment for the execution trace."
            },
            "quotient_commitment": {
                "type": "string",
                "pattern": "^[0-9a-fA-F]{64}$",
                "description": "Poseidon Merkle cap commitment for the quotient domain."
            },
            "random_commitment": {
                "type": ["string", "null"],
                "pattern": "^[0-9a-fA-F]{64}$",
                "description": "Optional Poseidon Merkle cap commitment for the randomizer domain when zero-knowledge is enabled."
            },
            "fri_commitments": {
                "type": "array",
                "items": {
                    "type": "string",
                    "pattern": "^[0-9a-fA-F]{64}$",
                    "description": "Poseidon Merkle cap commitment generated for each FRI commit-phase round (oldest to newest)."
                },
                "minItems": 1,
                "description": "Sequence of Merkle cap commitments binding every folding layer of the FRI transcript."
            },
            "public_inputs_hash": {
                "type": "string",
                "pattern": "^[0-9a-fA-F]{64}$",
                "description": "BLAKE3 digest of the encoded public inputs."
            },
            "challenger_digests": {
                "type": "array",
                "items": {
                    "type": "string",
                    "pattern": "^[0-9a-fA-F]{64}$",
                    "description": "BLAKE3 digests of the Poseidon sponge state after major transcript milestones (Fiat-Shamir checkpoints)."
                },
                "minItems": 1,
                "description": "Deterministic checkpoints of the challenger transcript useful for external auditing."
            },
            "hash_format": {
                "type": "string",
                "enum": ["poseidon_merkle_cap"],
                "description": "Digest algorithm used for transcript commitments (header order preserved)."
            },
            "security_bits": {
                "type": "integer",
                "minimum": 1,
                "description": "Security parameter negotiated between prover and verifier."
            },
            "derived_security_bits": {
                "type": "integer",
                "minimum": 1,
                "description": "Security level inferred from the circuit configuration, query schedule, and proof of work."
            },
            "use_gpu": {
                "type": "boolean",
                "description": "Indicates whether the proof was constructed with GPU acceleration."
            }
        },
        "required": [
            "trace_commitment",
            "quotient_commitment",
            "fri_commitments",
            "public_inputs_hash",
            "challenger_digests",
            "security_bits",
            "derived_security_bits",
            "use_gpu",
            "hash_format"
        ],
        "additionalProperties": false
    });
    assert_eq!(metadata, expected_metadata);
}

#[test]
fn prover_context_rejects_mismatched_metadata() {
    let fixture = load_consensus_fixture();
    let verifying_blob = decode_base64(&fixture.verifying_key.value);
    let verifying_key =
        VerifyingKey::from_bytes(verifying_blob, &fixture.circuit).expect("verifying key decodes");
    let verifying_metadata = Arc::clone(verifying_key.air_metadata());
    let proving_blob = decode_base64(&fixture.proving_key.value);
    let proving_key = ProvingKey::from_bytes(
        proving_blob,
        &fixture.circuit,
        Some(verifying_key.air_metadata()),
    )
    .expect("proving key decodes");

    let tampered: AirMetadata = serde_json::from_value(json!({
        "air": {"log_blowup": 7},
        "generator": "poseidon",
    }))
    .expect("metadata parses");
    let tampered = Arc::new(tampered);
    let verifying_key = verifying_key.with_metadata(Arc::clone(&tampered));

    let err = ProverContext::new(&fixture.circuit, verifying_key, proving_key, 64, false)
        .expect_err("metadata mismatch must fail");
    match err {
        plonky3_backend::BackendError::InvalidKeyEncoding { kind, message, .. } => {
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
fn stark_config_builder_parses_metadata() {
    let metadata: AirMetadata = serde_json::from_value(json!({
        "air": {
            "challenge_extension_degree": 4,
            "fri": {
                "log_blowup": 6,
                "log_final_poly_len": 3,
                "num_queries": 88,
                "proof_of_work_bits": 21,
            },
            "challenger": {
                "width": 24,
                "rate": 16,
            }
        }
    }))
    .expect("metadata parses");

    let bundle = CircuitConfigBuilder::new(&metadata, 64, false)
        .build("test")
        .expect("config builds");
    let config = bundle.stark_config();
    let pcs_debug = format!("{:?}", config.pcs());
    assert!(
        pcs_debug.contains("log_blowup: 6"),
        "unexpected pcs debug output: {pcs_debug}"
    );
    assert!(
        pcs_debug.contains("log_final_poly_len: 3"),
        "unexpected pcs debug output: {pcs_debug}"
    );
    assert!(
        pcs_debug.contains("num_queries: 88"),
        "unexpected pcs debug output: {pcs_debug}"
    );
    assert!(
        pcs_debug.contains("proof_of_work_bits: 21"),
        "unexpected pcs debug output: {pcs_debug}"
    );

    let mut challenger = config.initialise_challenger();
    assert_eq!(challenger.sponge_state.len(), 24);
    assert!(bundle.derived_security_bits() >= 64);
    assert!(challenger.input_buffer.is_empty());

    for _ in 0..15 {
        challenger.observe(CircuitBaseField::ONE);
    }
    assert_eq!(challenger.input_buffer.len(), 15);

    challenger.observe(CircuitBaseField::ONE);
    assert!(challenger.input_buffer.is_empty());
    assert_eq!(challenger.output_buffer.len(), 16);
}

#[test]
fn circuit_config_builder_rejects_excessive_security_bits() {
    let metadata: AirMetadata = serde_json::from_value(json!({
        "air": {
            "fri": {
                "log_blowup": 5,
                "log_final_poly_len": 2,
                "num_queries": 10,
                "proof_of_work_bits": 8,
            }
        }
    }))
    .expect("metadata parses");

    let baseline = CircuitConfigBuilder::new(&metadata, 1, false)
        .build("test")
        .expect("baseline config builds");
    let derived = baseline.derived_security_bits();
    let requested = derived + 1;
    let err = CircuitConfigBuilder::new(&metadata, requested, false)
        .build("test")
        .expect_err("excessive security bits must fail");
    match err {
        BackendError::InsufficientSecurity {
            requested: actual_requested,
            available,
            ..
        } => {
            assert_eq!(actual_requested, requested);
            assert_eq!(available, derived);
        }
        other => panic!("unexpected error: {other:?}"),
    }
}

#[cfg(not(feature = "plonky3-gpu"))]
#[test]
fn circuit_config_builder_errors_without_gpu_support() {
    let metadata: AirMetadata = serde_json::from_value(json!({"air": {"fri": {"log_blowup": 5}}}))
        .expect("metadata parses");

    let err = CircuitConfigBuilder::new(&metadata, 32, true)
        .build("test")
        .expect_err("GPU builds must fail without feature");
    match err {
        BackendError::GpuInitialization { message, .. } => {
            assert!(
                message.contains("GPU support"),
                "unexpected GPU error message: {message}"
            );
        }
        other => panic!("unexpected error: {other:?}"),
    }
}
