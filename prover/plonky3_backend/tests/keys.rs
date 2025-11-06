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

fn decode_fixture_key_bytes(label: &str, key: &FixtureKey) -> Vec<u8> {
    assert!(
        key.byte_length > 0,
        "{label} key fixture must advertise a non-zero payload length",
    );
    let decoded = decode_base64(&key.value);
    let decompressed = match key.compression.as_deref() {
        Some("gzip") => decompress_gzip(&decoded),
        Some("none") | None => decoded,
        Some(other) => panic!("unsupported fixture compression: {other}"),
    };
    assert_eq!(
        decompressed.len(),
        key.byte_length,
        "{label} key fixture decompressed length must match byte_length",
    );
    if let Some(expected_hash) = &key.hash_blake3 {
        let expected =
            hex_decode(expected_hash).expect("fixture hash must be valid hexadecimal digest");
        assert_eq!(
            expected.as_slice(),
            hash(&decompressed).as_bytes(),
            "{label} key fixture digest must match decoded payload",
        );
    }
    decompressed
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

fn encode_fixture_key_bytes(bytes: &[u8], key: &FixtureKey) -> String {
    let compressed = match key.compression.as_deref() {
        Some("gzip") => compress_gzip(bytes),
        Some("none") | None => bytes.to_vec(),
        Some(other) => panic!("unsupported fixture compression: {other}"),
    };
    match key.encoding.as_str() {
        "base64" => BASE64_STANDARD.encode(&compressed),
        other => panic!("unsupported fixture encoding: {other}"),
    }
}

#[test]
fn consensus_fixture_descriptor_decodes_typed_keys() {
    let fixture = load_consensus_fixture();

    let verifying_fixture_raw = decode_fixture_key_bytes("verifying", &fixture.verifying_key);
    let (fixture_metadata, fixture_verifying_key): (AirMetadata, CircuitStarkVerifyingKey) =
        bincode::deserialize(&verifying_fixture_raw).expect("parse verifying key fixture");
    let verifying_roundtrip_raw =
        bincode::serialize(&(fixture_metadata.clone(), &fixture_verifying_key))
            .expect("serialize verifying tuple");
    assert_eq!(verifying_roundtrip_raw, verifying_fixture_raw);

    let verifying_encoded_bytes = decode_base64(&fixture.verifying_key.value);

    let verifying_key = VerifyingKey::from_encoded_parts(
        &fixture.verifying_key.value,
        &fixture.verifying_key.encoding,
        fixture.verifying_key.compression.as_deref(),
        &fixture.circuit,
    )
    .expect("verifying key decodes");
    assert_eq!(verifying_key.bytes(), verifying_fixture_raw.as_slice());
    assert_eq!(verifying_key.bytes().len(), verifying_fixture_raw.len());
    assert_eq!(
        verifying_key.hash(),
        *hash(&verifying_encoded_bytes).as_bytes()
    );
    assert_eq!(
        encode_fixture_key_bytes(verifying_key.bytes(), &fixture.verifying_key),
        fixture.verifying_key.value
    );

    let verifying_stark = verifying_key.stark_key();
    assert_eq!(verifying_stark.air(), ToolchainAir::Consensus);
    assert_eq!(verifying_stark.len(), verifying_fixture_raw.len());
    let verifying_stark_again = verifying_key.stark_key();
    assert!(Arc::ptr_eq(verifying_stark, verifying_stark_again));
    let verifying_inner = verifying_stark.key().key();
    assert_eq!(verifying_inner.as_ref(), &fixture_verifying_key);

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
    assert_eq!(verifying_metadata.as_ref(), &fixture_metadata);
    let verifying_metadata_again = verifying_key.air_metadata();
    assert!(Arc::ptr_eq(verifying_metadata, verifying_metadata_again));

    let verifying_metadata_arc = Arc::clone(verifying_metadata);

    let proving_fixture_raw = decode_fixture_key_bytes("proving", &fixture.proving_key);
    let (proving_metadata, fixture_proving_key): (AirMetadata, CircuitStarkProvingKey) =
        bincode::deserialize(&proving_fixture_raw).expect("parse proving key fixture");
    assert_eq!(fixture_metadata, proving_metadata);

    let proving_roundtrip_raw =
        bincode::serialize(&(fixture_metadata.clone(), &fixture_proving_key))
            .expect("serialize proving tuple");
    assert_eq!(proving_roundtrip_raw, proving_fixture_raw);

    let proving_encoded_bytes = decode_base64(&fixture.proving_key.value);

    let proving_key = ProvingKey::from_encoded_parts(
        &fixture.proving_key.value,
        &fixture.proving_key.encoding,
        fixture.proving_key.compression.as_deref(),
        &fixture.circuit,
        Some(&verifying_metadata_arc),
    )
    .expect("proving key decodes");
    assert_eq!(proving_key.bytes(), proving_fixture_raw.as_slice());
    assert_eq!(proving_key.bytes().len(), proving_fixture_raw.len());
    assert_eq!(proving_key.hash(), *hash(&proving_encoded_bytes).as_bytes());
    assert_eq!(
        encode_fixture_key_bytes(proving_key.bytes(), &fixture.proving_key),
        fixture.proving_key.value
    );

    let proving_stark = proving_key.stark_key();
    assert_eq!(proving_stark.air(), ToolchainAir::Consensus);
    assert_eq!(proving_stark.len(), proving_fixture_raw.len());
    let proving_stark_again = proving_key.stark_key();
    assert!(Arc::ptr_eq(proving_stark, proving_stark_again));
    let proving_inner = proving_stark.key().key();
    assert_eq!(proving_inner.as_ref(), &fixture_proving_key);

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
    assert_eq!(proving_reserialized, proving_fixture_raw);
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
        "description": "Transcript commitments, challenger checkpoints, and security parameters embedded in a Plonky3 proof payload.",
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
            "canonical_public_inputs": {
                "type": "string",
                "contentEncoding": "base64",
                "description": "Canonical JSON encoding of the public inputs observed by the verifier."
            },
            "transcript": {
                "type": "object",
                "properties": {
                    "degree_bits": {
                        "type": "integer",
                        "minimum": 1,
                        "description": "Binary logarithm of the low-degree extension used during proof generation."
                    },
                    "trace_length_bits": {
                        "type": "integer",
                        "minimum": 1,
                        "description": "Binary logarithm of the execution trace length observed by the verifier."
                    },
                    "alpha": {
                        "type": "array",
                        "items": {
                            "type": "integer",
                            "minimum": 0,
                            "description": "Little-endian BabyBear limb"
                        },
                        "minItems": 4,
                        "maxItems": 4,
                        "description": "Main relation challenge alpha sampled from the transcript."
                    },
                    "zeta": {
                        "type": "array",
                        "items": {
                            "type": "integer",
                            "minimum": 0,
                            "description": "Little-endian BabyBear limb"
                        },
                        "minItems": 4,
                        "maxItems": 4,
                        "description": "Evaluation challenge zeta binding the quotient polynomial."
                    },
                    "pcs_alpha": {
                        "type": "array",
                        "items": {
                            "type": "integer",
                            "minimum": 0,
                            "description": "Little-endian BabyBear limb"
                        },
                        "minItems": 4,
                        "maxItems": 4,
                        "description": "Polynomial commitment challenge alpha issued before FRI."
                    },
                    "fri_challenges": {
                        "type": "array",
                        "items": {
                            "type": "array",
                            "items": {
                                "type": "integer",
                                "minimum": 0,
                                "description": "Little-endian BabyBear limb"
                            },
                            "minItems": 4,
                            "maxItems": 4,
                            "description": "FRI folding challenge"
                        },
                        "minItems": 1,
                        "description": "Sequence of FRI folding challenges sampled for each commit-phase round."
                    },
                    "query_indices": {
                        "type": "array",
                        "items": {
                            "type": "integer",
                            "minimum": 0,
                            "description": "Unsigned 32-bit integer"
                        },
                        "minItems": 1,
                        "description": "Indices sampled during the Fiat-Shamir query phase (little-endian representation)."
                    },
                    "checkpoints": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "properties": {
                                "stage": {
                                    "type": "string",
                                    "enum": [
                                        "after_public_values",
                                        "after_commitments",
                                        "after_zeta_sampling",
                                        "after_query_sampling"
                                    ],
                                    "description": "Transcript stage identifier capturing the challenger state."
                                },
                                "state": {
                                    "type": "string",
                                    "contentEncoding": "base64",
                                    "description": "Little-endian BabyBear encoding of the challenger sponge, input buffer, and output buffer at the recorded stage."
                                }
                            },
                            "required": ["stage", "state"],
                            "additionalProperties": false
                        },
                        "minItems": 3,
                        "description": "Deterministic checkpoints of the Fiat-Shamir challenger transcript used for external auditing."
                    }
                },
                "required": [
                    "degree_bits",
                    "trace_length_bits",
                    "alpha",
                    "zeta",
                    "pcs_alpha",
                    "fri_challenges",
                    "query_indices",
                    "checkpoints"
                ],
                "additionalProperties": false
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
            "canonical_public_inputs",
            "transcript",
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
