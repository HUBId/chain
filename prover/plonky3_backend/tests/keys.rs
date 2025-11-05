use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::Engine;
use blake3::hash;
use flate2::read::GzDecoder;
use plonky3_backend::{AirMetadata, ProofMetadata, ProverContext, ProvingKey, VerifyingKey};
use serde::Deserialize;
use serde_json::json;
use std::fs;
use std::io::Read;
use std::sync::Arc;

#[derive(Deserialize)]
struct FixtureKey {
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

fn decompress_gzip(bytes: &[u8]) -> Vec<u8> {
    let mut decoder = GzDecoder::new(bytes);
    let mut decompressed = Vec::new();
    decoder
        .read_to_end(&mut decompressed)
        .expect("decompress gzip payload");
    decompressed
}

#[test]
fn verifying_key_roundtrip_base64_gzip() {
    let fixture = load_consensus_fixture();
    let encoded_blob = decode_base64(&fixture.verifying_key.value);
    let key = VerifyingKey::from_encoded_parts(
        &fixture.verifying_key.value,
        "base64",
        fixture.verifying_key.compression.as_deref(),
        &fixture.circuit,
    )
    .expect("verifying key decodes");
    let raw = decompress_gzip(&encoded_blob);
    assert_eq!(key.bytes(), raw.as_slice());
    assert_eq!(key.hash(), *hash(&encoded_blob).as_bytes());
    let metadata = key.metadata();
    assert_eq!(metadata.digest().is_some(), !metadata.is_empty());
}

#[test]
fn proving_key_roundtrip_base64_gzip() {
    let fixture = load_consensus_fixture();
    let encoded_blob = decode_base64(&fixture.proving_key.value);
    let key = ProvingKey::from_encoded_parts(
        &fixture.proving_key.value,
        "base64",
        fixture.proving_key.compression.as_deref(),
        &fixture.circuit,
        None,
    )
    .expect("proving key decodes");
    let raw = decompress_gzip(&encoded_blob);
    assert_eq!(key.bytes(), raw.as_slice());
    assert_eq!(key.hash(), *hash(&encoded_blob).as_bytes());
    let metadata = key.metadata();
    assert_eq!(metadata.digest().is_some(), !metadata.is_empty());
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
        "description": "Hex-encoded transcript and security parameters embedded in a Plonky3 proof payload.",
        "properties": {
            "verifying_key_hash": {
                "type": "string",
                "pattern": "^[0-9a-fA-F]{64}$",
                "description": "BLAKE3 digest of the verifying key referenced by the proof."
            },
            "public_inputs_hash": {
                "type": "string",
                "pattern": "^[0-9a-fA-F]{64}$",
                "description": "BLAKE3 digest of the encoded public inputs."
            },
            "fri_digest": {
                "type": "string",
                "pattern": "^[0-9a-fA-F]{64}$",
                "description": "BLAKE3 digest derived from the prover/verifier transcript."
            },
            "security_bits": {
                "type": "integer",
                "minimum": 1,
                "description": "Security parameter negotiated between prover and verifier."
            },
            "use_gpu": {
                "type": "boolean",
                "description": "Indicates whether the proof was constructed with GPU acceleration."
            }
        },
        "required": [
            "verifying_key_hash",
            "public_inputs_hash",
            "fri_digest",
            "security_bits",
            "use_gpu"
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
    let verifying_metadata = verifying_key.metadata();
    let proving_blob = decode_base64(&fixture.proving_key.value);
    let proving_key =
        ProvingKey::from_bytes(proving_blob, &fixture.circuit, Some(&verifying_metadata))
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
