use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::Engine;
use blake3::hash;
use flate2::{write::GzEncoder, Compression};
use plonky3_backend::{ProofMetadata, ProvingKey, VerifyingKey};
use serde_json::json;
use std::io::Write;

fn encode_gzip_base64(bytes: &[u8]) -> String {
    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(bytes).expect("write raw bytes");
    let compressed = encoder.finish().expect("finish gzip");
    BASE64_STANDARD.encode(compressed)
}

#[test]
fn verifying_key_roundtrip_base64_gzip() {
    let raw = vec![0x11; 48];
    let encoded = encode_gzip_base64(&raw);
    let key = VerifyingKey::from_encoded_parts(&encoded, "base64", Some("gzip"), "consensus")
        .expect("verifying key decodes");
    assert_eq!(key.bytes(), raw.as_slice());
    assert_eq!(key.hash(), *hash(&raw).as_bytes());
}

#[test]
fn proving_key_roundtrip_base64_gzip() {
    let raw = vec![0x22; 96];
    let encoded = encode_gzip_base64(&raw);
    let key = ProvingKey::from_encoded_parts(&encoded, "base64", Some("gzip"), "consensus")
        .expect("proving key decodes");
    assert_eq!(key.bytes(), raw.as_slice());
    assert_eq!(key.hash(), *hash(&raw).as_bytes());
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
