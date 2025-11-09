use super::{
    ErrorResponse, PipelineWaitRequest, PipelineWaitResponse, RuntimeModeResponse, SignTxRequest,
    SignTxResponse, ValidatorPeerResponse, ValidatorProofQueueResponse,
};
use jsonschema::{Draft, JSONSchema};
use serde::de::DeserializeOwned;
use serde::Serialize;
use serde_json::Value;
use std::fs;
use std::path::{Path, PathBuf};

fn interfaces_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../docs/interfaces")
}

fn load_json(path: &Path) -> Value {
    let raw = fs::read_to_string(path)
        .unwrap_or_else(|err| panic!("unable to read {}: {err}", path.display()));
    serde_json::from_str(&raw)
        .unwrap_or_else(|err| panic!("invalid JSON in {}: {err}", path.display()))
}

fn resolve_refs(value: &mut Value, base: &Path) {
    match value {
        Value::Object(map) => {
            if let Some(reference) = map.get("$ref").and_then(Value::as_str) {
                let target_path = base.join(reference);
                let mut target = load_json(&target_path);
                let target_base = target_path
                    .parent()
                    .map(Path::to_path_buf)
                    .unwrap_or_else(|| base.to_path_buf());
                resolve_refs(&mut target, &target_base);
                *value = target;
            } else {
                for sub in map.values_mut() {
                    resolve_refs(sub, base);
                }
            }
        }
        Value::Array(items) => {
            for item in items {
                resolve_refs(item, base);
            }
        }
        _ => {}
    }
}

fn load_schema(segment: &str) -> Value {
    let path = interfaces_dir().join(segment);
    let mut schema = load_json(&path);
    let base = path
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(|| interfaces_dir());
    resolve_refs(&mut schema, &base);
    schema
}

fn load_example(segment: &str) -> Value {
    load_json(&interfaces_dir().join(segment))
}

fn assert_roundtrip<T>(schema_file: &str, example_file: &str)
where
    T: Serialize + DeserializeOwned,
{
    let schema = load_schema(schema_file);
    let compiled = JSONSchema::options()
        .with_draft(Draft::Draft202012)
        .compile(&schema)
        .expect("schema compiles");
    let example = load_example(example_file);
    compiled.validate(&example).expect("example matches schema");
    let typed: T = serde_json::from_value(example.clone()).expect("deserialize example");
    let roundtrip = serde_json::to_value(&typed).expect("serialize payload");
    assert_eq!(roundtrip, example);
}

#[test]
fn runtime_mode_response_schema_roundtrip() {
    assert_roundtrip::<RuntimeModeResponse>(
        "rpc/runtime_mode_response.jsonschema",
        "rpc/examples/runtime_mode_response.json",
    );
}

#[test]
fn sign_tx_request_schema_roundtrip() {
    assert_roundtrip::<SignTxRequest>(
        "rpc/sign_tx_request.jsonschema",
        "rpc/examples/sign_tx_request.json",
    );
}

#[test]
fn sign_tx_response_schema_roundtrip() {
    assert_roundtrip::<SignTxResponse>(
        "rpc/sign_tx_response.jsonschema",
        "rpc/examples/sign_tx_response.json",
    );
}

#[test]
fn pipeline_wait_request_schema_roundtrip() {
    assert_roundtrip::<PipelineWaitRequest>(
        "rpc/pipeline_wait_request.jsonschema",
        "rpc/examples/pipeline_wait_request.json",
    );
}

#[test]
fn pipeline_wait_response_schema_roundtrip() {
    assert_roundtrip::<PipelineWaitResponse>(
        "rpc/pipeline_wait_response.jsonschema",
        "rpc/examples/pipeline_wait_response.json",
    );
}

#[test]
fn error_response_schema_roundtrip() {
    assert_roundtrip::<ErrorResponse>(
        "rpc/error_response.jsonschema",
        "rpc/examples/error_response.json",
    );
}

#[test]
fn validator_peer_response_schema_roundtrip() {
    assert_roundtrip::<ValidatorPeerResponse>(
        "rpc/validator_peer_response.jsonschema",
        "rpc/examples/validator_peer_response.json",
    );
}

#[test]
fn validator_proof_queue_response_schema_roundtrip() {
    assert_roundtrip::<ValidatorProofQueueResponse>(
        "rpc/validator_proof_queue_response.jsonschema",
        "rpc/examples/validator_proof_queue_response.json",
    );
}
