use super::{
    ErrorResponse, PipelineWaitRequest, PipelineWaitResponse, RuntimeModeResponse, SignTxRequest,
    SignTxResponse, ValidatorPeerResponse, ValidatorProofQueueResponse,
};
use chrono::{NaiveDate, Utc};
use jsonschema::{Draft, JSONSchema};
use semver::Version;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::fs;
use std::path::{Path, PathBuf};

fn interfaces_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../docs/interfaces")
}

fn deprecation_allowlist_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/rpc/deprecated_fields.toml")
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

#[derive(Debug, Deserialize, Default)]
struct DeprecationAllowlist {
    #[serde(default)]
    deprecated_fields: Vec<DeprecatedField>,
}

#[derive(Debug, Deserialize)]
struct DeprecatedField {
    schema: String,
    field: String,
    removal_version: String,
    expires_on: String,
    rationale: Option<String>,
}

fn load_deprecation_allowlist() -> DeprecationAllowlist {
    let path = deprecation_allowlist_path();
    let contents = fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("unable to read {}: {error}", path.display()));

    toml::from_str(&contents)
        .unwrap_or_else(|error| panic!("invalid TOML in {}: {error}", path.display()))
}

fn schema_has_field(schema: &Value, dotted_path: &str) -> bool {
    let mut cursor = schema;

    for segment in dotted_path.split('.') {
        let Value::Object(map) = cursor else {
            return false;
        };

        let Some(Value::Object(properties)) = map.get("properties").and_then(Value::as_object) else {
            return false;
        };

        match properties.get(segment) {
            Some(next) => {
                cursor = next;
            }
            None => return false,
        }
    }

    true
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

#[test]
fn deprecated_fields_require_version_bump_or_expiry() {
    let allowlist = load_deprecation_allowlist();
    let current_version = Version::parse(env!("CARGO_PKG_VERSION")).expect("valid package version");
    let today = Utc::now().date_naive();

    for entry in allowlist.deprecated_fields {
        let schema = load_schema(&entry.schema);
        let expires_on = NaiveDate::parse_from_str(&entry.expires_on, "%Y-%m-%d")
            .unwrap_or_else(|error| panic!("invalid expiry date for {}: {error}", entry.field));

        if today > expires_on {
            panic!(
                "Deprecation for `{field}` in `{schema}` expired on {expiry}. Remove the allowlist entry or extend the window with a new expiry date.",
                field = entry.field,
                schema = entry.schema,
                expiry = expires_on,
            );
        }

        let removal_version = Version::parse(&entry.removal_version)
            .unwrap_or_else(|error| panic!("invalid removal version for {}: {error}", entry.field));
        let field_present = schema_has_field(&schema, &entry.field);

        if !field_present && current_version < removal_version {
            panic!(
                "Deprecated RPC field `{field}` was removed from `{schema}` before the removal gate. Bump the workspace version to {removal} or wait until the deprecation expires on {expiry}.",
                field = entry.field,
                schema = entry.schema,
                removal = removal_version,
                expiry = entry.expires_on,
            );
        }
    }
}
