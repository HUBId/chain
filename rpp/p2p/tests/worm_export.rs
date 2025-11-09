use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use reqwest::blocking::Client as HttpClient;
use rpp_p2p::{
    AdmissionApprovalRecord, AdmissionPolicyChange, AdmissionPolicyLog, AdmissionPolicyLogOptions,
    CommandWormExporter, PolicySigner, PolicyTrustStore, S3WormExporter, WormExportSettings,
    WormRetention, WormRetentionMode,
};
use serde::Deserialize;
use serde_json::Value as JsonValue;
use tempfile::TempDir;

#[derive(Debug, Deserialize)]
struct StubObjectMetadata {
    bucket: String,
    key: String,
    stored_at: String,
    #[serde(default)]
    retain_until: Option<String>,
    #[serde(default)]
    retention_mode: Option<String>,
    size_bytes: u64,
    sha256: String,
    #[serde(default)]
    content_type: Option<String>,
}

fn build_policy_signer(dir: &Path, key_id: &str) -> PolicySigner {
    let key_path = dir.join(format!("{key_id}.toml"));
    let mut rng = OsRng;
    let signing_key = SigningKey::generate(&mut rng);
    let verifying_key = signing_key.verifying_key();
    let secret_hex = hex::encode(signing_key.to_bytes());
    let public_hex = hex::encode(verifying_key.to_bytes());
    let key_toml = format!("secret_key = \"{secret_hex}\"\npublic_key = \"{public_hex}\"\n");
    fs::write(&key_path, key_toml).expect("write signing key");

    let mut trust_store = BTreeMap::new();
    trust_store.insert(key_id.to_string(), public_hex.clone());
    let trust = PolicyTrustStore::from_hex(trust_store).expect("trust store");
    PolicySigner::with_filesystem_key(key_id.to_string(), key_path, trust).expect("policy signer")
}

fn worm_script() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("tools")
        .join("worm-export")
        .join("worm-export")
}

#[test]
fn command_exporter_streams_signed_entries() {
    let temp = TempDir::new().expect("tempdir");
    let audit_path = temp.path().join("audit.jsonl");
    let export_root = temp.path().join("worm");

    let mut env = BTreeMap::new();
    env.insert(
        "WORM_EXPORT_ROOT".to_string(),
        export_root.to_string_lossy().to_string(),
    );

    let exporter = CommandWormExporter::new(worm_script(), Vec::new(), env);
    let retention = WormRetention {
        min_days: 30,
        max_days: Some(90),
        mode: WormRetentionMode::Compliance,
    };
    let settings = WormExportSettings::new(Arc::new(exporter), retention, true).expect("settings");
    let mut options = AdmissionPolicyLogOptions::default();
    options.worm_export = Some(settings);
    let log = AdmissionPolicyLog::open_with_options(&audit_path, options).expect("open log");

    let signer = build_policy_signer(temp.path(), "worm-export");
    let approvals = vec![AdmissionApprovalRecord::new("operations", "alice")];
    let entry = log
        .append(
            "operator",
            Some("worm export test"),
            &approvals,
            AdmissionPolicyChange::Noop,
            Some(&signer),
        )
        .expect("append entry");

    assert!(entry.signature.is_some(), "entry should be signed");

    let mut exported_files = fs::read_dir(&export_root)
        .expect("export root")
        .filter_map(|res| res.ok())
        .filter(|entry| entry.path().extension().and_then(|ext| ext.to_str()) == Some("json"))
        .collect::<Vec<_>>();
    assert_eq!(exported_files.len(), 1, "expected single exported object");
    let exported_path = exported_files.remove(0).path();
    let exported_payload = fs::read_to_string(exported_path).expect("export payload");
    let exported_json: JsonValue = serde_json::from_str(&exported_payload).expect("json");
    assert_eq!(exported_json["id"].as_u64(), Some(entry.id));
    assert_eq!(exported_json["actor"].as_str(), Some("operator"));
    assert_eq!(
        exported_json["change"]
            .get("kind")
            .and_then(JsonValue::as_str),
        Some("noop")
    );

    let metadata = fs::read_to_string(export_root.join("retention.meta")).expect("metadata");
    assert!(metadata.contains("min_days=30"));
    assert!(metadata.contains("max_days=90"));
    assert!(metadata.contains("mode=COMPLIANCE"));
}

#[test]
fn command_exporter_rejects_unsigned_entries() {
    let temp = TempDir::new().expect("tempdir");
    let audit_path = temp.path().join("audit.jsonl");

    let mut env = BTreeMap::new();
    env.insert(
        "WORM_EXPORT_ROOT".to_string(),
        temp.path().join("worm").to_string_lossy().to_string(),
    );

    let exporter = CommandWormExporter::new(worm_script(), Vec::new(), env);
    let retention = WormRetention {
        min_days: 7,
        max_days: None,
        mode: WormRetentionMode::Governance,
    };
    let settings = WormExportSettings::new(Arc::new(exporter), retention, true).expect("settings");
    let mut options = AdmissionPolicyLogOptions::default();
    options.worm_export = Some(settings);
    let log = AdmissionPolicyLog::open_with_options(&audit_path, options).expect("open log");

    let approvals = vec![];
    let result = log.append(
        "operator",
        Some("missing signature"),
        &approvals,
        AdmissionPolicyChange::Noop,
        None,
    );
    assert!(result.is_err(), "unsigned entry should be rejected");
}

#[test]
fn s3_exporter_streams_entries_via_stub() {
    let endpoint = match std::env::var("WORM_EXPORT_STUB_ENDPOINT") {
        Ok(value) => value,
        Err(_) => {
            eprintln!("skipping S3 WORM export stub test: WORM_EXPORT_STUB_ENDPOINT not set");
            return;
        }
    };
    let endpoint = endpoint.trim_end_matches('/');
    if endpoint.is_empty() {
        eprintln!("skipping S3 WORM export stub test: endpoint is empty");
        return;
    }

    let temp = TempDir::new().expect("tempdir");
    let audit_path = temp.path().join("audit.jsonl");

    let retention = WormRetention {
        min_days: 30,
        max_days: Some(90),
        mode: WormRetentionMode::Compliance,
    };
    let exporter = S3WormExporter::new(
        "worm-audit".to_string(),
        "stub-region".to_string(),
        Some(endpoint.to_string()),
        Some("admission".to_string()),
        "stub-access".to_string(),
        "stub-secret".to_string(),
        None,
        true,
    )
    .expect("s3 exporter");
    let settings = WormExportSettings::new(Arc::new(exporter), retention, true).expect("settings");
    let mut options = AdmissionPolicyLogOptions::default();
    options.worm_export = Some(settings);
    let log = AdmissionPolicyLog::open_with_options(&audit_path, options).expect("open log");

    let signer = build_policy_signer(temp.path(), "worm-export-s3");
    let approvals = vec![AdmissionApprovalRecord::new("operations", "bob")];
    let entry = log
        .append(
            "operator",
            Some("worm export stub"),
            &approvals,
            AdmissionPolicyChange::Noop,
            Some(&signer),
        )
        .expect("append entry");

    assert!(entry.signature.is_some(), "entry should be signed");

    let object_name = format!("{:020}-{}.json", entry.timestamp_ms, entry.id);
    let object_url = format!(
        "{endpoint}/worm-audit/admission/{object}",
        endpoint = endpoint,
        object = object_name
    );

    let client = HttpClient::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .expect("http client");

    let response = client
        .get(&object_url)
        .send()
        .expect("fetch exported object");
    assert!(
        response.status().is_success(),
        "expected stub to return 200 for exported object, got {}",
        response.status()
    );
    let body = response.text().expect("exported object body");
    let exported_json: JsonValue = serde_json::from_str(&body).expect("decode exported json");
    assert_eq!(exported_json["id"].as_u64(), Some(entry.id));
    assert_eq!(exported_json["actor"].as_str(), Some("operator"));

    let list_url = format!("{endpoint}/_objects");
    let list_response = client
        .get(&list_url)
        .send()
        .expect("fetch metadata listing");
    assert!(
        list_response.status().is_success(),
        "expected metadata listing to succeed, got {}",
        list_response.status()
    );
    let list_body = list_response.text().expect("metadata listing body");
    let objects: Vec<StubObjectMetadata> =
        serde_json::from_str(&list_body).expect("decode metadata listing");

    let expected_key = format!("admission/{object_name}");
    let metadata = objects
        .into_iter()
        .find(|object| object.bucket == "worm-audit" && object.key == expected_key)
        .expect("metadata for exported object");
    assert_eq!(metadata.size_bytes, body.as_bytes().len() as u64);
    assert_eq!(metadata.retention_mode.as_deref(), Some("COMPLIANCE"));
    let expected_retain = retention
        .retain_until_string(entry.timestamp_ms)
        .expect("retain until");
    assert_eq!(
        metadata.retain_until.as_deref(),
        Some(expected_retain.as_str())
    );
    assert_eq!(metadata.content_type.as_deref(), Some("application/json"));
    assert_eq!(metadata.sha256.len(), 64, "sha256 should be 64 hex chars");
}
