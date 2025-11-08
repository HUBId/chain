use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use rpp_p2p::{
    AdmissionApprovalRecord, AdmissionPolicyChange, AdmissionPolicyLog, AdmissionPolicyLogOptions,
    CommandWormExporter, PolicySigner, PolicyTrustStore, WormExportSettings, WormRetention,
    WormRetentionMode,
};
use serde_json::Value as JsonValue;
use tempfile::TempDir;

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
