use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::env;
use std::fmt::Write as _;
use std::fs::{self, File};
use std::io::{BufRead, BufReader, Read};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;
use std::time::{Duration as StdDuration, SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, bail, Context, Result};
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use blake3::hash as blake3_hash;
use ed25519_dalek::SigningKey;
use flate2::read::GzDecoder;
use flate2::write::GzEncoder;
use flate2::Compression;
use hex::encode as hex_encode;
use jsonschema::{Draft, JSONSchema};
use rand::rngs::OsRng;
use reqwest::blocking::Client as HttpClient;
use rpp_p2p::{
    AdmissionApprovalRecord, AdmissionPolicyChange, AdmissionPolicyLog, AdmissionPolicyLogEntry,
    AdmissionPolicyLogOptions, CommandWormExporter, PolicySignatureVerifier, PolicySigner,
    PolicyTrustStore, TierLevel, WormExportSettings, WormRetention, WormRetentionMode,
};
use serde::Deserialize;
use serde::Serialize;
use serde_json::Value as JsonValue;
use sha2::{Digest, Sha256};
use tar::Builder as TarBuilder;
use tempfile::TempDir;
use time::format_description::well_known::Rfc3339;
use time::macros::format_description;
use time::{Duration as TimeDuration, OffsetDateTime};
use walkdir::WalkDir;

mod cli_smoke;
mod release;
mod telemetry;
use telemetry::MetricsReporter;

pub(crate) fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("xtask lives in workspace root")
        .to_path_buf()
}

pub(crate) fn apply_feature_flags(command: &mut Command) {
    let no_defaults = env::var("XTASK_NO_DEFAULT_FEATURES")
        .map(|value| !value.trim().is_empty())
        .unwrap_or(false);
    if no_defaults {
        command.arg("--no-default-features");
    }
    if let Ok(features) = env::var("XTASK_FEATURES") {
        let trimmed = features.trim();
        if !trimmed.is_empty() {
            command.arg("--features").arg(trimmed);
        }
    }
}

fn integration_feature_list() -> String {
    let raw = env::var("XTASK_FEATURES").unwrap_or_default();
    let mut features: Vec<String> = raw
        .split(|ch: char| ch == ',' || ch.is_whitespace())
        .filter_map(|segment| {
            let trimmed = segment.trim();
            if trimmed.is_empty() {
                None
            } else {
                Some(trimmed.to_string())
            }
        })
        .collect();

    if !features.iter().any(|feature| feature == "integration") {
        features.insert(0, "integration".to_string());
    }

    if features.is_empty() {
        "integration".to_string()
    } else {
        features.join(",")
    }
}

fn apply_integration_feature_flags(command: &mut Command) {
    let no_defaults = env::var("XTASK_NO_DEFAULT_FEATURES")
        .map(|value| !value.trim().is_empty())
        .unwrap_or(false);
    if no_defaults {
        command.arg("--no-default-features");
    }

    let features = integration_feature_list();
    command.arg("--features").arg(features);
}

fn run_command(mut command: Command, context: &str) -> Result<()> {
    let status = command.status()?;
    if status.success() {
        Ok(())
    } else {
        bail!("{context} exited with status {status}");
    }
}

fn run_pruning_validation() -> Result<()> {
    let mut command = Command::new("cargo");
    command
        .current_dir(workspace_root())
        .arg("test")
        .arg("-p")
        .arg("rpp-chain")
        .arg("--locked")
        .arg("--test")
        .arg("pruning_validation");
    apply_feature_flags(&mut command);
    run_command(command, "pruning validation")
}

fn run_unit_suites() -> Result<()> {
    let root = workspace_root();

    let mut library = Command::new("cargo");
    library
        .current_dir(&root)
        .arg("test")
        .arg("-p")
        .arg("rpp-chain")
        .arg("--locked")
        .arg("--lib");
    apply_feature_flags(&mut library);
    run_command(library, "rpp-chain library tests")?;

    let mut command = Command::new("cargo");
    command
        .current_dir(&root)
        .arg("test")
        .arg("-p")
        .arg("rpp-chain")
        .arg("--locked")
        .arg("--test")
        .arg("unit");
    apply_feature_flags(&mut command);
    run_command(command, "unit test suite")?;

    run_rpp_fail_matrix_tests()
}

fn run_rpp_fail_matrix_tests() -> Result<()> {
    let root = workspace_root();

    let mut default = Command::new("cargo");
    default
        .current_dir(&root)
        .arg("test")
        .arg("-p")
        .arg("rpp-chain")
        .arg("--locked")
        .arg("--test")
        .arg("rpp_fail_matrix");
    apply_feature_flags(&mut default);
    run_command(default, "rpp-stark fail-matrix (default)")?;

    let mut backend = Command::new("cargo");
    backend
        .current_dir(&root)
        .arg("test")
        .arg("-p")
        .arg("rpp-chain")
        .arg("--locked")
        .arg("--test")
        .arg("rpp_fail_matrix");
    apply_feature_flags(&mut backend);
    backend.arg("--features").arg("backend-rpp-stark");
    run_command(backend, "rpp-stark fail-matrix (backend)")
}

fn run_firewood_feature_matrix() -> Result<()> {
    let root = workspace_root();

    let mut default = Command::new("cargo");
    default
        .current_dir(&root)
        .arg("test")
        .arg("-p")
        .arg("firewood")
        .arg("--locked");
    run_command(default, "firewood unit tests (default branch factor)")?;

    let mut branch_factor_256 = Command::new("cargo");
    branch_factor_256
        .current_dir(&root)
        .arg("test")
        .arg("-p")
        .arg("firewood")
        .arg("--locked")
        .arg("--features")
        .arg("branch_factor_256");
    run_command(branch_factor_256, "firewood unit tests (branch_factor_256)")
}

fn run_integration_workflows() -> Result<()> {
    let root = workspace_root();

    let mut command = Command::new("cargo");
    command
        .current_dir(&root)
        .arg("test")
        .arg("-p")
        .arg("rpp-chain")
        .arg("--locked")
        .arg("--test")
        .arg("integration");
    apply_integration_feature_flags(&mut command);
    run_command(command, "integration workflows")?;

    let mut lifecycle = Command::new("cargo");
    lifecycle
        .current_dir(&root)
        .arg("test")
        .arg("-p")
        .arg("rpp-chain")
        .arg("--locked")
        .arg("--test")
        .arg("node_lifecycle");
    apply_integration_feature_flags(&mut lifecycle);
    run_command(lifecycle, "node lifecycle workflows")?;

    let mut restart = Command::new("cargo");
    restart
        .current_dir(&root)
        .arg("test")
        .arg("-p")
        .arg("rpp-chain")
        .arg("--locked")
        .arg("--test")
        .arg("snapshot_checksum_restart");
    apply_integration_feature_flags(&mut restart);
    run_command(restart, "snapshot checksum restart")
}

fn run_observability_suite() -> Result<()> {
    let mut command = Command::new("cargo");
    command
        .current_dir(workspace_root())
        .arg("test")
        .arg("-p")
        .arg("rpp-chain")
        .arg("--locked")
        .arg("--test")
        .arg("observability_metrics");
    apply_feature_flags(&mut command);
    run_command(command, "observability metrics")
}

fn run_simnet_smoke() -> Result<()> {
    let mut scenarios = vec![
        "tools/simnet/scenarios/ci_block_pipeline.ron",
        "tools/simnet/scenarios/ci_state_sync_guard.ron",
        "tools/simnet/scenarios/consensus_quorum_stress.ron",
        "tools/simnet/scenarios/snapshot_partition.ron",
    ];
    if has_feature_flag("backend-rpp-stark") {
        scenarios.push("tools/simnet/scenarios/consensus_reorg_stark.ron");
    }
    for scenario in scenarios {
        let scenario_path = workspace_root().join(scenario);
        let stem = Path::new(scenario)
            .file_stem()
            .and_then(|stem| stem.to_str())
            .unwrap_or("ci-simnet");
        let artifacts = workspace_root()
            .join("target/simnet")
            .join(stem.replace('_', "-"));
        let mut command = Command::new("cargo");
        command
            .current_dir(workspace_root())
            .arg("run")
            .arg("--quiet")
            .arg("--package")
            .arg("simnet")
            .arg("--")
            .arg("--scenario")
            .arg(scenario_path)
            .arg("--artifacts-dir")
            .arg(artifacts);
        apply_feature_flags(&mut command);
        let context = format!("simnet scenario {stem}");
        run_command(command, &context)?;
    }
    Ok(())
}

fn has_feature_flag(flag: &str) -> bool {
    env::var("XTASK_FEATURES")
        .ok()
        .map(|value| {
            value
                .split(|ch: char| ch == ',' || ch.is_whitespace())
                .any(|segment| segment.trim() == flag)
        })
        .unwrap_or(false)
}

fn run_snapshot_verifier_smoke() -> Result<()> {
    let workspace = workspace_root();
    let smoke_root = workspace.join("target/snapshot-verifier-smoke");
    if smoke_root.exists() {
        fs::remove_dir_all(&smoke_root).with_context(|| {
            format!(
                "remove previous snapshot verifier smoke artefacts under {}",
                smoke_root.display()
            )
        })?;
    }
    let manifest_dir = smoke_root.join("snapshots/manifest");
    let chunks_dir = smoke_root.join("snapshots/chunks");
    fs::create_dir_all(&manifest_dir)
        .with_context(|| format!("create manifest directory {}", manifest_dir.display()))?;
    fs::create_dir_all(&chunks_dir)
        .with_context(|| format!("create chunk directory {}", chunks_dir.display()))?;

    let chunk_path = chunks_dir.join("chunk-000");
    let chunk_contents = b"phase-a-snapshot-smoke";
    fs::write(&chunk_path, chunk_contents)
        .with_context(|| format!("write chunk data {}", chunk_path.display()))?;
    let mut chunk_hasher = Sha256::new();
    chunk_hasher.update(chunk_contents);
    let chunk_hash = hex_encode(chunk_hasher.finalize());

    let manifest = serde_json::json!({
        "segments": [
            {
                "segment_name": "chunk-000",
                "size_bytes": chunk_contents.len() as u64,
                "sha256": chunk_hash,
            }
        ]
    });
    let manifest_path = manifest_dir.join("chunks.json");
    fs::write(&manifest_path, serde_json::to_vec_pretty(&manifest)?)
        .with_context(|| format!("write manifest {}", manifest_path.display()))?;
    let manifest_bytes = serde_json::to_vec(&manifest)?;

    let mut rng = OsRng;
    let signing_key = SigningKey::generate(&mut rng);
    let verifying_key = signing_key.verifying_key();
    let signature = signing_key.sign(&manifest_bytes);
    let public_hex = hex_encode(verifying_key.to_bytes());
    let signature_hex = hex_encode(signature.to_bytes());

    let public_key_path = smoke_root.join("snapshot-key.hex");
    fs::write(&public_key_path, &public_hex)
        .with_context(|| format!("write verifying key {}", public_key_path.display()))?;
    let signature_path = manifest_dir.join("chunks.json.sig");
    fs::write(&signature_path, &signature_hex)
        .with_context(|| format!("write signature {}", signature_path.display()))?;

    let report_path = manifest_dir.join("chunks-verify.json");
    let mut command = Command::new("cargo");
    command
        .current_dir(&workspace)
        .arg("run")
        .arg("--locked")
        .arg("--package")
        .arg("snapshot-verify")
        .arg("--")
        .arg("--manifest")
        .arg(&manifest_path)
        .arg("--signature")
        .arg(&signature_path)
        .arg("--public-key")
        .arg(&public_key_path)
        .arg("--chunk-root")
        .arg(&chunks_dir)
        .arg("--output")
        .arg(&report_path);
    run_command(command, "snapshot verifier smoke report")?;

    let report_bytes = fs::read(&report_path)
        .with_context(|| format!("read verifier report {}", report_path.display()))?;
    let report_json: serde_json::Value =
        serde_json::from_slice(&report_bytes).context("decode snapshot verifier report")?;
    let signature_valid = report_json
        .get("signature")
        .and_then(|value| value.get("signature_valid"))
        .and_then(|value| value.as_bool())
        .unwrap_or(false);
    let errors_empty = report_json
        .get("errors")
        .and_then(|value| value.as_array())
        .map(|array| array.is_empty())
        .unwrap_or(true);
    let summary = report_json
        .get("summary")
        .and_then(|value| value.as_object())
        .ok_or_else(|| anyhow!("snapshot verifier report missing summary"))?;
    let verified = summary
        .get("verified")
        .and_then(|value| value.as_u64())
        .unwrap_or(0);
    let segments_total = summary
        .get("segments_total")
        .and_then(|value| value.as_u64())
        .unwrap_or(0);
    let failure_counters = [
        "metadata_incomplete",
        "missing_files",
        "size_mismatches",
        "checksum_mismatches",
        "io_errors",
    ];
    let mut summary_ok = verified == segments_total;
    for key in &failure_counters {
        let value = summary
            .get(*key)
            .and_then(|value| value.as_u64())
            .unwrap_or(0);
        if value != 0 {
            summary_ok = false;
            break;
        }
    }
    if !(signature_valid && errors_empty && summary_ok) {
        bail!("snapshot verifier smoke report indicates a failure");
    }

    let manifest_rel = manifest_path
        .strip_prefix(&workspace)
        .unwrap_or(manifest_path.as_path());
    let report_rel = report_path
        .strip_prefix(&workspace)
        .unwrap_or(report_path.as_path());
    let aggregate_path = smoke_root.join("snapshot-verify-report.json");
    let aggregate = serde_json::json!({
        "generated_at": OffsetDateTime::now_utc().format(&Rfc3339)?,
        "reports": [
            {
                "manifest": relative_display_path(manifest_rel),
                "report": relative_display_path(report_rel),
                "signature_valid": true,
                "summary": report_json.get("summary").cloned().unwrap_or_else(|| serde_json::json!({})),
                "errors": report_json.get("errors").cloned().unwrap_or_else(|| serde_json::json!([])),
                "status": true,
            }
        ],
        "all_passed": true,
    });
    fs::write(&aggregate_path, serde_json::to_vec_pretty(&aggregate)?).with_context(|| {
        format!(
            "write aggregate verifier report {}",
            aggregate_path.display()
        )
    })?;

    let aggregate_bytes = fs::read(&aggregate_path).with_context(|| {
        format!(
            "read aggregate verifier report {}",
            aggregate_path.display()
        )
    })?;
    let digest = Sha256::digest(&aggregate_bytes);
    let hash_hex = hex_encode(digest);
    let sha_path = aggregate_path.with_extension("json.sha256");
    let sha_line = format!(
        "{hash_hex}  {}\n",
        aggregate_path
            .file_name()
            .and_then(|value| value.to_str())
            .unwrap_or("snapshot-verify-report.json")
    );
    fs::write(&sha_path, sha_line)
        .with_context(|| format!("write aggregate verifier hash {}", sha_path.display()))?;

    println!(
        "snapshot verifier smoke bundle written to {}",
        aggregate_path.display()
    );

    Ok(())
}

fn verify_snapshot_verifier_report(args: &[String]) -> Result<()> {
    let root = workspace_root();
    let mut report: Option<PathBuf> = None;
    let mut schema: Option<PathBuf> = None;

    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--report" => {
                let value = iter
                    .next()
                    .ok_or_else(|| anyhow!("--report requires a value"))?;
                report = Some(PathBuf::from(value));
            }
            "--schema" => {
                let value = iter
                    .next()
                    .ok_or_else(|| anyhow!("--schema requires a value"))?;
                schema = Some(PathBuf::from(value));
            }
            "--help" => {
                verify_report_usage();
                return Ok(());
            }
            other => {
                bail!("unknown argument '{other}' for verify-report");
            }
        }
    }

    let schema_path = schema
        .map(|path| {
            if path.is_absolute() {
                path
            } else {
                root.join(path)
            }
        })
        .unwrap_or_else(|| root.join("docs/interfaces/snapshot_verify_report.schema.json"));
    if !schema_path.exists() {
        bail!(
            "JSON schema {} not found; pass --schema to override the lookup",
            schema_path.display()
        );
    }

    let report_path = match report {
        Some(path) => {
            if path.is_absolute() {
                path
            } else {
                root.join(path)
            }
        }
        None => discover_snapshot_report(&root)?,
    };

    if !report_path.exists() {
        bail!(
            "snapshot verifier report {} not found",
            report_path.display()
        );
    }

    let schema_file = File::open(&schema_path)
        .with_context(|| format!("open snapshot verifier schema {}", schema_path.display()))?;
    let schema_json: JsonValue = serde_json::from_reader(schema_file)
        .with_context(|| format!("parse snapshot verifier schema {}", schema_path.display()))?;

    let report_file = File::open(&report_path)
        .with_context(|| format!("open snapshot verifier report {}", report_path.display()))?;
    let report_json: JsonValue = serde_json::from_reader(report_file)
        .with_context(|| format!("parse snapshot verifier report {}", report_path.display()))?;

    let compiled = JSONSchema::options()
        .with_draft(Draft::Draft202012)
        .compile(&schema_json)
        .context("compile snapshot verifier schema")?;

    match compiled.validate(&report_json) {
        Ok(_) => {
            println!(
                "snapshot verifier report {} matches schema {}",
                report_path.display(),
                schema_path.display()
            );
            Ok(())
        }
        Err(errors) => {
            eprintln!(
                "::error::Snapshot verifier report {} failed schema validation against {}",
                report_path.display(),
                schema_path.display()
            );
            for error in errors {
                eprintln!(" - {} at {}", error, error.instance_path);
            }
            bail!("snapshot verifier report schema validation failed");
        }
    }
}

fn discover_snapshot_report(root: &Path) -> Result<PathBuf> {
    let mut candidates: Vec<PathBuf> = Vec::new();
    for base in ["dist", "target"] {
        let dir = root.join(base);
        if !dir.exists() {
            continue;
        }
        for entry in WalkDir::new(&dir) {
            let entry = entry?;
            if !entry.file_type().is_file() {
                continue;
            }
            if entry
                .file_name()
                .to_str()
                .is_some_and(|name| name == "snapshot-verify-report.json")
            {
                candidates.push(entry.path().to_path_buf());
            }
        }
    }

    match candidates.len() {
        0 => bail!(
            "snapshot-verify-report.json not found; pass --report <path> to cargo xtask verify-report"
        ),
        1 => Ok(candidates.remove(0)),
        _ => {
            eprintln!("multiple snapshot verifier reports detected:");
            for path in &candidates {
                eprintln!(" - {}", path.display());
            }
            bail!("multiple snapshot verifier reports discovered; pass --report <path> to disambiguate");
        }
    }
}

#[derive(Serialize, Deserialize)]
struct WormExportSummaryEntry {
    entry_id: u64,
    export_object: String,
    actor: String,
    reason: Option<String>,
    approvals: Vec<AdmissionApprovalRecord>,
    signature_key: String,
    signature_valid: bool,
}

#[derive(Serialize, Deserialize)]
struct WormExportSummary {
    generated_at: String,
    audit_log: String,
    export_root: String,
    retention: WormRetention,
    retention_metadata: Option<String>,
    signer_key_id: String,
    signer_public_key_hex: String,
    entries: Vec<WormExportSummaryEntry>,
}

#[derive(Default, Serialize)]
struct WormRetentionCheckReport {
    generated_at: String,
    scanned_roots: Vec<String>,
    summaries: Vec<WormRetentionSummaryReport>,
    stale_entries: Vec<WormRetentionStaleEntry>,
    orphaned_entries: Vec<WormRetentionOrphanedEntry>,
    unsigned_records: Vec<WormRetentionUnsignedRecord>,
    warnings: Vec<String>,
}

#[derive(Default, Serialize)]
struct WormRetentionSummaryReport {
    summary_path: String,
    audit_log: String,
    export_root: String,
    retention: WormRetention,
    retention_metadata: Option<WormRetentionMetadataReport>,
    entries: Vec<WormRetentionEntryReport>,
    retention_logs: Vec<WormRetentionLogReport>,
    warnings: Vec<String>,
}

#[derive(Default, Serialize)]
struct WormRetentionMetadataReport {
    path: String,
    values: BTreeMap<String, String>,
    valid: bool,
    warnings: Vec<String>,
}

#[derive(Default, Serialize)]
struct WormRetentionEntryReport {
    entry_id: u64,
    timestamp_ms: u64,
    export_object: String,
    retain_until: String,
    stale: bool,
}

#[derive(Default, Serialize)]
struct WormRetentionLogReport {
    path: String,
    record_count: usize,
    unsigned_records: usize,
}

#[derive(Default, Serialize)]
struct WormRetentionStaleEntry {
    summary_path: String,
    entry_id: u64,
    export_object: String,
    retain_until: String,
}

#[derive(Default, Serialize)]
struct WormRetentionOrphanedEntry {
    summary_path: String,
    entry_id: u64,
    context: String,
}

#[derive(Default, Serialize)]
struct WormRetentionUnsignedRecord {
    log_path: String,
    entry_id: u64,
    reason: String,
}

struct WormRetentionCheckOutcome {
    report: WormRetentionCheckReport,
    report_path: PathBuf,
}

impl WormRetentionCheckOutcome {
    fn has_failures(&self) -> bool {
        !(self.report.stale_entries.is_empty()
            && self.report.orphaned_entries.is_empty()
            && self.report.unsigned_records.is_empty())
    }

    fn failure_summary(&self) -> String {
        let mut reasons = Vec::new();
        if !self.report.stale_entries.is_empty() {
            reasons.push(format!("{} stale entries", self.report.stale_entries.len()));
        }
        if !self.report.orphaned_entries.is_empty() {
            reasons.push(format!(
                "{} orphaned audit/export records",
                self.report.orphaned_entries.len()
            ));
        }
        if !self.report.unsigned_records.is_empty() {
            reasons.push(format!(
                "{} unsigned retention log records",
                self.report.unsigned_records.len()
            ));
        }
        reasons.join(", ")
    }

    fn ensure_success(&self) -> Result<()> {
        if self.has_failures() {
            bail!(
                "worm retention check failed: {} (see {})",
                self.failure_summary(),
                self.report_path.display()
            );
        }
        Ok(())
    }
}

struct WormRetentionSummaryEvaluation {
    report: WormRetentionSummaryReport,
    stale_entries: Vec<WormRetentionStaleEntry>,
    orphaned_entries: Vec<WormRetentionOrphanedEntry>,
    unsigned_records: Vec<WormRetentionUnsignedRecord>,
    warnings: Vec<String>,
}

fn initialise_policy_signer(dir: &Path) -> Result<(PolicySigner, String)> {
    fs::create_dir_all(dir)?;
    let key_path = dir.join("worm-export.toml");
    let mut rng = OsRng;
    let signing_key = SigningKey::generate(&mut rng);
    let public_hex = hex_encode(signing_key.verifying_key().to_bytes());
    let secret_hex = hex_encode(signing_key.to_bytes());
    let key_toml = format!("secret_key = \"{secret_hex}\"\npublic_key = \"{public_hex}\"\n");
    fs::write(&key_path, key_toml).context("write generated WORM signing key")?;

    let mut trust_store = BTreeMap::new();
    trust_store.insert("worm-export".to_string(), public_hex.clone());
    let trust = PolicyTrustStore::from_hex(trust_store)
        .context("construct policy trust store for WORM signer")?;
    let signer = PolicySigner::with_filesystem_key("worm-export".to_string(), key_path, trust)
        .context("initialise policy signer for WORM smoke test")?;

    Ok((signer, public_hex))
}

fn load_latest_audit_entry(path: &Path) -> Result<AdmissionPolicyLogEntry> {
    let file = File::open(path).with_context(|| format!("open audit log {path:?}"))?;
    let reader = BufReader::new(file);
    let mut last_line = None;
    for line in reader.lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        last_line = Some(line);
    }
    let line =
        last_line.ok_or_else(|| anyhow!("audit log {path:?} did not contain any entries"))?;
    serde_json::from_str(&line).with_context(|| "decode audit log entry".to_string())
}

fn verify_exported_entries(
    workspace: &Path,
    export_root: &Path,
    signer: &PolicySigner,
) -> Result<Vec<WormExportSummaryEntry>> {
    let mut entries = Vec::new();
    let mut exported = Vec::new();
    if export_root.exists() {
        for item in fs::read_dir(export_root)? {
            let item = item?;
            let path = item.path();
            if path
                .extension()
                .and_then(|ext| ext.to_str())
                .map(|ext| ext.eq_ignore_ascii_case("json"))
                .unwrap_or(false)
            {
                exported.push(path);
            }
        }
    }
    if exported.is_empty() {
        bail!(
            "WORM export smoke test did not produce any exported JSON objects under {}",
            export_root.display()
        );
    }
    exported.sort();

    for path in exported {
        let contents = fs::read_to_string(&path)
            .with_context(|| format!("read exported WORM object {}", path.display()))?;
        let entry: AdmissionPolicyLogEntry = serde_json::from_str(&contents)
            .with_context(|| format!("decode exported WORM object {}", path.display()))?;
        let signature = entry
            .signature
            .as_ref()
            .ok_or_else(|| anyhow!("exported entry {} is missing a signature", entry.id))?;
        let canonical = entry.canonical_bytes()?;
        signer
            .verify(signature, &canonical)
            .with_context(|| format!("verify signature for exported entry {}", entry.id))?;

        let relative = path.strip_prefix(workspace).unwrap_or(path.as_path());
        entries.push(WormExportSummaryEntry {
            entry_id: entry.id,
            export_object: relative_display_path(relative),
            actor: entry.actor,
            reason: entry.reason,
            approvals: entry.approvals,
            signature_key: signature.key_id.clone(),
            signature_valid: true,
        });
    }

    Ok(entries)
}

fn run_worm_export_smoke() -> Result<()> {
    let workspace = workspace_root();
    let smoke_root = workspace.join("target/worm-export-smoke");
    if smoke_root.exists() {
        fs::remove_dir_all(&smoke_root).with_context(|| {
            format!(
                "remove previous WORM smoke artefacts under {}",
                smoke_root.display()
            )
        })?;
    }
    fs::create_dir_all(&smoke_root)
        .with_context(|| format!("create WORM smoke directory {}", smoke_root.display()))?;

    let export_root = smoke_root.join("worm");
    fs::create_dir_all(&export_root)
        .with_context(|| format!("create WORM export root {}", export_root.display()))?;
    let audit_path = smoke_root.join("audit.jsonl");
    let worm_wrapper = workspace.join("tools/worm-export/worm-export");
    if !worm_wrapper.exists() {
        bail!(
            "worm-export wrapper not found at {}; run from the workspace root",
            worm_wrapper.display()
        );
    }

    let mut env = BTreeMap::new();
    env.insert(
        "WORM_EXPORT_ROOT".to_string(),
        export_root.to_string_lossy().to_string(),
    );

    let exporter = CommandWormExporter::new(worm_wrapper, Vec::new(), env);
    let retention = WormRetention {
        min_days: 30,
        max_days: Some(90),
        mode: WormRetentionMode::Compliance,
    };
    let settings = WormExportSettings::new(Arc::new(exporter), retention, true)
        .context("initialise WORM export settings")?;
    let mut options = AdmissionPolicyLogOptions::default();
    options.worm_export = Some(settings.clone());

    let log = AdmissionPolicyLog::open_with_options(&audit_path, options)
        .context("open admission policy log for WORM smoke test")?;

    let keys_dir = smoke_root.join("keys");
    let (signer, public_hex) = initialise_policy_signer(&keys_dir)?;
    let approvals = vec![AdmissionApprovalRecord::new("operations", "alice")];
    let entry = log
        .append(
            "operator",
            Some("nightly worm export smoke"),
            &approvals,
            AdmissionPolicyChange::Noop,
            Some(&signer),
        )
        .context("append signed admission entry to audit log")?;

    let audit_entry = load_latest_audit_entry(&audit_path)?;
    if audit_entry.id != entry.id {
        bail!(
            "latest audit entry id {} does not match appended entry id {}",
            audit_entry.id,
            entry.id
        );
    }
    if audit_entry.signature.is_none() {
        bail!("latest audit entry is missing a signature");
    }

    let entries = verify_exported_entries(&workspace, &export_root, &signer)?;
    let retention_meta = export_root.join("retention.meta");
    let retention_metadata = if retention_meta.exists() {
        Some(relative_display_path(
            retention_meta
                .strip_prefix(&workspace)
                .unwrap_or(retention_meta.as_path()),
        ))
    } else {
        None
    };

    let audit_rel = audit_path
        .strip_prefix(&workspace)
        .unwrap_or(audit_path.as_path());
    let export_rel = export_root
        .strip_prefix(&workspace)
        .unwrap_or(export_root.as_path());
    let summary = WormExportSummary {
        generated_at: OffsetDateTime::now_utc().format(&Rfc3339)?,
        audit_log: relative_display_path(audit_rel),
        export_root: relative_display_path(export_rel),
        retention,
        retention_metadata,
        signer_key_id: signer.active_key().to_string(),
        signer_public_key_hex: public_hex,
        entries,
    };
    let summary_path = smoke_root.join("worm-export-summary.json");
    fs::write(&summary_path, serde_json::to_vec_pretty(&summary)?)
        .with_context(|| format!("write WORM export summary {}", summary_path.display()))?;
    println!(
        "worm export smoke summary written to {}",
        summary_path.display()
    );

    let mut command = Command::new("cargo");
    command
        .current_dir(&workspace)
        .arg("test")
        .arg("-p")
        .arg("rpp-p2p")
        .arg("--locked")
        .arg("--test")
        .arg("worm_export");
    apply_feature_flags(&mut command);
    run_command(command, "worm export smoke test")
}

fn run_consensus_manipulation_tests() -> Result<()> {
    let mut command = Command::new("cargo");
    command
        .current_dir(workspace_root())
        .arg("test")
        .arg("--locked")
        .arg("--test")
        .arg("consensus_certificate_tampering");
    apply_feature_flags(&mut command);
    run_command(command, "consensus manipulation checks")
}

fn run_full_test_matrix() -> Result<()> {
    run_unit_suites()?;
    run_integration_workflows()?;
    run_observability_suite()?;
    run_simnet_smoke()
}

#[derive(Default, Deserialize)]
struct ValidatorConfigSnippet {
    #[serde(default)]
    snapshot_dir: Option<String>,
    #[serde(default)]
    network: Option<ValidatorNetworkSnippet>,
    #[serde(default)]
    admission_reconciler: Option<ValidatorAdmissionReconcilerSnippet>,
}

#[derive(Default, Deserialize)]
struct ValidatorNetworkSnippet {
    #[serde(default)]
    rpc: Option<ValidatorRpcSnippet>,
    #[serde(default)]
    admission: Option<ValidatorAdmissionSnippet>,
}

#[derive(Default, Deserialize)]
struct ValidatorRpcSnippet {
    #[serde(default)]
    listen: Option<String>,
    #[serde(default)]
    auth_token: Option<String>,
}

#[derive(Default, Deserialize)]
struct ValidatorAdmissionSnippet {
    #[serde(default)]
    policy_path: Option<String>,
}

#[derive(Default, Deserialize)]
struct ValidatorAdmissionReconcilerSnippet {
    #[serde(default)]
    max_audit_lag_secs: Option<u64>,
}

#[derive(Debug, Deserialize)]
struct RpcSnapshotStatus {
    session: u64,
    peer: String,
    root: String,
    #[serde(default)]
    plan_id: Option<String>,
    #[serde(default)]
    last_chunk_index: Option<u64>,
    #[serde(default)]
    last_update_index: Option<u64>,
    #[serde(default)]
    last_update_height: Option<u64>,
    #[serde(default)]
    verified: Option<bool>,
    #[serde(default)]
    error: Option<String>,
}

#[derive(Clone, Default)]
struct ManifestEntry {
    chunk_total: u64,
    update_total: Option<u64>,
    display_alias: Option<String>,
    aliases: HashSet<String>,
    source: Option<PathBuf>,
}

impl ManifestEntry {
    fn new(chunk_total: u64) -> Self {
        Self {
            chunk_total,
            update_total: None,
            display_alias: None,
            aliases: HashSet::new(),
            source: None,
        }
    }

    fn add_alias<S: AsRef<str>>(&mut self, alias: S) {
        let trimmed = alias.as_ref().trim();
        if trimmed.is_empty() {
            return;
        }
        if self.display_alias.is_none() {
            self.display_alias = Some(trimmed.to_string());
        }
        for variant in alias_variants(trimmed) {
            if !variant.is_empty() {
                self.aliases.insert(variant);
            }
        }
    }

    fn matches(&self, candidate: &str) -> bool {
        if candidate.trim().is_empty() {
            return false;
        }
        alias_variants(candidate)
            .into_iter()
            .any(|variant| self.aliases.contains(&variant))
    }

    fn label(&self) -> Option<String> {
        if let Some(source) = &self.source {
            return Some(source.display().to_string());
        }
        self.display_alias.clone()
    }

    fn describe_source(&self) -> Option<String> {
        if let Some(source) = &self.source {
            return Some(source.display().to_string());
        }
        self.display_alias.clone()
    }
}

#[derive(Default)]
struct ManifestCatalog {
    entries: Vec<ManifestEntry>,
}

impl ManifestCatalog {
    fn merge(&mut self, mut other: ManifestCatalog) {
        self.entries.append(&mut other.entries);
    }

    fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    fn find_entry(&self, plan_id: Option<&str>, root: &str) -> Option<&ManifestEntry> {
        if let Some(identifier) =
            plan_id.and_then(|value| normalise_string(Some(value.to_string())))
        {
            for entry in &self.entries {
                if entry.matches(&identifier) {
                    return Some(entry);
                }
            }
        }
        if !root.trim().is_empty() {
            for entry in &self.entries {
                if entry.matches(root) {
                    return Some(entry);
                }
            }
        }
        if self.entries.len() == 1 {
            self.entries.first()
        } else {
            None
        }
    }

    fn source_labels(&self) -> Vec<String> {
        let mut labels: Vec<String> = self
            .entries
            .iter()
            .filter_map(|entry| entry.describe_source())
            .collect();
        labels.sort();
        labels.dedup();
        labels
    }
}

#[derive(Serialize, Deserialize)]
struct SnapshotHealthReport {
    generated_at: String,
    rpc_base_url: String,
    manifest_sources: Vec<String>,
    sessions: Vec<SnapshotSessionReport>,
}

#[derive(Serialize, Deserialize)]
struct SnapshotSessionReport {
    session: u64,
    peer: String,
    plan_id: Option<String>,
    root: String,
    manifest: Option<String>,
    chunk_progress: Option<u64>,
    chunk_total: Option<u64>,
    update_progress: Option<u64>,
    update_total: Option<u64>,
    last_update_height: Option<u64>,
    verified: Option<bool>,
    error: Option<String>,
    cli_ok: bool,
    anomalies: Vec<String>,
}

#[derive(Serialize)]
struct SnapshotHealthLogEntry {
    level: String,
    message: String,
    session: u64,
    plan_id: Option<String>,
    manifest: Option<String>,
    chunk_progress: Option<u64>,
    chunk_total: Option<u64>,
    update_progress: Option<u64>,
    update_total: Option<u64>,
    verified: Option<bool>,
    cli_status: String,
    error: Option<String>,
    anomalies: Vec<String>,
}

fn run_snapshot_health(args: &[String]) -> Result<()> {
    let workspace = workspace_root();

    let mut config_path: Option<PathBuf> = None;
    let mut rpc_url: Option<String> = None;
    let mut auth_token: Option<String> = None;
    let mut manifest_path: Option<PathBuf> = None;
    let mut output_path: Option<PathBuf> = None;
    let mut rpp_node_bin: Option<PathBuf> = None;

    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--config" => {
                let value = iter
                    .next()
                    .ok_or_else(|| anyhow!("--config requires a value"))?;
                config_path = Some(PathBuf::from(value));
            }
            "--rpc-url" => {
                let value = iter
                    .next()
                    .ok_or_else(|| anyhow!("--rpc-url requires a value"))?;
                rpc_url = normalise_string(Some(value.clone()));
            }
            "--auth-token" => {
                let value = iter
                    .next()
                    .ok_or_else(|| anyhow!("--auth-token requires a value"))?;
                auth_token = normalise_string(Some(value.clone()));
            }
            "--manifest" => {
                let value = iter
                    .next()
                    .ok_or_else(|| anyhow!("--manifest requires a value"))?;
                manifest_path = Some(PathBuf::from(value));
            }
            "--output" => {
                let value = iter
                    .next()
                    .ok_or_else(|| anyhow!("--output requires a value"))?;
                output_path = Some(PathBuf::from(value));
            }
            "--rpp-node-bin" => {
                let value = iter
                    .next()
                    .ok_or_else(|| anyhow!("--rpp-node-bin requires a value"))?;
                rpp_node_bin = Some(PathBuf::from(value));
            }
            "--help" | "-h" => {
                snapshot_health_usage();
                return Ok(());
            }
            other => bail!("unknown argument '{other}' for snapshot-health"),
        }
    }

    let resolved_config = config_path
        .map(|path| resolve_path(&workspace, path))
        .unwrap_or_else(|| workspace.join("config/validator.toml"));

    let config_dir = resolved_config
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(|| workspace.clone());

    let config_snippet = load_validator_config_snippet(&resolved_config)?;

    let mut manifest_catalog = ManifestCatalog::default();

    if let Some(path) = manifest_path {
        let resolved = resolve_path(&workspace, path);
        let catalog = load_manifest_catalog_from_path(&resolved)?;
        manifest_catalog.merge(catalog);
    }

    if let Some(json_payload) = env::var("SNAPSHOT_MANIFEST_JSON")
        .ok()
        .and_then(|value| normalise_string(Some(value)))
    {
        let value: JsonValue =
            serde_json::from_str(&json_payload).context("parse SNAPSHOT_MANIFEST_JSON payload")?;
        let catalog = load_manifest_catalog_from_value(&value, None, None)?;
        manifest_catalog.merge(catalog);
    }

    if manifest_catalog.is_empty() {
        if let Some(path) = env::var("SNAPSHOT_MANIFEST_PATH")
            .ok()
            .and_then(|value| normalise_string(Some(value)))
            .map(PathBuf::from)
        {
            let resolved = resolve_path(&workspace, path);
            if resolved.exists() {
                let catalog = load_manifest_catalog_from_path(&resolved)?;
                manifest_catalog.merge(catalog);
            }
        }
    }

    if manifest_catalog.is_empty() {
        if let Some(dir) = config_snippet
            .snapshot_dir
            .as_ref()
            .and_then(|value| normalise_string(Some(value.clone())))
            .map(|value| resolve_relative_path(&config_dir, &value))
        {
            let fallback = dir.join("manifest/chunks.json");
            if fallback.exists() {
                let catalog = load_manifest_catalog_from_path(&fallback)?;
                manifest_catalog.merge(catalog);
            }
        }
    }

    if manifest_catalog.is_empty() {
        bail!("no manifest entries discovered; provide --manifest or set SNAPSHOT_MANIFEST_PATH/SNAPSHOT_MANIFEST_JSON");
    }

    let rpp_node_bin = rpp_node_bin.map(|path| resolve_path(&workspace, path));

    let explicit_rpc_url = rpc_url;
    let base_url = resolve_rpc_base_url(explicit_rpc_url.clone(), &config_snippet);
    let cli_rpc_url = explicit_rpc_url.unwrap_or_else(|| base_url.clone());

    let mut resolved_auth = auth_token;
    if resolved_auth.is_none() {
        resolved_auth = env::var("SNAPSHOT_RPC_TOKEN")
            .ok()
            .and_then(|value| normalise_string(Some(value)));
    }
    if resolved_auth.is_none() {
        resolved_auth = config_snippet
            .network
            .as_ref()
            .and_then(|net| net.rpc.as_ref())
            .and_then(|rpc| rpc.auth_token.clone())
            .and_then(|value| normalise_string(Some(value)));
    }

    let http_client = HttpClient::builder()
        .timeout(StdDuration::from_secs(30))
        .build()
        .context("construct snapshot RPC client")?;

    let sessions =
        fetch_active_snapshot_sessions(&http_client, &base_url, resolved_auth.as_deref())?;

    let mut reports = Vec::new();
    let mut unhealthy = 0usize;

    for status in sessions {
        let manifest_entry = manifest_catalog.find_entry(status.plan_id.as_deref(), &status.root);
        let manifest_label = manifest_entry.and_then(|entry| entry.label());
        let chunk_total = manifest_entry.map(|entry| entry.chunk_total);
        let update_total = manifest_entry.and_then(|entry| entry.update_total);

        let mut anomalies = Vec::new();

        if manifest_entry.is_none() {
            anomalies.push("no manifest entry matched session plan".to_string());
        }

        if let Some(total) = chunk_total {
            if total == 0 {
                anomalies.push("manifest declares zero chunks".to_string());
            }
        }

        let chunk_progress = status.last_chunk_index.map(|value| value + 1);
        if let Some(total) = chunk_total {
            if let Some(progress) = chunk_progress {
                if progress > total {
                    anomalies.push(format!(
                        "chunk progress {progress} exceeds manifest total {total}"
                    ));
                }
            } else {
                anomalies.push("status missing last_chunk_index".to_string());
            }
        }

        let update_progress = status.last_update_index.map(|value| value + 1);
        if let Some(total) = update_total {
            if let Some(progress) = update_progress {
                if progress > total {
                    anomalies.push(format!(
                        "update progress {progress} exceeds manifest total {total}"
                    ));
                }
            }
        }

        if let Some(error) = status
            .error
            .as_ref()
            .map(|value| value.trim())
            .filter(|value| !value.is_empty())
        {
            anomalies.push(format!("snapshot reported error: {error}"));
        }

        if let (Some(total), Some(progress)) = (chunk_total, chunk_progress) {
            if progress == total && status.verified != Some(true) {
                anomalies.push("chunk replay complete but session not verified".to_string());
            }
        }

        let cli_result = run_rpp_node_snapshot_status(
            status.session,
            &resolved_config,
            &cli_rpc_url,
            resolved_auth.as_deref(),
            rpp_node_bin.as_deref(),
        );

        let cli_ok = match cli_result {
            Ok(_) => true,
            Err(err) => {
                anomalies.push(format!("rpp-node snapshot status failed: {err}"));
                false
            }
        };

        let log_entry = SnapshotHealthLogEntry {
            level: if anomalies.is_empty() {
                "info".to_string()
            } else {
                "error".to_string()
            },
            message: if anomalies.is_empty() {
                "snapshot healthy".to_string()
            } else {
                "snapshot health inconsistencies detected".to_string()
            },
            session: status.session,
            plan_id: status.plan_id.clone(),
            manifest: manifest_label.clone(),
            chunk_progress,
            chunk_total,
            update_progress,
            update_total,
            verified: status.verified,
            cli_status: if cli_ok {
                "ok".to_string()
            } else {
                "failed".to_string()
            },
            error: status.error.clone(),
            anomalies: anomalies.clone(),
        };

        println!("{}", serde_json::to_string(&log_entry)?);

        if !anomalies.is_empty() {
            unhealthy += 1;
        }

        reports.push(SnapshotSessionReport {
            session: status.session,
            peer: status.peer,
            plan_id: status.plan_id,
            root: status.root,
            manifest: manifest_label,
            chunk_progress,
            chunk_total,
            update_progress,
            update_total,
            last_update_height: status.last_update_height,
            verified: status.verified,
            error: status.error,
            cli_ok,
            anomalies,
        });
    }

    let generated_at = OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .context("format snapshot health timestamp")?;

    let report = SnapshotHealthReport {
        generated_at,
        rpc_base_url: base_url.clone(),
        manifest_sources: manifest_catalog.source_labels(),
        sessions: reports,
    };

    if let Some(path) = output_path {
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent)
                    .with_context(|| format!("create output directory {}", parent.display()))?;
            }
        }
        let data = serde_json::to_vec_pretty(&report)?;
        fs::write(&path, data)
            .with_context(|| format!("write snapshot health report to {}", path.display()))?;
    }

    if unhealthy > 0 {
        bail!("snapshot health check detected {unhealthy} failing session(s)");
    }

    Ok(())
}

fn load_validator_config_snippet(path: &Path) -> Result<ValidatorConfigSnippet> {
    if !path.exists() {
        bail!("validator configuration not found at {}", path.display());
    }
    let data = fs::read_to_string(path)
        .with_context(|| format!("read validator configuration from {}", path.display()))?;
    toml::from_str(&data)
        .with_context(|| format!("parse validator configuration from {}", path.display()))
}

fn resolve_path(base: &Path, path: PathBuf) -> PathBuf {
    if path.is_absolute() {
        path
    } else {
        base.join(path)
    }
}

fn resolve_relative_path(base: &Path, value: &str) -> PathBuf {
    let path = PathBuf::from(value);
    if path.is_absolute() {
        path
    } else {
        base.join(path)
    }
}

fn resolve_rpc_base_url(explicit: Option<String>, config: &ValidatorConfigSnippet) -> String {
    if let Some(url) = explicit.and_then(|value| normalise_string(Some(value))) {
        return normalise_base_url(&url);
    }
    if let Some(url) = env::var("SNAPSHOT_RPC_URL")
        .ok()
        .and_then(|value| normalise_string(Some(value)))
    {
        return normalise_base_url(&url);
    }
    if let Some(listen) = config
        .network
        .as_ref()
        .and_then(|net| net.rpc.as_ref())
        .and_then(|rpc| rpc.listen.clone())
        .and_then(|value| normalise_string(Some(value)))
    {
        return normalise_base_url(&listen);
    }
    normalise_base_url("127.0.0.1:7070")
}

fn normalise_base_url(value: &str) -> String {
    let trimmed = value.trim();
    let with_scheme = if trimmed.contains("://") {
        trimmed.to_string()
    } else {
        format!("http://{}", trimmed)
    };
    with_scheme.trim_end_matches('/').to_string()
}

fn fetch_active_snapshot_sessions(
    client: &HttpClient,
    base_url: &str,
    auth_token: Option<&str>,
) -> Result<Vec<RpcSnapshotStatus>> {
    let endpoint = format!("{}/p2p/snapshots", base_url.trim_end_matches('/'));
    let mut request = client.get(&endpoint);
    if let Some(token) = auth_token {
        request = request.bearer_auth(token);
    }
    let response = request
        .send()
        .with_context(|| format!("query snapshot sessions from {endpoint}"))?
        .error_for_status()
        .with_context(|| format!("snapshot status endpoint returned error status at {endpoint}"))?
        .json::<Vec<RpcSnapshotStatus>>()
        .with_context(|| format!("decode snapshot status list from {endpoint}"))?;
    Ok(response)
}

fn run_rpp_node_snapshot_status(
    session: u64,
    config_path: &Path,
    rpc_url: &str,
    auth_token: Option<&str>,
    binary: Option<&Path>,
) -> Result<()> {
    if let Some(bin) = binary {
        let mut command = Command::new(bin);
        command
            .current_dir(workspace_root())
            .arg("validator")
            .arg("snapshot")
            .arg("status")
            .arg("--config")
            .arg(config_path)
            .arg("--session")
            .arg(session.to_string())
            .arg("--rpc-url")
            .arg(rpc_url);
        if let Some(token) = auth_token {
            command.arg("--auth-token").arg(token);
        }
        run_command(command, &format!("rpp-node snapshot status ({session})"))
    } else {
        let mut command = Command::new("cargo");
        command
            .current_dir(workspace_root())
            .arg("run")
            .arg("--quiet")
            .arg("--package")
            .arg("rpp-node")
            .arg("--")
            .arg("validator")
            .arg("snapshot")
            .arg("status")
            .arg("--config")
            .arg(config_path)
            .arg("--session")
            .arg(session.to_string())
            .arg("--rpc-url")
            .arg(rpc_url);
        if let Some(token) = auth_token {
            command.arg("--auth-token").arg(token);
        }
        run_command(command, &format!("rpp-node snapshot status ({session})"))
    }
}

fn alias_variants(value: &str) -> Vec<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Vec::new();
    }
    let mut variants = Vec::new();
    let lower = trimmed.to_ascii_lowercase();
    variants.push(lower.clone());
    if let Some(stripped) = lower.strip_prefix("0x") {
        variants.push(stripped.to_string());
    }
    if let Some(name) = Path::new(trimmed)
        .file_name()
        .and_then(|value| value.to_str())
    {
        let lower_name = name.to_ascii_lowercase();
        variants.push(lower_name.clone());
        if let Some(stripped) = lower_name.strip_prefix("0x") {
            variants.push(stripped.to_string());
        }
        if let Some(stem) = Path::new(name).file_stem().and_then(|value| value.to_str()) {
            let lower_stem = stem.to_ascii_lowercase();
            variants.push(lower_stem.clone());
            if let Some(stripped) = lower_stem.strip_prefix("0x") {
                variants.push(stripped.to_string());
            }
        }
    }
    variants.sort();
    variants.dedup();
    variants
}

struct AdmissionReconciliationOptions {
    config: Option<PathBuf>,
    rpc_url: Option<String>,
    auth_token: Option<String>,
    policy_path: Option<PathBuf>,
    output: Option<PathBuf>,
    max_audit_lag_secs: Option<u64>,
}

impl Default for AdmissionReconciliationOptions {
    fn default() -> Self {
        Self {
            config: None,
            rpc_url: None,
            auth_token: None,
            policy_path: None,
            output: None,
            max_audit_lag_secs: None,
        }
    }
}

#[derive(Default, Clone)]
struct PolicySnapshotRecord {
    allowlist: BTreeMap<String, TierLevel>,
    blocklist: BTreeSet<String>,
}

impl PolicySnapshotRecord {
    fn from_runtime(policies: AdmissionPoliciesRpcResponse) -> Self {
        let allowlist = policies
            .allowlist
            .into_iter()
            .map(|entry| (entry.peer_id, entry.tier))
            .collect();
        let blocklist = policies.blocklist.into_iter().collect();
        Self {
            allowlist,
            blocklist,
        }
    }

    fn from_stored(stored: StoredAccessLists) -> Self {
        let allowlist = stored
            .allowlist
            .into_iter()
            .map(|entry| (entry.peer_id, entry.tier))
            .collect();
        let blocklist = stored.blocklist.into_iter().collect();
        Self {
            allowlist,
            blocklist,
        }
    }

    fn diff(&self, other: &PolicySnapshotRecord) -> SnapshotDiffRecord {
        let mut keys: BTreeSet<String> = BTreeSet::new();
        for peer in self.allowlist.keys() {
            keys.insert(peer.clone());
        }
        for peer in other.allowlist.keys() {
            keys.insert(peer.clone());
        }

        let mut allowlist_mismatches = 0u64;
        for peer in keys {
            if self.allowlist.get(&peer) != other.allowlist.get(&peer) {
                allowlist_mismatches += 1;
            }
        }

        let blocklist_diff = self
            .blocklist
            .symmetric_difference(&other.blocklist)
            .count() as u64;

        SnapshotDiffRecord {
            allowlist: allowlist_mismatches,
            blocklist: blocklist_diff,
        }
    }
}

#[derive(Default, Clone, Serialize)]
struct SnapshotDiffRecord {
    allowlist: u64,
    blocklist: u64,
}

impl SnapshotDiffRecord {
    fn total(&self) -> u64 {
        self.allowlist + self.blocklist
    }
}

struct DiskSnapshotRecord {
    snapshot: PolicySnapshotRecord,
    missing: bool,
    modified: Option<SystemTime>,
}

struct AuditSnapshotRecord {
    snapshot: Option<PolicySnapshotRecord>,
    last_timestamp: Option<u64>,
    entry_count: usize,
}

#[derive(Deserialize)]
struct AdmissionPoliciesRpcResponse {
    allowlist: Vec<AdmissionPolicyEntry>,
    blocklist: Vec<String>,
}

#[derive(Deserialize)]
struct AdmissionPolicyEntry {
    peer_id: String,
    tier: TierLevel,
}

#[derive(Deserialize)]
struct AdmissionAuditRpcResponse {
    offset: usize,
    limit: usize,
    total: usize,
    entries: Vec<AdmissionPolicyLogEntry>,
}

#[derive(Deserialize)]
struct StoredAccessLists {
    #[serde(default)]
    allowlist: Vec<StoredAllowlistEntry>,
    #[serde(default)]
    blocklist: Vec<String>,
}

#[derive(Deserialize)]
struct StoredAllowlistEntry {
    peer_id: String,
    tier: TierLevel,
}

#[derive(Serialize)]
struct AdmissionReconciliationReport {
    generated_at: String,
    rpc_base_url: String,
    policy_path: String,
    runtime_allowlist_total: usize,
    runtime_blocklist_total: usize,
    disk_allowlist_total: usize,
    disk_blocklist_total: usize,
    disk_missing: bool,
    disk_diff: SnapshotDiffRecord,
    audit_diff: Option<SnapshotDiffRecord>,
    audit_entries: usize,
    last_audit_timestamp: Option<u64>,
    audit_lagged: bool,
    drift_detected: bool,
    issues: Vec<String>,
}

struct AdmissionReconciliationResult {
    report: AdmissionReconciliationReport,
}

fn admission_reconciliation(args: &[String]) -> Result<AdmissionReconciliationResult> {
    let workspace = workspace_root();
    let mut options = AdmissionReconciliationOptions::default();

    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--config" => {
                let value = iter
                    .next()
                    .ok_or_else(|| anyhow!("--config requires a value"))?;
                options.config = Some(PathBuf::from(value));
            }
            "--rpc-url" => {
                let value = iter
                    .next()
                    .ok_or_else(|| anyhow!("--rpc-url requires a value"))?;
                options.rpc_url = normalise_string(Some(value.clone()));
            }
            "--auth-token" => {
                let value = iter
                    .next()
                    .ok_or_else(|| anyhow!("--auth-token requires a value"))?;
                options.auth_token = normalise_string(Some(value.clone()));
            }
            "--policy-path" => {
                let value = iter
                    .next()
                    .ok_or_else(|| anyhow!("--policy-path requires a value"))?;
                options.policy_path = Some(PathBuf::from(value));
            }
            "--output" => {
                let value = iter
                    .next()
                    .ok_or_else(|| anyhow!("--output requires a value"))?;
                options.output = Some(PathBuf::from(value));
            }
            "--max-audit-lag-secs" => {
                let value = iter
                    .next()
                    .ok_or_else(|| anyhow!("--max-audit-lag-secs requires a value"))?;
                let parsed = value
                    .parse::<u64>()
                    .with_context(|| format!("parse --max-audit-lag-secs value '{value}'"))?;
                options.max_audit_lag_secs = Some(parsed);
            }
            "--help" | "-h" => {
                admission_reconcile_usage();
                return Ok(AdmissionReconciliationResult {
                    report: AdmissionReconciliationReport {
                        generated_at: String::new(),
                        rpc_base_url: String::new(),
                        policy_path: String::new(),
                        runtime_allowlist_total: 0,
                        runtime_blocklist_total: 0,
                        disk_allowlist_total: 0,
                        disk_blocklist_total: 0,
                        disk_missing: false,
                        disk_diff: SnapshotDiffRecord::default(),
                        audit_diff: None,
                        audit_entries: 0,
                        last_audit_timestamp: None,
                        audit_lagged: false,
                        drift_detected: false,
                        issues: Vec::new(),
                    },
                    output_path: None,
                });
            }
            other => bail!("unknown argument '{other}' for admission-reconcile"),
        }
    }

    if options.rpc_url.is_none() {
        options.rpc_url = env::var("ADMISSION_RPC_URL")
            .ok()
            .and_then(|value| normalise_string(Some(value)));
    }
    if options.auth_token.is_none() {
        options.auth_token = env::var("ADMISSION_RPC_TOKEN")
            .ok()
            .and_then(|value| normalise_string(Some(value)));
    }
    if options.policy_path.is_none() {
        options.policy_path = env::var("ADMISSION_POLICY_PATH")
            .ok()
            .and_then(|value| normalise_string(Some(value)))
            .map(PathBuf::from);
    }
    if options.max_audit_lag_secs.is_none() {
        if let Ok(value) = env::var("ADMISSION_MAX_AUDIT_LAG_SECS") {
            if let Some(trimmed) = normalise_string(Some(value)) {
                let parsed = trimmed.parse::<u64>().with_context(|| {
                    format!("parse ADMISSION_MAX_AUDIT_LAG_SECS value '{trimmed}' as integer")
                })?;
                options.max_audit_lag_secs = Some(parsed);
            }
        }
    }

    let resolved_config = options
        .config
        .map(|path| resolve_path(&workspace, path))
        .unwrap_or_else(|| workspace.join("config/validator.toml"));
    let config_dir = resolved_config
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(|| workspace.clone());

    let config_snippet = load_validator_config_snippet(&resolved_config)?;
    let base_url = resolve_admission_base_url(options.rpc_url, &config_snippet);
    let auth_token = resolve_admission_auth(options.auth_token, &config_snippet);
    let policy_path = resolve_policy_path(&config_dir, &config_snippet, options.policy_path);
    let max_audit_lag = resolve_max_audit_lag_secs(options.max_audit_lag_secs, &config_snippet);

    let client = HttpClient::builder()
        .timeout(StdDuration::from_secs(30))
        .build()
        .context("construct admission RPC client")?;

    let runtime_snapshot = fetch_admission_policies(&client, &base_url, auth_token.as_deref())?;
    let disk_snapshot = load_admission_disk_snapshot(&policy_path)?;
    let audit_snapshot = fetch_admission_audit(&client, &base_url, auth_token.as_deref())?;

    let disk_diff = runtime_snapshot.diff(&disk_snapshot.snapshot);
    let audit_diff = audit_snapshot
        .snapshot
        .as_ref()
        .map(|snapshot| runtime_snapshot.diff(snapshot));

    let audit_lagged = if let (Some(last_ts), Some(modified)) =
        (audit_snapshot.last_timestamp, disk_snapshot.modified)
    {
        if let Ok(modified_ms) = modified.duration_since(UNIX_EPOCH) {
            let modified_millis = modified_ms.as_millis() as u128;
            let last_millis = last_ts as u128;
            modified_millis > last_millis.saturating_add(max_audit_lag as u128)
        } else {
            false
        }
    } else {
        false
    };

    let drift_detected = disk_snapshot.missing
        || disk_diff.total() > 0
        || audit_diff
            .as_ref()
            .map(|diff| diff.total() > 0)
            .unwrap_or(false)
        || audit_lagged;

    let mut issues = Vec::new();
    if disk_snapshot.missing {
        issues.push("admission policy file missing".to_string());
    }
    if disk_diff.total() > 0 {
        issues.push(format!(
            "disk admission snapshot diverges (allowlist {}, blocklist {})",
            disk_diff.allowlist, disk_diff.blocklist
        ));
    }
    if let Some(diff) = audit_diff.as_ref() {
        if diff.total() > 0 {
            issues.push(format!(
                "audit trail snapshot diverges (allowlist {}, blocklist {})",
                diff.allowlist, diff.blocklist
            ));
        }
    }
    if audit_lagged {
        issues.push(format!(
            "audit trail lags disk snapshot by more than {} seconds",
            max_audit_lag
        ));
    }

    let generated_at = OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .context("format admission reconciliation timestamp")?;

    let report = AdmissionReconciliationReport {
        generated_at,
        rpc_base_url: base_url.clone(),
        policy_path: policy_path.display().to_string(),
        runtime_allowlist_total: runtime_snapshot.allowlist.len(),
        runtime_blocklist_total: runtime_snapshot.blocklist.len(),
        disk_allowlist_total: disk_snapshot.snapshot.allowlist.len(),
        disk_blocklist_total: disk_snapshot.snapshot.blocklist.len(),
        disk_missing: disk_snapshot.missing,
        disk_diff,
        audit_diff,
        audit_entries: audit_snapshot.entry_count,
        last_audit_timestamp: audit_snapshot.last_timestamp,
        audit_lagged,
        drift_detected,
        issues,
    };

    if let Some(path) = options.output.as_ref() {
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent)
                    .with_context(|| format!("create output directory {}", parent.display()))?;
            }
        }
        let data =
            serde_json::to_vec_pretty(&report).context("encode admission reconciliation report")?;
        fs::write(path, &data).with_context(|| {
            format!(
                "write admission reconciliation report to {}",
                path.display()
            )
        })?;
    }

    println!("{}", serde_json::to_string(&report)?);

    Ok(AdmissionReconciliationResult { report })
}

fn admission_reconcile_usage() {
    eprintln!(
        "usage: cargo xtask admission-reconcile [--config <path>] [--rpc-url <url>] [--auth-token <token>] [--policy-path <path>] [--max-audit-lag-secs <secs>] [--output <path>]\n\nChecks that the admission policy snapshot on disk, the runtime admission state, and the audit log trail are consistent."
    );
}

fn resolve_admission_base_url(explicit: Option<String>, config: &ValidatorConfigSnippet) -> String {
    if let Some(url) = explicit.and_then(|value| normalise_string(Some(value))) {
        return normalise_base_url(&url);
    }
    if let Some(url) = env::var("ADMISSION_RPC_URL")
        .ok()
        .and_then(|value| normalise_string(Some(value)))
    {
        return normalise_base_url(&url);
    }
    resolve_rpc_base_url(None, config)
}

fn resolve_admission_auth(
    explicit: Option<String>,
    config: &ValidatorConfigSnippet,
) -> Option<String> {
    if let Some(token) = explicit.and_then(|value| normalise_string(Some(value))) {
        return Some(token);
    }
    if let Some(token) = env::var("ADMISSION_RPC_TOKEN")
        .ok()
        .and_then(|value| normalise_string(Some(value)))
    {
        return Some(token);
    }
    config
        .network
        .as_ref()
        .and_then(|net| net.rpc.as_ref())
        .and_then(|rpc| rpc.auth_token.clone())
        .and_then(|value| normalise_string(Some(value)))
}

fn resolve_policy_path(
    config_dir: &Path,
    config: &ValidatorConfigSnippet,
    explicit: Option<PathBuf>,
) -> PathBuf {
    if let Some(path) = explicit {
        resolve_path(config_dir, path)
    } else if let Some(path) = config
        .network
        .as_ref()
        .and_then(|net| net.admission.as_ref())
        .and_then(|admission| admission.policy_path.as_ref())
    {
        resolve_relative_path(config_dir, path)
    } else {
        config_dir.join("data/p2p/admission_policies.json")
    }
}

fn resolve_max_audit_lag_secs(explicit: Option<u64>, config: &ValidatorConfigSnippet) -> u64 {
    if let Some(value) = explicit {
        return value.max(1);
    }
    if let Some(value) = config
        .admission_reconciler
        .as_ref()
        .and_then(|snippet| snippet.max_audit_lag_secs)
    {
        return value.max(1);
    }
    300
}

fn fetch_admission_policies(
    client: &HttpClient,
    base_url: &str,
    auth_token: Option<&str>,
) -> Result<PolicySnapshotRecord> {
    let endpoint = format!("{}/p2p/admission/policies", base_url.trim_end_matches('/'));
    let mut request = client.get(&endpoint);
    if let Some(token) = auth_token {
        request = request.bearer_auth(token);
    }
    let response = request
        .send()
        .with_context(|| format!("query admission policies from {endpoint}"))?
        .error_for_status()
        .with_context(|| {
            format!("admission policies endpoint returned error status at {endpoint}")
        })?
        .json::<AdmissionPoliciesRpcResponse>()
        .with_context(|| format!("decode admission policies response from {endpoint}"))?;
    Ok(PolicySnapshotRecord::from_runtime(response))
}

fn load_admission_disk_snapshot(path: &Path) -> Result<DiskSnapshotRecord> {
    match fs::metadata(path) {
        Ok(metadata) => {
            let modified = metadata.modified().ok();
            let bytes = fs::read(path).with_context(|| {
                format!("read admission policy snapshot from {}", path.display())
            })?;
            if bytes.is_empty() {
                return Ok(DiskSnapshotRecord {
                    snapshot: PolicySnapshotRecord::default(),
                    missing: false,
                    modified,
                });
            }
            let stored: StoredAccessLists = serde_json::from_slice(&bytes).with_context(|| {
                format!("parse admission policy snapshot from {}", path.display())
            })?;
            Ok(DiskSnapshotRecord {
                snapshot: PolicySnapshotRecord::from_stored(stored),
                missing: false,
                modified,
            })
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(DiskSnapshotRecord {
            snapshot: PolicySnapshotRecord::default(),
            missing: true,
            modified: None,
        }),
        Err(err) => Err(err).with_context(|| {
            format!(
                "read admission policy snapshot metadata from {}",
                path.display()
            )
        }),
    }
}

fn fetch_admission_audit(
    client: &HttpClient,
    base_url: &str,
    auth_token: Option<&str>,
) -> Result<AuditSnapshotRecord> {
    let mut entries = Vec::new();
    let mut offset = 0usize;
    let mut total = None;
    let limit = 512usize;

    loop {
        let endpoint = format!("{}/p2p/admission/audit", base_url.trim_end_matches('/'));
        let mut request = client
            .get(&endpoint)
            .query(&[("offset", offset), ("limit", limit)]);
        if let Some(token) = auth_token {
            request = request.bearer_auth(token);
        }
        let response = request
            .send()
            .with_context(|| {
                format!("query admission audit log from {endpoint} (offset {offset})")
            })?
            .error_for_status()
            .with_context(|| {
                format!("admission audit endpoint returned error status at {endpoint}")
            })?
            .json::<AdmissionAuditRpcResponse>()
            .with_context(|| format!("decode admission audit response from {endpoint}"))?;
        total = Some(response.total);
        let received = response.entries.len();
        entries.extend(response.entries);
        offset += received;
        if received == 0 || entries.len() >= total.unwrap_or(entries.len()) {
            break;
        }
    }

    if entries.is_empty() {
        return Ok(AuditSnapshotRecord {
            snapshot: None,
            last_timestamp: None,
            entry_count: 0,
        });
    }

    let last_timestamp = entries.last().map(|entry| entry.timestamp_ms);
    let snapshot = audit_entries_to_snapshot(&entries)?;
    Ok(AuditSnapshotRecord {
        snapshot: Some(snapshot),
        last_timestamp,
        entry_count: entries.len(),
    })
}

fn audit_entries_to_snapshot(entries: &[AdmissionPolicyLogEntry]) -> Result<PolicySnapshotRecord> {
    let mut allowlist: BTreeMap<String, TierLevel> = BTreeMap::new();
    let mut blocklist: BTreeSet<String> = BTreeSet::new();

    for entry in entries {
        match &entry.change {
            AdmissionPolicyChange::Allowlist { previous, current } => {
                if let Some(current) = current {
                    allowlist.insert(current.peer_id.clone(), current.tier);
                } else if let Some(previous) = previous {
                    allowlist.remove(&previous.peer_id);
                }
            }
            AdmissionPolicyChange::Blocklist {
                peer_id, current, ..
            } => {
                if *current {
                    blocklist.insert(peer_id.clone());
                } else {
                    blocklist.remove(peer_id);
                }
            }
            AdmissionPolicyChange::Noop => {}
        }
    }

    Ok(PolicySnapshotRecord {
        allowlist,
        blocklist,
    })
}

#[derive(Default)]
struct StagingSoakOptions {
    output_dir: Option<PathBuf>,
    timestamp: Option<String>,
    snapshot_config: Option<PathBuf>,
    snapshot_rpc_url: Option<String>,
    snapshot_auth_token: Option<String>,
    snapshot_manifest: Option<PathBuf>,
    snapshot_rpp_node_bin: Option<PathBuf>,
    timetoke_prometheus_url: Option<String>,
    timetoke_bearer_token: Option<String>,
    timetoke_metrics_log: Option<PathBuf>,
    admission_config: Option<PathBuf>,
    admission_rpc_url: Option<String>,
    admission_auth_token: Option<String>,
    admission_policy_path: Option<PathBuf>,
    admission_max_audit_lag_secs: Option<u64>,
}

#[derive(Default, Serialize)]
struct StagingSoakSnapshotSummary {
    report_path: Option<String>,
    total_sessions: Option<usize>,
    unhealthy_sessions: Option<usize>,
    ok: bool,
}

#[derive(Serialize)]
struct StagingSoakTimetokeSummary {
    report_path: Option<String>,
    source: Option<String>,
    successes: Option<f64>,
    failures: Option<f64>,
    success_rate: Option<f64>,
    success_rate_target: f64,
    success_rate_ok: bool,
    latency_p50_ms: Option<f64>,
    latency_p95_ms: Option<f64>,
    latency_p99_ms: Option<f64>,
    latency_targets_ms: TimetokeLatencyTargets,
    latency_ok: bool,
    ok: bool,
}

impl Default for StagingSoakTimetokeSummary {
    fn default() -> Self {
        Self {
            report_path: None,
            source: None,
            successes: None,
            failures: None,
            success_rate: None,
            success_rate_target: TIMETOKE_SUCCESS_RATE_TARGET,
            success_rate_ok: false,
            latency_p50_ms: None,
            latency_p95_ms: None,
            latency_p99_ms: None,
            latency_targets_ms: TimetokeLatencyTargets {
                p50_ms: TIMETOKE_LATENCY_P50_TARGET_MS,
                p95_ms: TIMETOKE_LATENCY_P95_TARGET_MS,
                p99_ms: TIMETOKE_LATENCY_P99_TARGET_MS,
            },
            latency_ok: false,
            ok: false,
        }
    }
}

#[derive(Serialize)]
struct TimetokeLatencyTargets {
    p50_ms: f64,
    p95_ms: f64,
    p99_ms: f64,
}

impl Default for TimetokeLatencyTargets {
    fn default() -> Self {
        Self {
            p50_ms: TIMETOKE_LATENCY_P50_TARGET_MS,
            p95_ms: TIMETOKE_LATENCY_P95_TARGET_MS,
            p99_ms: TIMETOKE_LATENCY_P99_TARGET_MS,
        }
    }
}

#[derive(Default, Serialize)]
struct StagingSoakAdmissionSummary {
    report_path: Option<String>,
    runtime_allowlist_total: Option<usize>,
    runtime_blocklist_total: Option<usize>,
    disk_allowlist_total: Option<usize>,
    disk_blocklist_total: Option<usize>,
    disk_missing: Option<bool>,
    disk_diff_allowlist: Option<u64>,
    disk_diff_blocklist: Option<u64>,
    audit_diff_allowlist: Option<u64>,
    audit_diff_blocklist: Option<u64>,
    audit_entries: Option<usize>,
    last_audit_timestamp: Option<u64>,
    audit_lagged: Option<bool>,
    drift_detected: Option<bool>,
    ok: bool,
    issues: Vec<String>,
}

#[derive(Serialize)]
struct StagingSoakSummary {
    generated_at: String,
    run_directory: String,
    snapshot: StagingSoakSnapshotSummary,
    timetoke: StagingSoakTimetokeSummary,
    admission: StagingSoakAdmissionSummary,
    errors: Vec<String>,
    ok: bool,
}

fn run_staging_soak(args: &[String]) -> Result<()> {
    let workspace = workspace_root();
    let mut options = StagingSoakOptions::default();

    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--output-dir" => {
                let value = iter
                    .next()
                    .ok_or_else(|| anyhow!("--output-dir requires a value"))?;
                options.output_dir = Some(PathBuf::from(value));
            }
            "--timestamp" => {
                let value = iter
                    .next()
                    .ok_or_else(|| anyhow!("--timestamp requires a value"))?;
                options.timestamp = Some(value.to_string());
            }
            "--snapshot-config" => {
                let value = iter
                    .next()
                    .ok_or_else(|| anyhow!("--snapshot-config requires a value"))?;
                options.snapshot_config = Some(PathBuf::from(value));
            }
            "--snapshot-rpc-url" => {
                let value = iter
                    .next()
                    .ok_or_else(|| anyhow!("--snapshot-rpc-url requires a value"))?;
                options.snapshot_rpc_url = normalise_string(Some(value.clone()));
            }
            "--snapshot-auth-token" => {
                let value = iter
                    .next()
                    .ok_or_else(|| anyhow!("--snapshot-auth-token requires a value"))?;
                options.snapshot_auth_token = normalise_string(Some(value.clone()));
            }
            "--snapshot-manifest" => {
                let value = iter
                    .next()
                    .ok_or_else(|| anyhow!("--snapshot-manifest requires a value"))?;
                options.snapshot_manifest = Some(PathBuf::from(value));
            }
            "--snapshot-rpp-node-bin" => {
                let value = iter
                    .next()
                    .ok_or_else(|| anyhow!("--snapshot-rpp-node-bin requires a value"))?;
                options.snapshot_rpp_node_bin = Some(PathBuf::from(value));
            }
            "--timetoke-prometheus-url" => {
                let value = iter
                    .next()
                    .ok_or_else(|| anyhow!("--timetoke-prometheus-url requires a value"))?;
                options.timetoke_prometheus_url = normalise_string(Some(value.clone()));
            }
            "--timetoke-bearer-token" => {
                let value = iter
                    .next()
                    .ok_or_else(|| anyhow!("--timetoke-bearer-token requires a value"))?;
                options.timetoke_bearer_token = normalise_string(Some(value.clone()));
            }
            "--timetoke-metrics-log" => {
                let value = iter
                    .next()
                    .ok_or_else(|| anyhow!("--timetoke-metrics-log requires a value"))?;
                options.timetoke_metrics_log = Some(PathBuf::from(value));
            }
            "--admission-config" => {
                let value = iter
                    .next()
                    .ok_or_else(|| anyhow!("--admission-config requires a value"))?;
                options.admission_config = Some(PathBuf::from(value));
            }
            "--admission-rpc-url" => {
                let value = iter
                    .next()
                    .ok_or_else(|| anyhow!("--admission-rpc-url requires a value"))?;
                options.admission_rpc_url = normalise_string(Some(value.clone()));
            }
            "--admission-auth-token" => {
                let value = iter
                    .next()
                    .ok_or_else(|| anyhow!("--admission-auth-token requires a value"))?;
                options.admission_auth_token = normalise_string(Some(value.clone()));
            }
            "--admission-policy-path" => {
                let value = iter
                    .next()
                    .ok_or_else(|| anyhow!("--admission-policy-path requires a value"))?;
                options.admission_policy_path = Some(PathBuf::from(value));
            }
            "--admission-max-audit-lag-secs" => {
                let value = iter
                    .next()
                    .ok_or_else(|| anyhow!("--admission-max-audit-lag-secs requires a value"))?;
                let parsed = value
                    .parse::<u64>()
                    .with_context(|| format!("parse --admission-max-audit-lag-secs '{value}'"))?;
                options.admission_max_audit_lag_secs = Some(parsed);
            }
            "--help" | "-h" => {
                staging_soak_usage();
                return Ok(());
            }
            other => bail!("unknown argument '{other}' for staging-soak"),
        }
    }

    let output_base = options
        .output_dir
        .map(|path| resolve_path(&workspace, path))
        .unwrap_or_else(|| workspace.join("logs/staging-soak"));

    let timestamp = if let Some(ts) = options.timestamp.as_ref() {
        OffsetDateTime::parse(ts, &Rfc3339)
            .with_context(|| format!("parse --timestamp value '{ts}'"))?
    } else {
        OffsetDateTime::now_utc()
    };

    let date_label = timestamp
        .format(&format_description!("[year]-[month]-[day]"))
        .context("format staging soak date label")?;
    let run_label = timestamp
        .format(&format_description!(
            "[year][month][day]T[hour][minute][second]Z"
        ))
        .context("format staging soak run label")?;

    let run_dir = output_base.join(&date_label).join(&run_label);
    fs::create_dir_all(&run_dir)
        .with_context(|| format!("create staging soak directory {}", run_dir.display()))?;

    let mut summary = StagingSoakSummary {
        generated_at: OffsetDateTime::now_utc()
            .format(&Rfc3339)
            .context("format staging soak summary timestamp")?,
        run_directory: relative_display(&run_dir, &workspace),
        snapshot: StagingSoakSnapshotSummary::default(),
        timetoke: StagingSoakTimetokeSummary::default(),
        admission: StagingSoakAdmissionSummary::default(),
        errors: Vec::new(),
        ok: false,
    };

    // Snapshot health
    let snapshot_output = run_dir.join("snapshot-health-report.json");
    let mut snapshot_args: Vec<String> = Vec::new();
    if let Some(path) = options.snapshot_config.as_ref() {
        snapshot_args.push("--config".to_string());
        snapshot_args.push(resolve_path(&workspace, path.clone()).display().to_string());
    }
    if let Some(url) = options.snapshot_rpc_url.as_ref() {
        snapshot_args.push("--rpc-url".to_string());
        snapshot_args.push(url.clone());
    }
    if let Some(token) = options.snapshot_auth_token.as_ref() {
        snapshot_args.push("--auth-token".to_string());
        snapshot_args.push(token.clone());
    }
    if let Some(path) = options.snapshot_manifest.as_ref() {
        snapshot_args.push("--manifest".to_string());
        snapshot_args.push(resolve_path(&workspace, path.clone()).display().to_string());
    }
    if let Some(bin) = options.snapshot_rpp_node_bin.as_ref() {
        snapshot_args.push("--rpp-node-bin".to_string());
        snapshot_args.push(resolve_path(&workspace, bin.clone()).display().to_string());
    }
    snapshot_args.push("--output".to_string());
    snapshot_args.push(snapshot_output.display().to_string());

    if let Err(err) = run_snapshot_health(&snapshot_args) {
        summary
            .errors
            .push(format!("snapshot-health: {}", err.to_string()));
    }
    if snapshot_output.exists() {
        match fs::read(&snapshot_output) {
            Ok(data) => match serde_json::from_slice::<SnapshotHealthReport>(&data) {
                Ok(report) => {
                    let total = report.sessions.len();
                    let unhealthy = report
                        .sessions
                        .iter()
                        .filter(|session| !session.anomalies.is_empty())
                        .count();
                    summary.snapshot.report_path =
                        Some(relative_display(&snapshot_output, &workspace));
                    summary.snapshot.total_sessions = Some(total);
                    summary.snapshot.unhealthy_sessions = Some(unhealthy);
                    summary.snapshot.ok = unhealthy == 0;
                }
                Err(err) => summary
                    .errors
                    .push(format!("snapshot-health: decode report failed ({err})")),
            },
            Err(err) => summary
                .errors
                .push(format!("snapshot-health: read report failed ({err})")),
        }
    } else {
        summary
            .errors
            .push("snapshot-health: report not generated".to_string());
    }

    // Timetoke SLO
    let timetoke_output = run_dir.join("timetoke-slo-report.md");
    let mut timetoke_args: Vec<String> = Vec::new();
    if let Some(url) = options.timetoke_prometheus_url.as_ref() {
        timetoke_args.push("--prometheus-url".to_string());
        timetoke_args.push(url.clone());
    }
    if let Some(token) = options.timetoke_bearer_token.as_ref() {
        timetoke_args.push("--bearer-token".to_string());
        timetoke_args.push(token.clone());
    }
    if let Some(path) = options.timetoke_metrics_log.as_ref() {
        timetoke_args.push("--metrics-log".to_string());
        timetoke_args.push(resolve_path(&workspace, path.clone()).display().to_string());
    }
    timetoke_args.push("--output".to_string());
    timetoke_args.push(timetoke_output.display().to_string());

    match parse_timetoke_slo_options(&timetoke_args)? {
        Some(opts) => match generate_timetoke_slo_summary(&opts.source) {
            Ok(summary_data) => {
                let report = render_timetoke_report(&summary_data);
                if let Some(parent) = timetoke_output.parent() {
                    fs::create_dir_all(parent).with_context(|| {
                        format!("create Timetoke report directory {}", parent.display())
                    })?;
                }
                fs::write(&timetoke_output, report.as_bytes()).with_context(|| {
                    format!("write Timetoke SLO report to {}", timetoke_output.display())
                })?;
                summary.timetoke.report_path = Some(relative_display(&timetoke_output, &workspace));
                summary.timetoke.source = Some(summary_data.source.clone());
                summary.timetoke.successes = Some(summary_data.successes);
                summary.timetoke.failures = Some(summary_data.failures);
                summary.timetoke.success_rate = summary_data.success_rate();
                summary.timetoke.latency_p50_ms = summary_data.p50_ms;
                summary.timetoke.latency_p95_ms = summary_data.p95_ms;
                summary.timetoke.latency_p99_ms = summary_data.p99_ms;
                summary.timetoke.success_rate_ok = summary
                    .timetoke
                    .success_rate
                    .map(|rate| rate >= TIMETOKE_SUCCESS_RATE_TARGET)
                    .unwrap_or(false);
                summary.timetoke.latency_ok = summary
                    .timetoke
                    .latency_p50_ms
                    .map(|value| value <= TIMETOKE_LATENCY_P50_TARGET_MS)
                    .unwrap_or(false)
                    && summary
                        .timetoke
                        .latency_p95_ms
                        .map(|value| value <= TIMETOKE_LATENCY_P95_TARGET_MS)
                        .unwrap_or(false)
                    && summary
                        .timetoke
                        .latency_p99_ms
                        .map(|value| value <= TIMETOKE_LATENCY_P99_TARGET_MS)
                        .unwrap_or(false);
                summary.timetoke.ok =
                    summary.timetoke.success_rate_ok && summary.timetoke.latency_ok;
            }
            Err(err) => summary.errors.push(format!("timetoke-slo: {err}")),
        },
        None => {
            staging_soak_usage();
            return Ok(());
        }
    }

    // Admission reconciliation
    let admission_output = run_dir.join("admission-reconciliation.json");
    let mut admission_args: Vec<String> = Vec::new();
    if let Some(path) = options.admission_config.as_ref() {
        admission_args.push("--config".to_string());
        admission_args.push(resolve_path(&workspace, path.clone()).display().to_string());
    }
    if let Some(url) = options.admission_rpc_url.as_ref() {
        admission_args.push("--rpc-url".to_string());
        admission_args.push(url.clone());
    }
    if let Some(token) = options.admission_auth_token.as_ref() {
        admission_args.push("--auth-token".to_string());
        admission_args.push(token.clone());
    }
    if let Some(path) = options.admission_policy_path.as_ref() {
        admission_args.push("--policy-path".to_string());
        admission_args.push(resolve_path(&workspace, path.clone()).display().to_string());
    }
    if let Some(value) = options.admission_max_audit_lag_secs.as_ref() {
        admission_args.push("--max-audit-lag-secs".to_string());
        admission_args.push(value.to_string());
    }
    admission_args.push("--output".to_string());
    admission_args.push(admission_output.display().to_string());

    match admission_reconciliation(&admission_args) {
        Ok(result) => {
            let report = result.report;
            summary.admission.report_path = Some(relative_display(&admission_output, &workspace));
            summary.admission.runtime_allowlist_total = Some(report.runtime_allowlist_total);
            summary.admission.runtime_blocklist_total = Some(report.runtime_blocklist_total);
            summary.admission.disk_allowlist_total = Some(report.disk_allowlist_total);
            summary.admission.disk_blocklist_total = Some(report.disk_blocklist_total);
            summary.admission.disk_missing = Some(report.disk_missing);
            summary.admission.disk_diff_allowlist = Some(report.disk_diff.allowlist);
            summary.admission.disk_diff_blocklist = Some(report.disk_diff.blocklist);
            summary.admission.audit_diff_allowlist =
                report.audit_diff.as_ref().map(|diff| diff.allowlist);
            summary.admission.audit_diff_blocklist =
                report.audit_diff.as_ref().map(|diff| diff.blocklist);
            summary.admission.audit_entries = Some(report.audit_entries);
            summary.admission.last_audit_timestamp = report.last_audit_timestamp;
            summary.admission.audit_lagged = Some(report.audit_lagged);
            summary.admission.drift_detected = Some(report.drift_detected);
            summary.admission.issues = report.issues.clone();
            summary.admission.ok = !report.drift_detected;
            if report.drift_detected {
                summary
                    .errors
                    .push("admission-reconcile: drift detected".to_string());
            }
        }
        Err(err) => summary.errors.push(format!("admission-reconcile: {err}")),
    }

    let snapshot_ok = summary.snapshot.ok;
    let timetoke_ok = summary.timetoke.ok;
    let admission_ok = summary.admission.ok;
    summary.ok = snapshot_ok && timetoke_ok && admission_ok && summary.errors.is_empty();

    let summary_path = run_dir.join("summary.json");
    let data = serde_json::to_vec_pretty(&summary).context("encode staging soak summary")?;
    fs::write(&summary_path, &data)
        .with_context(|| format!("write staging soak summary to {}", summary_path.display()))?;

    println!(
        "staging soak summary written to {}",
        relative_display(&summary_path, &workspace)
    );

    if !summary.ok {
        bail!("staging soak checks detected failures");
    }

    Ok(())
}

fn staging_soak_usage() {
    eprintln!(
        "usage: cargo xtask staging-soak [--output-dir <path>] [--timestamp <RFC3339>] [--snapshot-config <path>] [--snapshot-rpc-url <url>] [--snapshot-auth-token <token>] [--snapshot-manifest <path>] [--snapshot-rpp-node-bin <path>] [--timetoke-prometheus-url <url>] [--timetoke-bearer-token <token>] [--timetoke-metrics-log <path>] [--admission-config <path>] [--admission-rpc-url <url>] [--admission-auth-token <token>] [--admission-policy-path <path>] [--admission-max-audit-lag-secs <secs>] [--help]\n\nRuns the staging soak checks (snapshot health, Timetoke SLO report, and admission reconciliation) and stores timestamped artefacts."
    );
}

fn relative_display(path: &Path, base: &Path) -> String {
    if let Ok(stripped) = path.strip_prefix(base) {
        stripped.display().to_string()
    } else {
        path.display().to_string()
    }
}

fn load_manifest_catalog_from_path(path: &Path) -> Result<ManifestCatalog> {
    let data = fs::read_to_string(path)
        .with_context(|| format!("read manifest file {}", path.display()))?;
    let json: JsonValue = serde_json::from_str(&data)
        .with_context(|| format!("parse manifest file {}", path.display()))?;
    load_manifest_catalog_from_value(&json, path.parent(), Some(path))
}

fn load_manifest_catalog_from_value(
    value: &JsonValue,
    base_dir: Option<&Path>,
    source_path: Option<&Path>,
) -> Result<ManifestCatalog> {
    if let Some(segments) = value.get("segments").and_then(|v| v.as_array()) {
        let mut entry = ManifestEntry::new(segments.len() as u64);
        if let Some(path) = source_path {
            entry.source = Some(path.to_path_buf());
            entry.add_alias(path.display().to_string());
        }
        if let Some(version) = value.get("version").and_then(|v| v.as_str()) {
            entry.add_alias(version);
        }
        return Ok(ManifestCatalog {
            entries: vec![entry],
        });
    }

    if let Some(snapshots) = value.get("snapshots").and_then(|v| v.as_array()) {
        let bundle_root = value
            .get("bundle_root")
            .and_then(|v| v.as_str())
            .and_then(|v| {
                let trimmed = v.trim();
                if trimmed.is_empty() {
                    None
                } else {
                    Some(PathBuf::from(trimmed))
                }
            });
        let mut catalog = ManifestCatalog::default();
        for snapshot in snapshots {
            if let Some(entry) =
                load_manifest_summary_entry(snapshot, base_dir, bundle_root.as_ref())?
            {
                catalog.entries.push(entry);
            }
        }
        return Ok(catalog);
    }

    bail!("unsupported manifest format: expected chunk manifest or summary");
}

fn load_manifest_summary_entry(
    value: &JsonValue,
    base_dir: Option<&Path>,
    bundle_root: Option<&PathBuf>,
) -> Result<Option<ManifestEntry>> {
    let obj = match value.as_object() {
        Some(obj) => obj,
        None => return Ok(None),
    };

    let plan_path = obj
        .get("plan")
        .and_then(|v| v.as_str())
        .map(|v| resolve_summary_path(base_dir, bundle_root, v));

    let plan_counts = if let Some(plan) = plan_path.as_ref() {
        Some(
            load_plan_counts(plan)
                .with_context(|| format!("load state-sync plan from {}", plan.display()))?,
        )
    } else {
        None
    };

    let chunk_total = if let Some(count) = obj.get("chunk_count").and_then(|v| v.as_u64()) {
        count
    } else if let Some(counts) = plan_counts.as_ref().and_then(|counts| counts.chunk_count) {
        counts
    } else {
        bail!("manifest summary entry missing chunk_count and plan metadata");
    };

    let mut entry = ManifestEntry::new(chunk_total);

    if let Some(plan) = plan_counts {
        entry.update_total = plan.update_count;
    }

    if let Some(plan) = plan_path {
        entry.add_alias(plan.display().to_string());
        if let Some(stem) = plan.file_stem().and_then(|stem| stem.to_str()) {
            entry.add_alias(stem);
        }
    }

    if let Some(manifest) = obj
        .get("manifest")
        .and_then(|v| v.as_str())
        .map(|v| resolve_summary_path(base_dir, bundle_root, v))
    {
        entry.source = Some(manifest.clone());
        entry.add_alias(manifest.display().to_string());
        if let Some(stem) = manifest.file_stem().and_then(|stem| stem.to_str()) {
            entry.add_alias(stem);
        }
    }

    if let Some(id) = obj.get("id").and_then(|v| v.as_str()) {
        entry.add_alias(id);
    }

    if let Some(root) = obj.get("state_root").and_then(|v| v.as_str()) {
        entry.add_alias(root);
    }

    if let Some(height) = obj.get("block_height").and_then(|v| v.as_u64()) {
        entry.add_alias(format!("height-{height}"));
    }

    Ok(Some(entry))
}

struct PlanCounts {
    chunk_count: Option<u64>,
    update_count: Option<u64>,
}

fn load_plan_counts(path: &Path) -> Result<PlanCounts> {
    let data = fs::read_to_string(path)
        .with_context(|| format!("read state-sync plan from {}", path.display()))?;
    let json: JsonValue = serde_json::from_str(&data)
        .with_context(|| format!("parse state-sync plan from {}", path.display()))?;
    let chunk_count = json
        .get("chunks")
        .and_then(|value| value.as_array())
        .map(|chunks| chunks.len() as u64);
    let update_count = json
        .get("updates")
        .and_then(|value| value.as_array())
        .map(|updates| updates.len() as u64);
    Ok(PlanCounts {
        chunk_count,
        update_count,
    })
}

fn resolve_summary_path(
    base_dir: Option<&Path>,
    bundle_root: Option<&PathBuf>,
    value: &str,
) -> PathBuf {
    let candidate = PathBuf::from(value);
    if candidate.is_absolute() {
        candidate
    } else if let Some(root) = bundle_root {
        let resolved_root = if root.is_absolute() {
            root.clone()
        } else if let Some(base) = base_dir {
            base.join(root)
        } else {
            root.clone()
        };
        resolved_root.join(candidate)
    } else if let Some(base) = base_dir {
        base.join(candidate)
    } else {
        candidate
    }
}

fn usage() {
    eprintln!(
        "xtask commands:\n  pruning-validation    Run pruning receipt conformance checks\n  test-unit            Execute lightweight unit test suites\n  test-integration     Execute integration workflows\n  test-observability   Run Prometheus-backed observability tests\n  test-simnet          Run the CI simnet scenarios\n  test-firewood        Run Firewood unit tests across the branch-factor matrix\n  test-cli            Run chain-cli help/version smoke checks\n  test-consensus-manipulation  Exercise consensus tamper detection tests\n  test-worm-export     Verify the WORM export pipeline against the stub backend\n  worm-retention-check Audit WORM retention windows, verify signatures, and surface stale entries\n  test-all             Run unit, integration, observability, and simnet scenarios\n  proof-metadata       Export circuit/proof metadata as JSON or markdown\n  proof-version-guard  Verify PROOF_VERSION bumps alongside proof-affecting changes\n  plonky3-setup        Regenerate Plonky3 setup JSON descriptors\n  plonky3-verify       Validate setup artifacts against embedded hash manifests\n  report-timetoke-slo  Summarise Timetoke replay SLOs from Prometheus or log archives\n  snapshot-verifier    Generate a synthetic snapshot bundle and aggregate verifier report\n  snapshot-health      Audit snapshot streaming progress against manifest totals\n  admission-reconcile  Compare runtime admission state, disk snapshots, and audit logs\n  staging-soak         Run the daily staging soak orchestration and store artefacts\n  collect-phase3-evidence  Bundle dashboards, alerts, audit logs, policy backups, checksum reports, and CI logs\n  verify-report        Validate snapshot verifier outputs against the JSON schema",
    );
}

fn proof_metadata_usage() {
    eprintln!(
        "usage: cargo xtask proof-metadata [--format json|markdown] [--output <path>]\n\nOutputs proof metadata aggregated from Plonky3 setup files, STWO verifying keys, and the blueprint.",
    );
}

fn report_timetoke_slo_usage() {
    eprintln!(
        "usage: cargo xtask report-timetoke-slo [--prometheus-url <url>] [--bearer-token <token>] [--metrics-log <path>] [--output <path>]\n\nSummarises the Timetoke replay success rate and latency SLOs across the last seven days. The command falls back to the environment variables TIMETOKE_PROMETHEUS_URL, TIMETOKE_PROMETHEUS_BEARER, and TIMETOKE_METRICS_LOG when CLI arguments are not provided.",
    );
}

fn snapshot_health_usage() {
    eprintln!(
        "usage: cargo xtask snapshot-health [--config <path>] [--rpc-url <url>] [--auth-token <token>] [--manifest <path>] [--output <path>] [--rpp-node-bin <path>]\n\nPolls active snapshot sessions via the validator RPC, executes the `rpp-node validator snapshot status` CLI for each session, and verifies chunk progress against the persisted manifest totals.",
    );
}

fn collect_phase3_evidence_usage() {
    eprintln!(
        "usage: cargo xtask collect-phase3-evidence [--output-dir <path>]\n\nBundles snapshot/timetoke dashboards, alert YAMLs, admission audit logs, policy backups, checksum reports, and CI job logs into a timestamped archive with a manifest.",
    );
}

fn verify_report_usage() {
    eprintln!(
        "usage: cargo xtask verify-report [--report <path>] [--schema <path>]\n\nValidates aggregated snapshot verifier reports (snapshot-verify-report.json) or per-manifest reports against the repository JSON schema. When --report is omitted the command searches dist/ and target/ for snapshot-verify-report.json and fails if multiple candidates exist.",
    );
}

const TIMETOKE_LOOKBACK_DAYS: i64 = 7;
const TIMETOKE_SUCCESS_RATE_TARGET: f64 = 0.99;
const TIMETOKE_LATENCY_P50_TARGET_MS: f64 = 5_000.0;
const TIMETOKE_LATENCY_P95_TARGET_MS: f64 = 60_000.0;
const TIMETOKE_LATENCY_P99_TARGET_MS: f64 = 120_000.0;

#[derive(Default)]
struct TimetokeSloSummary {
    source: String,
    window_start: Option<OffsetDateTime>,
    window_end: Option<OffsetDateTime>,
    successes: f64,
    failures: f64,
    p50_ms: Option<f64>,
    p95_ms: Option<f64>,
    p99_ms: Option<f64>,
}

impl TimetokeSloSummary {
    fn success_rate(&self) -> Option<f64> {
        let total = self.successes + self.failures;
        if total > 0.0 {
            Some(self.successes / total)
        } else {
            None
        }
    }
}

#[derive(Deserialize)]
struct TimetokeLogEntry {
    timestamp: String,
    successes: Option<f64>,
    failures: Option<f64>,
    #[serde(rename = "p50_ms")]
    replay_ms_p50: Option<f64>,
    #[serde(rename = "p95_ms")]
    replay_ms_p95: Option<f64>,
    #[serde(rename = "p99_ms")]
    replay_ms_p99: Option<f64>,
    #[serde(rename = "replay_p50_ms")]
    replay_alt_p50: Option<f64>,
    #[serde(rename = "replay_p95_ms")]
    replay_alt_p95: Option<f64>,
    #[serde(rename = "replay_p99_ms")]
    replay_alt_p99: Option<f64>,
}

#[derive(Default)]
struct TimetokeSloSource {
    prometheus_url: Option<String>,
    bearer_token: Option<String>,
    metrics_log: Option<PathBuf>,
}

struct TimetokeSloOptions {
    source: TimetokeSloSource,
    output: Option<PathBuf>,
}

fn parse_timetoke_slo_options(args: &[String]) -> Result<Option<TimetokeSloOptions>> {
    let mut source = TimetokeSloSource::default();
    let mut output: Option<PathBuf> = None;

    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--prometheus-url" => {
                let value = iter
                    .next()
                    .ok_or_else(|| anyhow!("--prometheus-url requires a value"))?;
                source.prometheus_url = normalise_string(Some(value.clone()));
            }
            "--bearer-token" => {
                let value = iter
                    .next()
                    .ok_or_else(|| anyhow!("--bearer-token requires a value"))?;
                source.bearer_token = normalise_string(Some(value.clone()));
            }
            "--metrics-log" => {
                let value = iter
                    .next()
                    .ok_or_else(|| anyhow!("--metrics-log requires a value"))?;
                if let Some(path) = normalise_string(Some(value.clone())) {
                    source.metrics_log = Some(PathBuf::from(path));
                }
            }
            "--output" => {
                let value = iter
                    .next()
                    .ok_or_else(|| anyhow!("--output requires a value"))?;
                output = Some(PathBuf::from(value));
            }
            "--help" | "-h" => {
                report_timetoke_slo_usage();
                return Ok(None);
            }
            other => bail!("unknown argument '{other}' for report-timetoke-slo"),
        }
    }

    if source.prometheus_url.is_none() {
        source.prometheus_url = env::var("TIMETOKE_PROMETHEUS_URL")
            .ok()
            .and_then(|value| normalise_string(Some(value)))
            .or_else(|| {
                env::var("PROMETHEUS_URL")
                    .ok()
                    .and_then(|v| normalise_string(Some(v)))
            });
    }
    if source.bearer_token.is_none() {
        source.bearer_token = env::var("TIMETOKE_PROMETHEUS_BEARER")
            .ok()
            .and_then(|value| normalise_string(Some(value)))
            .or_else(|| {
                env::var("PROMETHEUS_BEARER_TOKEN")
                    .ok()
                    .and_then(|v| normalise_string(Some(v)))
            });
    }
    if source.metrics_log.is_none() {
        source.metrics_log = env::var("TIMETOKE_METRICS_LOG")
            .ok()
            .and_then(|value| normalise_string(Some(value)))
            .map(PathBuf::from);
    }

    Ok(Some(TimetokeSloOptions { source, output }))
}

fn generate_timetoke_slo_summary(source: &TimetokeSloSource) -> Result<TimetokeSloSummary> {
    if let Some(url) = source.prometheus_url.as_ref() {
        fetch_prometheus_summary(url, source.bearer_token.as_deref())
    } else if let Some(path) = source.metrics_log.as_ref() {
        parse_log_summary(path)
    } else {
        bail!("report-timetoke-slo requires either --prometheus-url or --metrics-log");
    }
}

fn report_timetoke_slo(args: &[String]) -> Result<()> {
    let Some(options) = parse_timetoke_slo_options(args)? else {
        return Ok(());
    };

    let summary = generate_timetoke_slo_summary(&options.source)?;
    let report = render_timetoke_report(&summary);
    println!("{report}");

    if let Some(path) = options.output {
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent)
                    .with_context(|| format!("create output directory {}", parent.display()))?;
            }
        }
        fs::write(&path, report.as_bytes())
            .with_context(|| format!("write Timetoke SLO report to {}", path.display()))?;
    }

    Ok(())
}

fn normalise_string(value: Option<String>) -> Option<String> {
    value
        .map(|v| v.trim().to_string())
        .and_then(|v| if v.is_empty() { None } else { Some(v) })
}

fn fetch_prometheus_summary(url: &str, bearer: Option<&str>) -> Result<TimetokeSloSummary> {
    let client = HttpClient::builder()
        .timeout(StdDuration::from_secs(30))
        .build()
        .context("construct HTTP client")?;
    let now = OffsetDateTime::now_utc();
    let start = now - TimeDuration::days(TIMETOKE_LOOKBACK_DAYS);

    let successes = query_prometheus_value(
        &client,
        url,
        bearer,
        "sum(increase(timetoke_replay_success_total[7d]))",
    )?
    .unwrap_or(0.0);
    let failures = query_prometheus_value(
        &client,
        url,
        bearer,
        "sum(increase(timetoke_replay_failure_total[7d]))",
    )?
    .unwrap_or(0.0);
    let p50_ms = query_prometheus_value(
        &client,
        url,
        bearer,
        "histogram_quantile(0.50, sum(rate(timetoke_replay_duration_ms_bucket[7d])) by (le))",
    )?;
    let p95_ms = query_prometheus_value(
        &client,
        url,
        bearer,
        "histogram_quantile(0.95, sum(rate(timetoke_replay_duration_ms_bucket[7d])) by (le))",
    )?;
    let p99_ms = query_prometheus_value(
        &client,
        url,
        bearer,
        "histogram_quantile(0.99, sum(rate(timetoke_replay_duration_ms_bucket[7d])) by (le))",
    )?;

    Ok(TimetokeSloSummary {
        source: format!("Prometheus {}", url),
        window_start: Some(start),
        window_end: Some(now),
        successes,
        failures,
        p50_ms,
        p95_ms,
        p99_ms,
    })
}

fn query_prometheus_value(
    client: &HttpClient,
    base_url: &str,
    bearer: Option<&str>,
    query: &str,
) -> Result<Option<f64>> {
    let endpoint = format!("{}/api/v1/query", base_url.trim_end_matches('/'));
    let mut request = client.get(&endpoint).query(&[("query", query)]);
    if let Some(token) = bearer {
        request = request.bearer_auth(token);
    }

    let response = request
        .send()
        .with_context(|| format!("query Prometheus for '{query}'"))?
        .error_for_status()
        .with_context(|| format!("Prometheus returned error status for '{query}'"))?
        .json::<JsonValue>()
        .with_context(|| format!("decode Prometheus response for '{query}'"))?;

    match response.get("status").and_then(|value| value.as_str()) {
        Some("success") => {}
        Some(other) => {
            bail!("Prometheus reported status '{other}' for query '{query}'");
        }
        None => {
            bail!("Prometheus response missing status for query '{query}'");
        }
    }

    let result = response
        .get("data")
        .and_then(|data| data.get("result"))
        .and_then(|value| value.as_array())
        .ok_or_else(|| anyhow!("Prometheus response missing data.result for '{query}'"))?;

    let Some(first) = result.first() else {
        return Ok(None);
    };
    let value = first
        .get("value")
        .and_then(|value| value.as_array())
        .and_then(|values| values.get(1))
        .and_then(|value| value.as_str())
        .ok_or_else(|| anyhow!("Prometheus response missing value for '{query}'"))?;
    let parsed = value
        .parse::<f64>()
        .with_context(|| format!("parse Prometheus value '{value}' for '{query}'"))?;
    Ok(Some(parsed))
}

fn parse_log_summary(path: &Path) -> Result<TimetokeSloSummary> {
    let file = fs::File::open(path)
        .with_context(|| format!("open Timetoke metrics log {}", path.display()))?;
    let reader = BufReader::new(file);
    let cutoff = OffsetDateTime::now_utc() - TimeDuration::days(TIMETOKE_LOOKBACK_DAYS);

    let mut summary = TimetokeSloSummary::default();
    summary.source = format!("log file {}", path.display());

    let mut min_ts: Option<OffsetDateTime> = None;
    let mut max_ts: Option<OffsetDateTime> = None;
    let mut samples = 0usize;

    for (index, line) in reader.lines().enumerate() {
        let line =
            line.with_context(|| format!("read entry {} from {}", index + 1, path.display()))?;
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let entry: TimetokeLogEntry = serde_json::from_str(trimmed).with_context(|| {
            format!(
                "parse Timetoke metrics entry {} from {}",
                index + 1,
                path.display()
            )
        })?;
        let timestamp = OffsetDateTime::parse(&entry.timestamp, &Rfc3339).with_context(|| {
            format!(
                "parse timestamp '{}' in {}",
                entry.timestamp,
                path.display()
            )
        })?;
        if timestamp < cutoff {
            continue;
        }
        samples += 1;
        summary.successes += entry.successes.unwrap_or(0.0);
        summary.failures += entry.failures.unwrap_or(0.0);

        if let Some(value) = entry.replay_ms_p50.or(entry.replay_alt_p50) {
            summary.p50_ms = Some(match summary.p50_ms {
                Some(existing) => existing.max(value),
                None => value,
            });
        }
        if let Some(value) = entry.replay_ms_p95.or(entry.replay_alt_p95) {
            summary.p95_ms = Some(match summary.p95_ms {
                Some(existing) => existing.max(value),
                None => value,
            });
        }
        if let Some(value) = entry.replay_ms_p99.or(entry.replay_alt_p99) {
            summary.p99_ms = Some(match summary.p99_ms {
                Some(existing) => existing.max(value),
                None => value,
            });
        }

        min_ts = Some(match min_ts {
            Some(existing) if existing <= timestamp => existing,
            _ => timestamp,
        });
        max_ts = Some(match max_ts {
            Some(existing) if existing >= timestamp => existing,
            _ => timestamp,
        });
    }

    if samples == 0 {
        bail!(
            "no Timetoke metrics found in {} within the last {} days",
            path.display(),
            TIMETOKE_LOOKBACK_DAYS
        );
    }

    summary.window_start = min_ts;
    summary.window_end = max_ts;

    Ok(summary)
}

fn render_timetoke_report(summary: &TimetokeSloSummary) -> String {
    let mut output = String::new();
    let _ = writeln!(
        output,
        "# Timetoke Replay SLO Report (last {} days)",
        TIMETOKE_LOOKBACK_DAYS
    );
    let _ = writeln!(output);
    let _ = writeln!(output, "- Source: {}", summary.source);
    if let (Some(start), Some(end)) = (
        format_optional_datetime(summary.window_start),
        format_optional_datetime(summary.window_end),
    ) {
        let _ = writeln!(output, "- Window: {} – {}", start, end);
    } else if let Some(end) = format_optional_datetime(summary.window_end) {
        let _ = writeln!(output, "- Window end: {}", end);
    }

    let total = summary.successes + summary.failures;
    let _ = writeln!(output);
    let _ = writeln!(output, "## Replay success");
    let _ = writeln!(output, "- Observations: {:.0}", total);
    let _ = writeln!(output, "- Successes: {:.0}", summary.successes);
    let _ = writeln!(output, "- Failures: {:.0}", summary.failures);
    match summary.success_rate() {
        Some(rate) => {
            let percent = rate * 100.0;
            let status = if rate >= TIMETOKE_SUCCESS_RATE_TARGET {
                "✅"
            } else {
                "❌"
            };
            let _ = writeln!(
                output,
                "- Success rate: {} {:.2}% (target ≥ {:.2}%)",
                status,
                percent,
                TIMETOKE_SUCCESS_RATE_TARGET * 100.0
            );
        }
        None => {
            let _ = writeln!(
                output,
                "- Success rate: ⚠️ unavailable (target ≥ {:.2}%)",
                TIMETOKE_SUCCESS_RATE_TARGET * 100.0
            );
        }
    }

    let _ = writeln!(output);
    let _ = writeln!(output, "## Replay latency (timetoke_replay_duration_ms)");
    render_latency_line(
        &mut output,
        "p50",
        summary.p50_ms,
        TIMETOKE_LATENCY_P50_TARGET_MS,
    );
    render_latency_line(
        &mut output,
        "p95",
        summary.p95_ms,
        TIMETOKE_LATENCY_P95_TARGET_MS,
    );
    render_latency_line(
        &mut output,
        "p99",
        summary.p99_ms,
        TIMETOKE_LATENCY_P99_TARGET_MS,
    );

    output
}

fn render_latency_line(buffer: &mut String, label: &str, value: Option<f64>, target: f64) {
    match value {
        Some(latency) => {
            let status = if latency <= target { "✅" } else { "❌" };
            let _ = writeln!(
                buffer,
                "- {}: {} {:.2} ms (target ≤ {:.0} ms)",
                label, status, latency, target
            );
        }
        None => {
            let _ = writeln!(
                buffer,
                "- {}: ⚠️ no data (target ≤ {:.0} ms)",
                label, target
            );
        }
    }
}

fn format_optional_datetime(value: Option<OffsetDateTime>) -> Option<String> {
    value.and_then(|dt| dt.format(&Rfc3339).ok())
}

#[derive(Serialize, Deserialize)]
struct EvidenceFileEntry {
    path: String,
    sha256: String,
}

#[derive(Serialize, Deserialize)]
struct EvidenceCategoryManifest {
    name: String,
    description: String,
    files: Vec<EvidenceFileEntry>,
    missing: Vec<String>,
    warnings: Vec<String>,
}

#[derive(Serialize, Deserialize)]
struct EvidenceManifest {
    generated_at: String,
    bundle: String,
    categories: Vec<EvidenceCategoryManifest>,
    warnings: Vec<String>,
}

fn verify_snapshot_verifier_checksums(workspace: &Path) -> Result<usize> {
    let search_roots = [
        workspace.join("target"),
        workspace.join("dist"),
        workspace.join("logs"),
    ];
    let mut verified = 0usize;
    for root in search_roots.iter().filter(|path| path.exists()) {
        for entry in WalkDir::new(root)
            .max_depth(6)
            .into_iter()
            .filter_map(|res| res.ok())
            .filter(|entry| entry.file_type().is_file())
        {
            if entry
                .file_name()
                .to_str()
                .is_some_and(|name| name == "snapshot-verify-report.json.sha256")
            {
                verify_snapshot_sha256(entry.path())?;
                verified += 1;
            }
        }
    }
    Ok(verified)
}

fn verify_snapshot_sha256(sha_path: &Path) -> Result<()> {
    let contents = fs::read_to_string(sha_path)
        .with_context(|| format!("read snapshot verifier checksum {}", sha_path.display()))?;
    let line = contents
        .lines()
        .find(|line| !line.trim().is_empty())
        .ok_or_else(|| anyhow!("{} is empty", sha_path.display()))?;
    let mut parts = line.split_whitespace();
    let expected = parts
        .next()
        .ok_or_else(|| anyhow!("{} does not contain a hash", sha_path.display()))?;
    let target = parts
        .next()
        .ok_or_else(|| anyhow!("{} does not reference a file", sha_path.display()))?
        .trim_start_matches('*');
    let parent = sha_path
        .parent()
        .ok_or_else(|| anyhow!("{} is missing a parent directory", sha_path.display()))?;
    let report_path = parent.join(target);
    let report_bytes = fs::read(&report_path).with_context(|| {
        format!(
            "read snapshot verifier report {} referenced by {}",
            report_path.display(),
            sha_path.display()
        )
    })?;
    let mut hasher = Sha256::new();
    hasher.update(&report_bytes);
    let computed = hex_encode(hasher.finalize());
    if !computed.eq_ignore_ascii_case(expected.trim()) {
        bail!(
            "snapshot verifier report {} failed checksum validation against {}",
            report_path.display(),
            sha_path.display()
        );
    }
    println!(
        "verified snapshot verifier report checksum via {}",
        report_path.display()
    );
    Ok(())
}

fn verify_worm_export_signatures(workspace: &Path) -> Result<usize> {
    let search_roots = [
        workspace.join("target/worm-export-smoke"),
        workspace.join("logs"),
    ];
    let mut verified = 0usize;
    for root in search_roots.iter().filter(|path| path.exists()) {
        for entry in WalkDir::new(root)
            .max_depth(6)
            .into_iter()
            .filter_map(|res| res.ok())
            .filter(|entry| entry.file_type().is_file())
        {
            if entry
                .file_name()
                .to_str()
                .is_some_and(|name| name == "worm-export-summary.json")
            {
                verify_worm_export_summary(entry.path(), workspace)?;
                verified += 1;
            }
        }
    }
    Ok(verified)
}

fn verify_worm_export_summary(path: &Path, workspace: &Path) -> Result<()> {
    let contents = fs::read_to_string(path)
        .with_context(|| format!("read WORM export summary {}", path.display()))?;
    let summary: WormExportSummary = serde_json::from_str(&contents)
        .with_context(|| format!("decode WORM export summary {}", path.display()))?;
    if summary.entries.is_empty() {
        bail!(
            "WORM export summary {} does not contain any entries",
            path.display()
        );
    }
    let mut trust = HashMap::new();
    trust.insert(
        summary.signer_key_id.clone(),
        summary.signer_public_key_hex.clone(),
    );
    let trust_store = PolicyTrustStore::from_hex(trust).with_context(|| {
        format!(
            "construct trust store for WORM export summary {}",
            path.display()
        )
    })?;
    let verifier = PolicySignatureVerifier::new(trust_store);
    for entry in &summary.entries {
        if !entry.signature_valid {
            bail!(
                "WORM export summary {} flags entry {} as invalid",
                path.display(),
                entry.entry_id
            );
        }
        let export_path = resolve_workspace_path(workspace, &entry.export_object);
        let export_raw = fs::read_to_string(&export_path).with_context(|| {
            format!(
                "read WORM export object {} referenced by {}",
                export_path.display(),
                path.display()
            )
        })?;
        let log_entry: AdmissionPolicyLogEntry =
            serde_json::from_str(&export_raw).with_context(|| {
                format!(
                    "decode WORM export object {} referenced by {}",
                    export_path.display(),
                    path.display()
                )
            })?;
        let signature = log_entry.signature.clone().ok_or_else(|| {
            anyhow!(
                "WORM export object {} referenced by {} is missing a signature",
                export_path.display(),
                path.display()
            )
        })?;
        if signature.key_id != entry.signature_key {
            bail!(
                "WORM export entry {} expects signing key {} but object {} used {}",
                entry.entry_id,
                entry.signature_key,
                export_path.display(),
                signature.key_id
            );
        }
        let canonical = log_entry.canonical_bytes().map_err(|err| {
            anyhow!(
                "compute canonical payload for WORM export object {} (entry {} referenced by {}): {err}",
                export_path.display(),
                entry.entry_id,
                path.display()
            )
        })?;
        verifier.verify(&signature, &canonical).with_context(|| {
            format!(
                "verify signature for WORM export entry {} referenced by {}",
                entry.entry_id,
                path.display()
            )
        })?;
    }
    println!(
        "verified WORM export signatures via {} ({} entries)",
        path.display(),
        summary.entries.len()
    );
    Ok(())
}

fn resolve_workspace_path(workspace: &Path, recorded: &str) -> PathBuf {
    let candidate = Path::new(recorded);
    if candidate.is_absolute() {
        candidate.to_path_buf()
    } else {
        workspace.join(candidate)
    }
}

fn worm_retention_check_usage() {
    eprintln!(
        "usage: cargo xtask worm-retention-check [--root <path>]... [--output <path>]\n\n\
Searches for worm-export summaries, verifies signature coverage, and enforces retention windows.\n\
The command fails when stale, orphaned, or unsigned records are detected."
    );
}

fn worm_retention_check(args: &[String]) -> Result<()> {
    let workspace = workspace_root();
    let mut search_roots = vec![
        workspace.join("target/worm-export-smoke"),
        workspace.join("logs"),
    ];
    let mut output_path =
        workspace.join("target/compliance/worm-retention/worm-retention-report.json");

    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--root" => {
                let value = iter
                    .next()
                    .ok_or_else(|| anyhow!("--root requires a value"))?;
                let path = PathBuf::from(value);
                let resolved = if path.is_absolute() {
                    path
                } else {
                    workspace.join(path)
                };
                search_roots.push(resolved);
            }
            "--output" => {
                let value = iter
                    .next()
                    .ok_or_else(|| anyhow!("--output requires a value"))?;
                let path = PathBuf::from(value);
                output_path = if path.is_absolute() {
                    path
                } else {
                    workspace.join(path)
                };
            }
            "--help" | "-h" => {
                worm_retention_check_usage();
                return Ok(());
            }
            other => bail!("unknown argument '{other}' for worm-retention-check"),
        }
    }

    let mut metrics = MetricsReporter::from_env("nightly.worm_retention", "compliance-nightly")?;
    let result = execute_worm_retention_check(&workspace, &search_roots, &output_path);

    match result {
        Ok(outcome) => {
            let success = !outcome.has_failures();
            metrics.record_worm_retention(success);
            metrics.flush();

            println!(
                "worm retention report written to {}",
                outcome.report_path.display()
            );
            if outcome.report.summaries.is_empty() {
                println!(
                    "⚠️ no WORM export summaries located under the configured roots; report generated"
                );
            }

            if success {
                Ok(())
            } else {
                outcome.ensure_success()
            }
        }
        Err(error) => {
            metrics.record_worm_retention(false);
            metrics.flush();
            Err(error)
        }
    }
}

fn execute_worm_retention_check(
    workspace: &Path,
    search_roots: &[PathBuf],
    output_path: &Path,
) -> Result<WormRetentionCheckOutcome> {
    let mut report = WormRetentionCheckReport::default();
    report.generated_at = OffsetDateTime::now_utc().format(&Rfc3339)?;
    report.scanned_roots = search_roots
        .iter()
        .map(|path| {
            let display = path.strip_prefix(workspace).unwrap_or(path);
            relative_display_path(display)
        })
        .collect();

    let mut summary_paths: Vec<PathBuf> = Vec::new();
    for root in search_roots {
        if !root.exists() {
            continue;
        }
        for entry in WalkDir::new(root)
            .max_depth(6)
            .into_iter()
            .filter_map(|res| res.ok())
            .filter(|entry| entry.file_type().is_file())
        {
            if entry
                .file_name()
                .to_str()
                .is_some_and(|name| name == "worm-export-summary.json")
            {
                summary_paths.push(entry.path().to_path_buf());
            }
        }
    }
    summary_paths.sort();
    summary_paths.dedup();

    let mut aggregated_warnings = Vec::new();
    for summary_path in summary_paths {
        let evaluation = evaluate_worm_retention_summary(&summary_path, workspace)?;
        aggregated_warnings.extend(evaluation.warnings.clone());
        report
            .stale_entries
            .extend(evaluation.stale_entries.clone());
        report
            .orphaned_entries
            .extend(evaluation.orphaned_entries.clone());
        report
            .unsigned_records
            .extend(evaluation.unsigned_records.clone());
        report.summaries.push(evaluation.report);
    }

    if report.summaries.is_empty() {
        aggregated_warnings.push("no worm-export-summary.json files found".to_string());
    }
    report.warnings.extend(aggregated_warnings);

    if let Some(parent) = output_path.parent() {
        fs::create_dir_all(parent).with_context(|| {
            format!(
                "create worm retention report directory {}",
                parent.display()
            )
        })?;
    }
    fs::write(output_path, serde_json::to_vec_pretty(&report)?)
        .with_context(|| format!("write worm retention report {}", output_path.display()))?;

    Ok(WormRetentionCheckOutcome {
        report,
        report_path: output_path.to_path_buf(),
    })
}

fn evaluate_worm_retention_summary(
    summary_path: &Path,
    workspace: &Path,
) -> Result<WormRetentionSummaryEvaluation> {
    let contents = fs::read_to_string(summary_path)
        .with_context(|| format!("read worm export summary {}", summary_path.display()))?;
    let summary: WormExportSummary = serde_json::from_str(&contents)
        .with_context(|| format!("decode worm export summary {}", summary_path.display()))?;

    let summary_rel = summary_path.strip_prefix(workspace).unwrap_or(summary_path);
    let summary_display = relative_display_path(summary_rel);

    let audit_path = resolve_workspace_path(workspace, &summary.audit_log);
    let audit_rel = audit_path.strip_prefix(workspace).unwrap_or(&audit_path);
    let audit_display = relative_display_path(audit_rel);

    let export_root = resolve_workspace_path(workspace, &summary.export_root);
    let export_rel = export_root.strip_prefix(workspace).unwrap_or(&export_root);
    let export_display = relative_display_path(export_rel);

    let mut report = WormRetentionSummaryReport {
        summary_path: summary_display.clone(),
        audit_log: audit_display.clone(),
        export_root: export_display,
        retention: summary.retention,
        ..Default::default()
    };

    let mut warnings = Vec::new();
    let mut stale_entries = Vec::new();
    let mut orphaned_entries = Vec::new();
    let mut unsigned_records = Vec::new();

    let mut trust = HashMap::new();
    trust.insert(
        summary.signer_key_id.clone(),
        summary.signer_public_key_hex.clone(),
    );
    let trust_store = PolicyTrustStore::from_hex(trust).with_context(|| {
        format!(
            "construct trust store for worm export summary {}",
            summary_path.display()
        )
    })?;
    let verifier = PolicySignatureVerifier::new(trust_store);
    let now = OffsetDateTime::now_utc();

    let mut exported_entries: HashMap<u64, AdmissionPolicyLogEntry> = HashMap::new();
    let mut entry_reports = Vec::new();
    let mut latest_retain_until: Option<(OffsetDateTime, String)> = None;

    for entry_ref in &summary.entries {
        let export_path = resolve_workspace_path(workspace, &entry_ref.export_object);
        if !export_path.exists() {
            orphaned_entries.push(WormRetentionOrphanedEntry {
                summary_path: summary_display.clone(),
                entry_id: entry_ref.entry_id,
                context: format!(
                    "export object {} referenced by {} missing",
                    entry_ref.export_object, summary_display
                ),
            });
            continue;
        }
        let export_contents = fs::read_to_string(&export_path)
            .with_context(|| format!("read exported worm object {}", export_path.display()))?;
        let log_entry: AdmissionPolicyLogEntry = serde_json::from_str(&export_contents)
            .with_context(|| format!("decode exported worm object {}", export_path.display()))?;
        let export_rel = export_path
            .strip_prefix(workspace)
            .unwrap_or(export_path.as_path());
        let export_display = relative_display_path(export_rel);

        let mut verification_error: Option<String> = None;
        match log_entry.signature.as_ref() {
            Some(signature) => {
                if signature.key_id != entry_ref.signature_key {
                    verification_error = Some(format!(
                        "expected signing key {} but observed {}",
                        entry_ref.signature_key, signature.key_id
                    ));
                } else {
                    let canonical = log_entry.canonical_bytes().map_err(|err| {
                        anyhow!(
                            "canonicalise exported worm entry {}: {err}",
                            export_path.display()
                        )
                    })?;
                    if let Err(err) = verifier.verify(signature, &canonical) {
                        verification_error = Some(format!("signature verification failed: {err}"));
                    }
                }
            }
            None => {
                verification_error = Some("missing signature".to_string());
            }
        }
        if let Some(reason) = verification_error {
            unsigned_records.push(WormRetentionUnsignedRecord {
                log_path: export_display.clone(),
                entry_id: log_entry.id,
                reason,
            });
        }

        let retain_until = summary
            .retention
            .retain_until_string(log_entry.timestamp_ms)
            .with_context(|| {
                format!("compute retain-until timestamp for entry {}", log_entry.id)
            })?;
        let retain_until_dt =
            OffsetDateTime::parse(&retain_until, &Rfc3339).with_context(|| {
                format!(
                    "parse retain-until timestamp '{}' for entry {}",
                    retain_until, log_entry.id
                )
            })?;
        if latest_retain_until
            .as_ref()
            .map(|(existing, _)| retain_until_dt > *existing)
            .unwrap_or(true)
        {
            latest_retain_until = Some((retain_until_dt, retain_until.clone()));
        }
        let stale = retain_until_dt < now;
        if stale {
            stale_entries.push(WormRetentionStaleEntry {
                summary_path: summary_display.clone(),
                entry_id: log_entry.id,
                export_object: export_display.clone(),
                retain_until: retain_until.clone(),
            });
        }
        entry_reports.push(WormRetentionEntryReport {
            entry_id: log_entry.id,
            timestamp_ms: log_entry.timestamp_ms,
            export_object: export_display,
            retain_until,
            stale,
        });
        exported_entries.insert(log_entry.id, log_entry);
    }
    report.entries = entry_reports;

    let audit_entries = load_audit_log_entries(&audit_path).with_context(|| {
        format!(
            "load audit log {} referenced by summary",
            audit_path.display()
        )
    })?;
    let mut audit_ids = HashSet::new();
    for entry in &audit_entries {
        audit_ids.insert(entry.id);
        let mut verification_error: Option<String> = None;
        match entry.signature.as_ref() {
            Some(signature) => {
                let canonical = entry.canonical_bytes().map_err(|err| {
                    anyhow!(
                        "canonicalise audit log entry {} in {}: {err}",
                        entry.id,
                        audit_path.display()
                    )
                })?;
                if let Err(err) = verifier.verify(signature, &canonical) {
                    verification_error = Some(format!("signature verification failed: {err}"));
                }
            }
            None => {
                verification_error = Some("missing signature".to_string());
            }
        }
        if let Some(reason) = verification_error {
            unsigned_records.push(WormRetentionUnsignedRecord {
                log_path: audit_display.clone(),
                entry_id: entry.id,
                reason,
            });
        }
        if !exported_entries.contains_key(&entry.id) {
            orphaned_entries.push(WormRetentionOrphanedEntry {
                summary_path: summary_display.clone(),
                entry_id: entry.id,
                context: format!(
                    "audit log {} contains entry {} without exported object",
                    audit_display, entry.id
                ),
            });
        }
    }
    for entry_id in exported_entries.keys() {
        if !audit_ids.contains(entry_id) {
            orphaned_entries.push(WormRetentionOrphanedEntry {
                summary_path: summary_display.clone(),
                entry_id: *entry_id,
                context: format!("exported object missing audit entry in {}", audit_display),
            });
        }
    }

    if let Some(metadata) = &summary.retention_metadata {
        let metadata_path = resolve_workspace_path(workspace, metadata);
        if metadata_path.exists() {
            let metadata_rel = metadata_path
                .strip_prefix(workspace)
                .unwrap_or(metadata_path.as_path());
            let metadata_display = relative_display_path(metadata_rel);
            let values = parse_retention_metadata(&metadata_path)
                .with_context(|| format!("parse retention metadata {}", metadata_path.display()))?;
            let mut metadata_report = WormRetentionMetadataReport {
                path: metadata_display.clone(),
                values: values.clone(),
                valid: true,
                warnings: Vec::new(),
            };

            match values
                .get("min_days")
                .and_then(|value| value.parse::<u64>().ok())
            {
                Some(value) if value == summary.retention.min_days => {}
                _ => {
                    metadata_report.valid = false;
                    metadata_report.warnings.push(format!(
                        "min_days mismatch (expected {}, recorded {:?})",
                        summary.retention.min_days,
                        values.get("min_days")
                    ));
                }
            }

            match summary.retention.max_days {
                Some(expected) => {
                    let recorded = values
                        .get("max_days")
                        .and_then(|value| value.parse::<u64>().ok());
                    if recorded != Some(expected) {
                        metadata_report.valid = false;
                        metadata_report.warnings.push(format!(
                            "max_days mismatch (expected {}, recorded {:?})",
                            expected,
                            values.get("max_days")
                        ));
                    }
                }
                None => {
                    if values
                        .get("max_days")
                        .is_some_and(|value| !value.trim().is_empty())
                    {
                        metadata_report.valid = false;
                        metadata_report
                            .warnings
                            .push("max_days present despite retention.max_days=None".to_string());
                    }
                }
            }

            let expected_mode = match summary.retention.mode {
                WormRetentionMode::Compliance => "COMPLIANCE",
                WormRetentionMode::Governance => "GOVERNANCE",
            };
            match values.get("mode") {
                Some(mode) if mode.eq_ignore_ascii_case(expected_mode) => {}
                Some(mode) => {
                    metadata_report.valid = false;
                    metadata_report.warnings.push(format!(
                        "mode mismatch (expected {}, recorded {})",
                        expected_mode, mode
                    ));
                }
                None => {
                    metadata_report.valid = false;
                    metadata_report
                        .warnings
                        .push("mode entry missing in retention metadata".to_string());
                }
            }

            if let Some((_, expected)) = &latest_retain_until {
                match values.get("retain_until") {
                    Some(recorded) if recorded == expected => {}
                    Some(recorded) => {
                        metadata_report.valid = false;
                        metadata_report.warnings.push(format!(
                            "retain_until mismatch (expected {}, recorded {})",
                            expected, recorded
                        ));
                    }
                    None => {
                        metadata_report.valid = false;
                        metadata_report
                            .warnings
                            .push("retain_until missing from retention metadata".to_string());
                    }
                }
            } else {
                metadata_report
                    .warnings
                    .push("no exported entries to validate retain_until window".to_string());
            }

            warnings.extend(metadata_report.warnings.clone());
            report.retention_metadata = Some(metadata_report);
        } else {
            warnings.push(format!(
                "retention metadata {} referenced by {} missing",
                metadata, summary_display
            ));
        }
    }

    let retention_logs = discover_retention_logs(summary_path, &export_root)?;
    for log_path in retention_logs {
        let log_rel = log_path
            .strip_prefix(workspace)
            .unwrap_or(log_path.as_path());
        let log_display = relative_display_path(log_rel);
        let entries = load_audit_log_entries(&log_path)
            .with_context(|| format!("read retention log {}", log_path.display()))?;
        let mut unsigned_count = 0usize;
        for entry in &entries {
            let mut issue = None;
            match entry.signature.as_ref() {
                Some(signature) => {
                    let canonical = entry.canonical_bytes().map_err(|err| {
                        anyhow!(
                            "canonicalise retention log entry {} in {}: {err}",
                            entry.id,
                            log_path.display()
                        )
                    })?;
                    if let Err(err) = verifier.verify(signature, &canonical) {
                        issue = Some(format!("signature verification failed: {err}"));
                    }
                }
                None => {
                    issue = Some("missing signature".to_string());
                }
            }
            if let Some(reason) = issue {
                unsigned_count += 1;
                unsigned_records.push(WormRetentionUnsignedRecord {
                    log_path: log_display.clone(),
                    entry_id: entry.id,
                    reason,
                });
            }
        }
        report.retention_logs.push(WormRetentionLogReport {
            path: log_display,
            record_count: entries.len(),
            unsigned_records: unsigned_count,
        });
    }

    report.warnings.extend(warnings.clone());
    Ok(WormRetentionSummaryEvaluation {
        report,
        stale_entries,
        orphaned_entries,
        unsigned_records,
        warnings,
    })
}

fn discover_retention_logs(summary_path: &Path, export_root: &Path) -> Result<Vec<PathBuf>> {
    let mut candidates = Vec::new();
    if let Some(parent) = summary_path.parent() {
        if parent.exists() {
            candidates.push(parent.to_path_buf());
        }
    }
    if export_root.exists() {
        candidates.push(export_root.to_path_buf());
    }

    let mut logs = Vec::new();
    for root in candidates {
        for entry in fs::read_dir(&root)
            .with_context(|| format!("list retention directory {}", root.display()))?
        {
            let entry = entry?;
            let path = entry.path();
            if !path.is_file() {
                continue;
            }
            let file_name = entry
                .file_name()
                .into_string()
                .unwrap_or_else(|_| "".to_string())
                .to_ascii_lowercase();
            if !(file_name.contains("retention")
                || file_name.contains("archive")
                || file_name.contains("delete"))
            {
                continue;
            }
            if !matches!(
                path.extension().and_then(|ext| ext.to_str()),
                Some(ext) if matches!(ext, "json" | "jsonl" | "log")
            ) {
                continue;
            }
            logs.push(path);
        }
    }

    logs.sort();
    logs.dedup();
    Ok(logs)
}

fn load_audit_log_entries(path: &Path) -> Result<Vec<AdmissionPolicyLogEntry>> {
    let file = File::open(path).with_context(|| format!("open audit log {}", path.display()))?;
    let reader = BufReader::new(file);
    let mut entries = Vec::new();
    for line in reader.lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        let entry: AdmissionPolicyLogEntry = serde_json::from_str(&line)
            .with_context(|| format!("decode audit log entry from {}", path.display()))?;
        entries.push(entry);
    }
    Ok(entries)
}

fn parse_retention_metadata(path: &Path) -> Result<BTreeMap<String, String>> {
    let contents = fs::read_to_string(path)
        .with_context(|| format!("read retention metadata {}", path.display()))?;
    let mut values = BTreeMap::new();
    for line in contents.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        if let Some((key, value)) = trimmed.split_once('=') {
            values.insert(key.trim().to_string(), value.trim().to_string());
        }
    }
    Ok(values)
}

fn collect_phase3_evidence(args: &[String]) -> Result<()> {
    let workspace = workspace_root();
    let mut output_root = workspace.join("target/compliance/phase3");

    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--output-dir" => {
                let value = iter
                    .next()
                    .ok_or_else(|| anyhow!("--output-dir requires a value"))?;
                let candidate = PathBuf::from(value);
                output_root = if candidate.is_absolute() {
                    candidate
                } else {
                    workspace.join(candidate)
                };
            }
            "--help" | "-h" => {
                collect_phase3_evidence_usage();
                return Ok(());
            }
            other => bail!("unknown argument '{other}' for collect-phase3-evidence"),
        }
    }

    fs::create_dir_all(&output_root)?;
    let now = OffsetDateTime::now_utc();
    let timestamp = now.format(&format_description!(
        "[year][month][day]T[hour][minute][second]Z"
    ))?;
    let staging_dir = output_root.join(&timestamp);
    fs::create_dir_all(&staging_dir)?;

    let snapshot_verified = verify_snapshot_verifier_checksums(&workspace)?;
    if snapshot_verified == 0 {
        println!("⚠️ no snapshot verifier reports with SHA256 found; skipping checksum validation");
    }
    let worm_verified = verify_worm_export_signatures(&workspace)?;
    if worm_verified == 0 {
        println!("⚠️ no WORM export summaries found; skipping signature verification");
    }

    let retention_roots = vec![
        workspace.join("target/worm-export-smoke"),
        workspace.join("logs"),
        workspace.join("target/compliance/worm-retention"),
    ];
    let retention_output =
        workspace.join("target/compliance/worm-retention/worm-retention-report.json");
    let retention_outcome =
        execute_worm_retention_check(&workspace, &retention_roots, &retention_output)?;
    if retention_outcome.report.summaries.is_empty() {
        println!("⚠️ worm retention check did not locate any summaries; report generated");
    }
    retention_outcome.ensure_success()?;

    let mut categories = Vec::new();
    categories.push(bundle_snapshot_dashboards(&workspace, &staging_dir)?);
    categories.push(bundle_alert_rules(&workspace, &staging_dir)?);
    categories.push(bundle_audit_logs(&workspace, &staging_dir)?);
    categories.push(bundle_policy_backups(&workspace, &staging_dir)?);
    categories.push(bundle_worm_exports(&workspace, &staging_dir)?);
    categories.push(bundle_snapshot_signatures(&workspace, &staging_dir)?);
    categories.push(bundle_checksum_reports(&workspace, &staging_dir)?);
    categories.push(bundle_chaos_reports(&workspace, &staging_dir)?);
    categories.push(bundle_ci_job_logs(&workspace, &staging_dir)?);

    let bundle_name = format!("phase3-evidence-{timestamp}.tar.gz");
    let bundle_path = output_root.join(&bundle_name);

    let manifest = EvidenceManifest {
        generated_at: now.format(&Rfc3339)?,
        bundle: bundle_name,
        categories,
        warnings: Vec::new(),
    };
    let manifest_path = staging_dir.join("manifest.json");
    fs::write(&manifest_path, serde_json::to_vec_pretty(&manifest)?)?;

    validate_phase3_manifest(&workspace, &staging_dir, &manifest_path)?;
    let manifest_sha256 = compute_sha256(&manifest_path)?;

    create_tarball(&staging_dir, &bundle_path)?;

    println!("phase3 evidence bundle created: {}", bundle_path.display());
    println!("manifest: {}", manifest_path.display());
    println!("manifest sha256: {manifest_sha256}");

    Ok(())
}

fn create_tarball(source_dir: &Path, output: &Path) -> Result<()> {
    let file = File::create(output)?;
    let encoder = GzEncoder::new(file, Compression::default());
    let mut builder = TarBuilder::new(encoder);
    builder.append_dir_all("phase3-evidence", source_dir)?;
    let encoder = builder.into_inner()?;
    encoder.finish()?;
    Ok(())
}

fn validate_phase3_manifest(
    workspace: &Path,
    staging_dir: &Path,
    manifest_path: &Path,
) -> Result<()> {
    let schema_path = workspace.join("docs/governance/phase3_evidence_manifest.schema.json");
    if !schema_path.exists() {
        bail!(
            "phase3 evidence manifest schema {} not found; ensure repository documentation is up to date",
            schema_path.display()
        );
    }

    let schema_file = File::open(&schema_path)
        .with_context(|| format!("open phase3 evidence schema {}", schema_path.display()))?;
    let schema_json: JsonValue = serde_json::from_reader(schema_file)
        .with_context(|| format!("parse phase3 evidence schema {}", schema_path.display()))?;
    let compiled = JSONSchema::options()
        .with_draft(Draft::Draft7)
        .compile(&schema_json)
        .context("compile phase3 evidence manifest schema")?;

    let manifest_bytes = fs::read(manifest_path)
        .with_context(|| format!("read manifest {}", manifest_path.display()))?;
    let manifest_json: JsonValue = serde_json::from_slice(&manifest_bytes)
        .with_context(|| format!("parse manifest {}", manifest_path.display()))?;
    if let Err(errors) = compiled.validate(&manifest_json) {
        let mut details = String::from("phase3 evidence manifest schema validation failed:");
        for error in errors {
            write!(&mut details, "\n  - {error}")?;
        }
        bail!(details);
    }

    let manifest: EvidenceManifest = serde_json::from_slice(&manifest_bytes)
        .with_context(|| format!("deserialize manifest {}", manifest_path.display()))?;
    for category in &manifest.categories {
        for file_entry in &category.files {
            let candidate = staging_dir.join(&file_entry.path);
            if !candidate.exists() {
                bail!(
                    "phase3 evidence manifest references missing file '{}' (category '{}')",
                    file_entry.path,
                    category.name
                );
            }
            let actual = compute_sha256(&candidate)?;
            if actual != file_entry.sha256 {
                bail!(
                    "phase3 evidence manifest checksum mismatch for '{}' (category '{}'): expected {}, computed {}",
                    file_entry.path,
                    category.name,
                    file_entry.sha256,
                    actual
                );
            }
        }
    }

    Ok(())
}

fn bundle_snapshot_dashboards(
    workspace: &Path,
    staging: &Path,
) -> Result<EvidenceCategoryManifest> {
    let mut category = EvidenceCategoryManifest {
        name: "Snapshot & Timetoke dashboards".to_string(),
        description:
            "Grafana JSON exports highlighting snapshot throughput, lag, and timetoke replay panels.".
                to_string(),
        files: Vec::new(),
        missing: Vec::new(),
        warnings: Vec::new(),
    };
    let dashboards_dir = workspace.join("docs/dashboards");
    if dashboards_dir.exists() {
        for entry in WalkDir::new(&dashboards_dir)
            .into_iter()
            .filter_map(|res| res.ok())
            .filter(|entry| entry.file_type().is_file())
        {
            let path = entry.path();
            if !matches!(path.extension().and_then(|ext| ext.to_str()), Some(ext) if ext.eq_ignore_ascii_case("json"))
            {
                continue;
            }
            let file_name = path
                .file_name()
                .and_then(|value| value.to_str())
                .unwrap_or("")
                .to_ascii_lowercase();
            let mut matches = file_name.contains("snapshot") || file_name.contains("timetoke");
            if !matches {
                match fs::read_to_string(path) {
                    Ok(contents) => {
                        let lower = contents.to_ascii_lowercase();
                        matches = lower.contains("snapshot") || lower.contains("timetoke");
                    }
                    Err(err) => category
                        .warnings
                        .push(format!("failed to read {}: {err}", path.display())),
                }
            }
            if matches {
                let recorded = copy_into_category(workspace, staging, "dashboards", path)?;
                category.files.push(recorded);
            }
        }
    } else {
        category
            .missing
            .push("docs/dashboards directory not found".to_string());
    }
    if category.files.is_empty() {
        category
            .missing
            .push("docs/dashboards exports containing snapshot or timetoke metrics".to_string());
    }
    category.files.sort_by(|lhs, rhs| lhs.path.cmp(&rhs.path));
    category.files.dedup_by(|lhs, rhs| lhs.path == rhs.path);
    Ok(category)
}

fn bundle_alert_rules(workspace: &Path, staging: &Path) -> Result<EvidenceCategoryManifest> {
    let mut category = EvidenceCategoryManifest {
        name: "Alertmanager rules".to_string(),
        description: "Prometheus/Alertmanager YAML definitions for snapshot and timetoke monitors."
            .to_string(),
        files: Vec::new(),
        missing: Vec::new(),
        warnings: Vec::new(),
    };
    let alerts_dir = workspace.join("docs/observability/alerts");
    if alerts_dir.exists() {
        for entry in WalkDir::new(&alerts_dir)
            .max_depth(2)
            .into_iter()
            .filter_map(|res| res.ok())
            .filter(|entry| entry.file_type().is_file())
        {
            let path = entry.path();
            if !matches!(path.extension().and_then(|ext| ext.to_str()), Some(ext) if matches!(ext, "yaml" | "yml"))
            {
                continue;
            }
            let recorded = copy_into_category(workspace, staging, "alerts", path)?;
            category.files.push(recorded);
        }
    } else {
        category
            .missing
            .push("docs/observability/alerts directory not found".to_string());
    }
    if category.files.is_empty() {
        category
            .missing
            .push("docs/observability/alerts/*.yaml".to_string());
    }
    category.files.sort_by(|lhs, rhs| lhs.path.cmp(&rhs.path));
    category.files.dedup_by(|lhs, rhs| lhs.path == rhs.path);
    Ok(category)
}

fn bundle_audit_logs(workspace: &Path, staging: &Path) -> Result<EvidenceCategoryManifest> {
    let mut category = EvidenceCategoryManifest {
        name: "Admission audit logs".to_string(),
        description: "Append-only admission or policy audit trails exported for compliance review."
            .to_string(),
        files: Vec::new(),
        missing: Vec::new(),
        warnings: Vec::new(),
    };
    let mut candidates: Vec<(PathBuf, Option<usize>)> = Vec::new();
    let logs_dir = workspace.join("logs");
    if logs_dir.exists() {
        candidates.push((logs_dir, Some(4)));
    }
    let examples_dir = workspace.join("docs/observability/examples");
    if examples_dir.exists() {
        candidates.push((examples_dir, Some(2)));
    }
    for (root, depth) in candidates {
        let walker = if let Some(limit) = depth {
            WalkDir::new(&root).max_depth(limit)
        } else {
            WalkDir::new(&root)
        };
        for entry in walker
            .into_iter()
            .filter_map(|res| res.ok())
            .filter(|entry| entry.file_type().is_file())
        {
            let path = entry.path();
            let lower = path.to_string_lossy().to_ascii_lowercase();
            if !lower.contains("audit") {
                continue;
            }
            if !matches!(path.extension().and_then(|ext| ext.to_str()), Some(ext) if matches!(ext, "log" | "jsonl" | "json" | "txt"))
            {
                continue;
            }
            let recorded = copy_into_category(workspace, staging, "audit-logs", path)?;
            category.files.push(recorded);
        }
    }
    if category.files.is_empty() {
        category
            .missing
            .push("logs/*audit*.log or *.jsonl".to_string());
        category
            .missing
            .push("docs/observability/examples/*audit*.jsonl".to_string());
    }
    category.files.sort_by(|lhs, rhs| lhs.path.cmp(&rhs.path));
    category.files.dedup_by(|lhs, rhs| lhs.path == rhs.path);
    Ok(category)
}

fn bundle_policy_backups(workspace: &Path, staging: &Path) -> Result<EvidenceCategoryManifest> {
    let mut category = EvidenceCategoryManifest {
        name: "Admission policy backups".to_string(),
        description: "Filesystem snapshots of tier admission policies with retention metadata."
            .to_string(),
        files: Vec::new(),
        missing: Vec::new(),
        warnings: Vec::new(),
    };
    let search_roots = [
        workspace.join("logs"),
        workspace.join("storage"),
        workspace.join("config"),
        workspace.join("docs"),
        workspace.join("target"),
    ];
    for root in search_roots.iter().filter(|path| path.exists()) {
        let walker = WalkDir::new(root).max_depth(6);
        for entry in walker
            .into_iter()
            .filter_map(|res| res.ok())
            .filter(|entry| entry.file_type().is_file())
        {
            let path = entry.path();
            let lower = path.to_string_lossy().to_ascii_lowercase();
            if !(lower.contains("backup")
                && (lower.contains("policy") || lower.contains("admission")))
            {
                continue;
            }
            let recorded = copy_into_category(workspace, staging, "policy-backups", path)?;
            category.files.push(recorded);
        }
    }
    if category.files.is_empty() {
        category
            .missing
            .push("admission policy backup archives (*.json, *.tar.gz)".to_string());
    }
    category.files.sort_by(|lhs, rhs| lhs.path.cmp(&rhs.path));
    category.files.dedup_by(|lhs, rhs| lhs.path == rhs.path);
    Ok(category)
}

fn bundle_snapshot_signatures(
    workspace: &Path,
    staging: &Path,
) -> Result<EvidenceCategoryManifest> {
    let mut category = EvidenceCategoryManifest {
        name: "Snapshot manifest signatures".to_string(),
        description: "Detached signatures and verifying keys for snapshot manifest bundles."
            .to_string(),
        files: Vec::new(),
        missing: Vec::new(),
        warnings: Vec::new(),
    };
    let search_roots = [
        workspace.join("target/snapshot-verifier-smoke"),
        workspace.join("logs"),
    ];
    for root in search_roots.iter().filter(|path| path.exists()) {
        for entry in WalkDir::new(root)
            .max_depth(6)
            .into_iter()
            .filter_map(|res| res.ok())
            .filter(|entry| entry.file_type().is_file())
        {
            let path = entry.path();
            let lower = path.to_string_lossy().to_ascii_lowercase();
            if !(lower.contains("snapshot") || lower.contains("manifest")) {
                continue;
            }
            let ext = path.extension().and_then(|ext| ext.to_str()).unwrap_or("");
            let is_signature = matches!(ext, "sig" | "sha256");
            let is_key = matches!(ext, "hex" | "pub" | "pem")
                && entry
                    .file_name()
                    .to_str()
                    .is_some_and(|name| name.to_ascii_lowercase().contains("key"));
            if !(is_signature || is_key) {
                continue;
            }
            let recorded = copy_into_category(workspace, staging, "snapshot-signatures", path)?;
            category.files.push(recorded);
        }
    }
    if category.files.is_empty() {
        category.missing.push(
            "Snapshot manifest signatures and verifying keys (target/snapshot-verifier-smoke)"
                .to_string(),
        );
    }
    category.files.sort_by(|lhs, rhs| lhs.path.cmp(&rhs.path));
    category.files.dedup_by(|lhs, rhs| lhs.path == rhs.path);
    Ok(category)
}

fn bundle_worm_exports(workspace: &Path, staging: &Path) -> Result<EvidenceCategoryManifest> {
    let mut category = EvidenceCategoryManifest {
        name: "WORM export evidence".to_string(),
        description:
            "Admission audit WORM export logs, retention metadata, and aggregated verification summaries.".to_string(),
        files: Vec::new(),
        missing: Vec::new(),
        warnings: Vec::new(),
    };
    let search_roots = [
        workspace.join("target/worm-export-smoke"),
        workspace.join("logs"),
        workspace.join("target/compliance/worm-retention"),
    ];
    for root in search_roots.iter().filter(|path| path.exists()) {
        for entry in WalkDir::new(root)
            .max_depth(6)
            .into_iter()
            .filter_map(|res| res.ok())
            .filter(|entry| entry.file_type().is_file())
        {
            let path = entry.path();
            let lower = path.to_string_lossy().to_ascii_lowercase();
            if !lower.contains("worm") {
                continue;
            }
            if !matches!(
                path.extension().and_then(|ext| ext.to_str()),
                Some(ext) if matches!(ext, "json" | "jsonl" | "meta" | "sha256")
            ) {
                continue;
            }
            let recorded = copy_into_category(workspace, staging, "worm-export", path)?;
            category.files.push(recorded);
        }
    }
    if category.files.is_empty() {
        category.missing.push(
            "WORM export audit logs and verification summaries (target/worm-export-smoke)"
                .to_string(),
        );
    }
    category.files.sort_by(|lhs, rhs| lhs.path.cmp(&rhs.path));
    category.files.dedup_by(|lhs, rhs| lhs.path == rhs.path);
    Ok(category)
}

fn bundle_checksum_reports(workspace: &Path, staging: &Path) -> Result<EvidenceCategoryManifest> {
    let mut category = EvidenceCategoryManifest {
        name: "Checksum reports".to_string(),
        description: "Reports validating snapshot checksum monitors or restart drills.".to_string(),
        files: Vec::new(),
        missing: Vec::new(),
        warnings: Vec::new(),
    };
    let search_roots = [
        workspace.join("logs"),
        workspace.join("docs"),
        workspace.join("target"),
    ];
    for root in search_roots.iter().filter(|path| path.exists()) {
        let walker = WalkDir::new(root).max_depth(6);
        for entry in walker
            .into_iter()
            .filter_map(|res| res.ok())
            .filter(|entry| entry.file_type().is_file())
        {
            let path = entry.path();
            let lower = path.to_string_lossy().to_ascii_lowercase();
            if !lower.contains("checksum") {
                continue;
            }
            if !matches!(path.extension().and_then(|ext| ext.to_str()), Some(ext) if matches!(ext, "log" | "json" | "jsonl" | "txt" | "md" | "csv"))
            {
                continue;
            }
            let recorded = copy_into_category(workspace, staging, "checksum-reports", path)?;
            category.files.push(recorded);
        }
    }
    if category.files.is_empty() {
        category
            .missing
            .push("Checksum validation outputs (*.log, *.json, *.md)".to_string());
    }
    category.files.sort_by(|lhs, rhs| lhs.path.cmp(&rhs.path));
    category.files.dedup_by(|lhs, rhs| lhs.path == rhs.path);
    Ok(category)
}

fn bundle_chaos_reports(workspace: &Path, staging: &Path) -> Result<EvidenceCategoryManifest> {
    let mut category = EvidenceCategoryManifest {
        name: "Chaos drill reports".to_string(),
        description: "Partition and chaos drill summaries documenting recovery thresholds."
            .to_string(),
        files: Vec::new(),
        missing: Vec::new(),
        warnings: Vec::new(),
    };
    let search_roots = vec![
        workspace.join("target/simnet"),
        workspace.join("target/compliance/chaos"),
        workspace.join("logs"),
    ];
    for root in search_roots.iter().filter(|path| path.exists()) {
        for entry in WalkDir::new(root)
            .max_depth(6)
            .into_iter()
            .filter_map(|res| res.ok())
            .filter(|entry| entry.file_type().is_file())
        {
            let path = entry.path();
            let file_name = entry
                .file_name()
                .to_str()
                .map(|name| name.to_ascii_lowercase())
                .unwrap_or_default();
            let ext = path
                .extension()
                .and_then(|ext| ext.to_str())
                .map(|ext| ext.to_ascii_lowercase())
                .unwrap_or_default();
            let is_report = file_name.contains("snapshot_partition_report")
                || (file_name.contains("chaos") && file_name.contains("report"));
            let allowed_ext = matches!(ext.as_str(), "json" | "jsonl" | "log" | "txt" | "png");
            if !(is_report && allowed_ext) {
                continue;
            }
            let recorded = copy_into_category(workspace, staging, "chaos-reports", path)?;
            category.files.push(recorded);
        }
    }
    let partition_report = workspace.join("snapshot_partition_report.json");
    if partition_report.exists() {
        let recorded = copy_into_category(workspace, staging, "chaos-reports", &partition_report)?;
        category.files.push(recorded);
    }
    if category.files.is_empty() {
        category.missing.push(
            "Chaos drill reports (e.g. snapshot_partition_report.json from nightly snapshot-partition run)"
                .to_string(),
        );
    }
    category.files.sort_by(|lhs, rhs| lhs.path.cmp(&rhs.path));
    category.files.dedup_by(|lhs, rhs| lhs.path == rhs.path);
    Ok(category)
}

fn bundle_ci_job_logs(workspace: &Path, staging: &Path) -> Result<EvidenceCategoryManifest> {
    let mut category = EvidenceCategoryManifest {
        name: "CI job logs".to_string(),
        description: "Selected CI logs demonstrating nightly or weekly compliance checks."
            .to_string(),
        files: Vec::new(),
        missing: Vec::new(),
        warnings: Vec::new(),
    };
    let logs_dir = workspace.join("logs");
    if logs_dir.exists() {
        for entry in WalkDir::new(&logs_dir)
            .max_depth(4)
            .into_iter()
            .filter_map(|res| res.ok())
            .filter(|entry| entry.file_type().is_file())
        {
            let path = entry.path();
            let lower = path.to_string_lossy().to_ascii_lowercase();
            if !(lower.contains("ci") || lower.contains("nightly") || lower.contains("simnet")) {
                continue;
            }
            if !matches!(path.extension().and_then(|ext| ext.to_str()), Some(ext) if matches!(ext, "log" | "txt" | "json" | "jsonl"))
            {
                continue;
            }
            let recorded = copy_into_category(workspace, staging, "ci-logs", path)?;
            category.files.push(recorded);
        }
    }
    if category.files.is_empty() {
        category
            .missing
            .push("logs capturing CI or nightly runs (*.log, *.json)".to_string());
    }
    category.files.sort_by(|lhs, rhs| lhs.path.cmp(&rhs.path));
    category.files.dedup_by(|lhs, rhs| lhs.path == rhs.path);
    Ok(category)
}

fn copy_into_category(
    workspace: &Path,
    staging: &Path,
    category: &str,
    source: &Path,
) -> Result<EvidenceFileEntry> {
    let relative = source
        .strip_prefix(workspace)
        .unwrap_or(source)
        .to_path_buf();
    let dest = staging.join(category).join(&relative);
    if let Some(parent) = dest.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::copy(source, &dest)?;
    let path = format!("{category}/{}", relative_display_path(&relative));
    let sha256 = compute_sha256(&dest)?;
    Ok(EvidenceFileEntry { path, sha256 })
}

fn relative_display_path(path: &Path) -> String {
    path.to_string_lossy().replace('\\', "/")
}

fn compute_sha256(path: &Path) -> Result<String> {
    let mut file =
        File::open(path).with_context(|| format!("open file for checksum {}", path.display()))?;
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 8192];
    loop {
        let read = file
            .read(&mut buffer)
            .with_context(|| format!("read file for checksum {}", path.display()))?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(format!("{:x}", hasher.finalize()))
}

fn main() -> Result<()> {
    let mut argv: Vec<String> = env::args().collect();
    let _ = argv.remove(0);
    if argv.is_empty() {
        usage();
        return Ok(());
    }
    let command = argv.remove(0);
    match command.as_str() {
        "pruning-validation" => run_pruning_validation(),
        "test-unit" => run_unit_suites(),
        "test-firewood" => run_firewood_feature_matrix(),
        "test-integration" => run_integration_workflows(),
        "test-observability" => run_observability_suite(),
        "test-simnet" => run_simnet_smoke(),
        "test-cli" => cli_smoke::run_cli_smoke(&argv),
        "test-consensus-manipulation" => run_consensus_manipulation_tests(),
        "test-worm-export" => run_worm_export_smoke(),
        "worm-retention-check" => worm_retention_check(&argv),
        "test-all" => run_full_test_matrix(),
        "proof-metadata" => generate_proof_metadata(&argv),
        "proof-version-guard" => release::proof_version_guard(&argv),
        "plonky3-setup" => regenerate_plonky3_setup(&argv),
        "plonky3-verify" => verify_plonky3_setup(),
        "report-timetoke-slo" => report_timetoke_slo(&argv),
        "snapshot-verifier" => run_snapshot_verifier_smoke(),
        "snapshot-health" => run_snapshot_health(&argv),
        "admission-reconcile" => {
            let result = admission_reconciliation(&argv)?;
            if result.report.generated_at.is_empty() {
                Ok(())
            } else if result.report.drift_detected {
                bail!("admission reconciliation detected drift");
            } else {
                Ok(())
            }
        }
        "staging-soak" => run_staging_soak(&argv),
        "collect-phase3-evidence" => collect_phase3_evidence(&argv),
        "verify-report" => verify_snapshot_verifier_report(&argv),
        "help" => {
            usage();
            Ok(())
        }
        other => bail!("unknown xtask command: {other}"),
    }
}

fn regenerate_plonky3_setup(args: &[String]) -> Result<()> {
    let root = workspace_root();
    let mut generator: Option<String> = None;
    let mut generator_cwd: Option<PathBuf> = None;
    let mut artifact_dir: Option<PathBuf> = None;
    let mut circuits: Vec<String> = Vec::new();
    let mut toolchain_version = env::var("PLONKY3_TOOLCHAIN_VERSION").ok();
    let mut git_shas: Vec<String> = env_var_list("PLONKY3_GIT_SHAS");
    let mut signature = env::var("PLONKY3_SIGNATURE")
        .ok()
        .filter(|value| !value.trim().is_empty());
    let mut signature_file = env::var("PLONKY3_SIGNATURE_FILE")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .map(PathBuf::from);
    let mut signature_output: Option<PathBuf> =
        Some(root.join("config/plonky3/setup/manifest.json"));
    let mut pretty = true;

    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--generator" => {
                generator = Some(
                    iter.next()
                        .ok_or_else(|| anyhow!("--generator requires a value"))?
                        .to_string(),
                );
            }
            "--generator-cwd" => {
                let value = iter
                    .next()
                    .ok_or_else(|| anyhow!("--generator-cwd requires a value"))?;
                generator_cwd = Some(PathBuf::from(value));
            }
            "--artifact-dir" => {
                let value = iter
                    .next()
                    .ok_or_else(|| anyhow!("--artifact-dir requires a value"))?;
                artifact_dir = Some(PathBuf::from(value));
            }
            "--circuits" => {
                let value = iter
                    .next()
                    .ok_or_else(|| anyhow!("--circuits requires a value"))?;
                circuits.extend(
                    value
                        .split(|ch: char| ch == ',' || ch.is_whitespace())
                        .filter_map(|segment: &str| {
                            let trimmed = segment.trim();
                            if trimmed.is_empty() {
                                None
                            } else {
                                Some(trimmed.to_string())
                            }
                        }),
                );
            }
            "--toolchain-version" => {
                toolchain_version = Some(
                    iter.next()
                        .ok_or_else(|| anyhow!("--toolchain-version requires a value"))?
                        .to_string(),
                );
            }
            "--git-sha" => {
                let value = iter
                    .next()
                    .ok_or_else(|| anyhow!("--git-sha requires a value"))?;
                git_shas.push(value.to_string());
            }
            "--signature" => {
                signature = Some(
                    iter.next()
                        .ok_or_else(|| anyhow!("--signature requires a value"))?
                        .to_string(),
                );
                signature_file = None;
            }
            "--signature-file" => {
                let value = iter
                    .next()
                    .ok_or_else(|| anyhow!("--signature-file requires a value"))?;
                signature_file = Some(PathBuf::from(value));
                signature = None;
            }
            "--signature-output" => {
                let value = iter
                    .next()
                    .ok_or_else(|| anyhow!("--signature-output requires a value"))?;
                signature_output = Some(PathBuf::from(value));
            }
            "--no-signature-output" => {
                signature_output = None;
            }
            "--no-pretty" => {
                pretty = false;
            }
            other => {
                bail!("unknown argument '{other}' for plonky3-setup");
            }
        }
    }

    if signature.is_some() && signature_file.is_some() {
        bail!("--signature and --signature-file cannot be combined");
    }

    let mut fixture_dir: Option<TempDir> = None;
    if generator.is_none() && artifact_dir.is_none() {
        let (dir_handle, path) = materialise_fixture_artifacts(&circuits)?;
        artifact_dir = Some(path);
        fixture_dir = Some(dir_handle);
    }

    let mut command = Command::new("python3");
    command
        .current_dir(&root)
        .arg(root.join("scripts/generate_plonky3_artifacts.py"))
        .arg(root.join("config/plonky3/setup"));

    if !circuits.is_empty() {
        command.arg("--circuits");
        for circuit in &circuits {
            command.arg(circuit);
        }
    }

    if let Some(gen) = generator {
        command.arg("--generator").arg(gen);
    }

    if let Some(cwd) = generator_cwd {
        command.arg("--generator-cwd").arg(cwd);
    }

    if let Some(dir) = artifact_dir {
        command.arg("--artifact-dir").arg(dir);
    }

    if pretty {
        command.arg("--pretty");
    }

    if let Some(version) = toolchain_version.filter(|value| !value.trim().is_empty()) {
        command.arg("--toolchain-version").arg(version);
    }

    for entry in git_shas {
        if !entry.trim().is_empty() {
            command.arg("--git-sha").arg(entry);
        }
    }

    if let Some(sig) = signature.filter(|value| !value.trim().is_empty()) {
        command.arg("--signature").arg(sig);
    }

    if let Some(sig_file) = signature_file {
        command.arg("--signature-file").arg(sig_file);
    }

    if let Some(sig_out) = signature_output {
        command.arg("--signature-output").arg(sig_out);
    }

    run_command(command, "generate Plonky3 setup artifacts")?;
    drop(fixture_dir);
    Ok(())
}

fn verify_plonky3_setup() -> Result<()> {
    let root = workspace_root();
    let mut command = Command::new("python3");
    command
        .current_dir(&root)
        .arg("scripts/generate_plonky3_artifacts.py")
        .arg("config/plonky3/setup")
        .arg("--verify");
    if let Ok(circuits) = env::var("PLONKY3_VERIFY_CIRCUITS") {
        let values: Vec<String> = circuits
            .split(',')
            .map(|value| value.trim())
            .filter(|value| !value.is_empty())
            .map(|value| value.to_string())
            .collect();
        if !values.is_empty() {
            command.arg("--circuits");
            for value in values {
                command.arg(value);
            }
        }
    }
    if let Ok(pattern) = env::var("PLONKY3_VERIFY_PATTERN") {
        let trimmed = pattern.trim();
        if !trimmed.is_empty() {
            command.arg("--verifying-pattern").arg(trimmed);
        }
    }
    if let Ok(pattern) = env::var("PLONKY3_VERIFY_PROVING_PATTERN") {
        let trimmed = pattern.trim();
        if !trimmed.is_empty() {
            command.arg("--proving-pattern").arg(trimmed);
        }
    }
    run_command(command, "plonky3 setup verification")
}

fn env_var_list(name: &str) -> Vec<String> {
    env::var(name)
        .ok()
        .map(|value| {
            value
                .split(|ch: char| ch == ',' || ch == ';' || ch.is_whitespace())
                .filter(|segment| !segment.trim().is_empty())
                .map(|segment| segment.trim().to_string())
                .collect()
        })
        .unwrap_or_default()
}

fn materialise_fixture_artifacts(circuits: &[String]) -> Result<(TempDir, PathBuf)> {
    let root = workspace_root();
    let setup_dir = root.join("config/plonky3/setup");
    let selected: Option<HashSet<String>> = if circuits.is_empty() {
        None
    } else {
        Some(circuits.iter().cloned().collect())
    };

    let temp_dir = tempfile::tempdir().context("create temporary Plonky3 artifact directory")?;
    let mut generated: HashSet<String> = HashSet::new();

    for entry in
        fs::read_dir(&setup_dir).with_context(|| format!("read {}", setup_dir.display()))?
    {
        let entry = entry?;
        let path = entry.path();
        if path.extension().and_then(|ext| ext.to_str()) != Some("json") {
            continue;
        }
        let contents = fs::read_to_string(&path)
            .with_context(|| format!("read Plonky3 setup file {}", path.display()))?;
        let doc: Plonky3ArtifactDoc = serde_json::from_str(&contents)
            .with_context(|| format!("parse Plonky3 setup file {}", path.display()))?;
        if let Some(selection) = &selected {
            if !selection.contains(&doc.circuit) {
                continue;
            }
        }
        let verifying = load_plonky3_artifact(&setup_dir, &doc.verifying_key)?;
        let proving = load_plonky3_artifact(&setup_dir, &doc.proving_key)?;
        fs::write(
            temp_dir.path().join(format!("{}.vk", doc.circuit)),
            verifying,
        )
        .with_context(|| format!("write verifying key for {}", doc.circuit))?;
        fs::write(temp_dir.path().join(format!("{}.pk", doc.circuit)), proving)
            .with_context(|| format!("write proving key for {}", doc.circuit))?;
        generated.insert(doc.circuit);
    }

    if let Some(selection) = &selected {
        let missing: Vec<String> = selection.difference(&generated).cloned().collect();
        if !missing.is_empty() {
            bail!("no fixture data found for circuits: {}", missing.join(", "));
        }
    }

    let dir_path = temp_dir.path().to_path_buf();
    Ok((temp_dir, dir_path))
}

fn generate_proof_metadata(args: &[String]) -> Result<()> {
    let mut format = MetadataFormat::Json;
    let mut output: Option<PathBuf> = None;
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--format" => {
                let value = iter
                    .next()
                    .ok_or_else(|| anyhow!("--format requires a value"))?;
                format = match value.as_str() {
                    "json" => MetadataFormat::Json,
                    "markdown" | "md" => MetadataFormat::Markdown,
                    other => bail!("unsupported format '{other}'"),
                };
            }
            "--output" => {
                let value = iter
                    .next()
                    .ok_or_else(|| anyhow!("--output requires a value"))?;
                output = Some(PathBuf::from(value));
            }
            "--help" | "-h" => {
                proof_metadata_usage();
                return Ok(());
            }
            other => bail!("unknown argument '{other}' for proof-metadata"),
        }
    }

    let report = collect_proof_metadata()?;
    let payload = match format {
        MetadataFormat::Json => serde_json::to_string_pretty(&report)?,
        MetadataFormat::Markdown => render_markdown(&report),
    };

    if let Some(path) = output {
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent)
                    .with_context(|| format!("create output directory {}", parent.display()))?;
            }
        }
        fs::write(&path, payload.as_bytes())
            .with_context(|| format!("write proof metadata to {}", path.display()))?;
    } else {
        println!("{payload}");
    }

    Ok(())
}

fn collect_proof_metadata() -> Result<ProofMetadataReport> {
    let root = workspace_root();
    let plonky3_dir = root.join("config/plonky3/setup");
    let stwo_vk = root.join("prover/prover_stwo_backend/params/vk.json");

    Ok(ProofMetadataReport {
        plonky3: collect_plonky3_metadata(&plonky3_dir)?,
        stwo: collect_stwo_metadata(&stwo_vk)?,
        blueprint: collect_blueprint_metadata()?,
    })
}

fn collect_plonky3_metadata(dir: &Path) -> Result<Plonky3Metadata> {
    let mut circuits = Vec::new();
    for entry in fs::read_dir(dir).with_context(|| format!("read {dir:?}"))? {
        let entry = entry?;
        if entry.path().extension().and_then(|ext| ext.to_str()) != Some("json") {
            continue;
        }
        let contents = fs::read_to_string(entry.path())
            .with_context(|| format!("read Plonky3 setup file {}", entry.path().display()))?;
        let doc: Plonky3ArtifactDoc = serde_json::from_str(&contents)
            .with_context(|| format!("parse Plonky3 setup file {}", entry.path().display()))?;
        let verifying_key = load_plonky3_artifact(dir, &doc.verifying_key)?;
        let proving_key = load_plonky3_artifact(dir, &doc.proving_key)?;
        circuits.push(Plonky3CircuitMetadata {
            name: doc.circuit,
            verifying_key_hash: blake3_hash(&verifying_key).to_string(),
            verifying_key_bytes: verifying_key.len(),
            proving_key_hash: blake3_hash(&proving_key).to_string(),
            proving_key_bytes: proving_key.len(),
        });
    }
    circuits.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(Plonky3Metadata { circuits })
}

fn load_plonky3_artifact(dir: &Path, artifact: &Plonky3Artifact) -> Result<Vec<u8>> {
    let raw = if let Some(path) = artifact.value.strip_prefix('@') {
        let resolved = dir.join(path);
        fs::read(&resolved)
            .with_context(|| format!("read Plonky3 artifact {}", resolved.display()))?
    } else if artifact.value.starts_with("file:") {
        let stripped = artifact.value.trim_start_matches("file:");
        let resolved = dir.join(stripped);
        fs::read(&resolved)
            .with_context(|| format!("read Plonky3 artifact {}", resolved.display()))?
    } else {
        decode_blob(&artifact.value, artifact.encoding.as_deref())?
    };

    let bytes = match artifact
        .compression
        .as_deref()
        .map(|value| value.to_ascii_lowercase())
    {
        Some(ref compression) if compression == "gzip" || compression == "gz" => {
            let mut decoder = GzDecoder::new(raw.as_slice());
            let mut decompressed = Vec::new();
            decoder
                .read_to_end(&mut decompressed)
                .context("decompress Plonky3 artifact")?;
            decompressed
        }
        Some(other) => bail!("unsupported compression '{other}' in Plonky3 setup"),
        None => raw,
    };

    if let Some(expected) = artifact.byte_length {
        if bytes.len() != expected as usize {
            bail!(
                "Plonky3 artifact length mismatch: expected {expected} bytes, found {}",
                bytes.len()
            );
        }
    }

    Ok(bytes)
}

fn decode_blob(value: &str, encoding: Option<&str>) -> Result<Vec<u8>> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        bail!("Plonky3 artifact value cannot be empty");
    }

    match encoding.map(|enc| enc.to_ascii_lowercase()) {
        Some(enc) if enc != "base64" => {
            bail!("unsupported artifact encoding '{enc}' (expected base64)");
        }
        _ => BASE64
            .decode(trimmed)
            .map_err(|err| anyhow!("failed to decode base64 artifact: {err}")),
    }
}

fn collect_stwo_metadata(path: &Path) -> Result<StwoMetadata> {
    let contents = fs::read_to_string(path)
        .with_context(|| format!("read STWO verifying-key manifest {}", path.display()))?;
    let file: StwoVkFile = serde_json::from_str(&contents)
        .with_context(|| format!("parse STWO verifying-key manifest {}", path.display()))?;
    let mut circuits: Vec<StwoCircuitMetadata> = file
        .circuits
        .into_iter()
        .map(|(name, circuit)| StwoCircuitMetadata {
            name,
            degree: circuit.degree,
            commitment: circuit.commitment,
        })
        .collect();
    circuits.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(StwoMetadata {
        version: file.version,
        circuits,
    })
}

fn collect_blueprint_metadata() -> Result<BlueprintMetadata> {
    let mut stages = blueprint_stage_summaries();
    stages.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(BlueprintMetadata { stages })
}

fn blueprint_stage_summaries() -> Vec<BlueprintStageMetadata> {
    vec![
        BlueprintStageMetadata {
            name: "block_transition_aggregation".to_string(),
            kind: "aggregation".to_string(),
            proof_system: "stwo".to_string(),
            constraint_count: 3,
            description: "Aggregates all module digests, binds them to the block header and exposes the proof registry root.".to_string(),
        },
        BlueprintStageMetadata {
            name: "consensus_attestation".to_string(),
            kind: "base".to_string(),
            proof_system: "stwo".to_string(),
            constraint_count: 3,
            description: "Validates Malachite BFT votes and quorum signatures for the proposed block.".to_string(),
        },
        BlueprintStageMetadata {
            name: "global_state_transition".to_string(),
            kind: "base".to_string(),
            proof_system: "stwo".to_string(),
            constraint_count: 3,
            description: "Applies account-level balance, stake and nonce updates while linking to the global state commitment.".to_string(),
        },
        BlueprintStageMetadata {
            name: "recursive_wrapper".to_string(),
            kind: "recursion".to_string(),
            proof_system: "plonky2".to_string(),
            constraint_count: 3,
            description: "Wraps the STWO block proof and the previous recursive accumulator into a succinct proof chain.".to_string(),
        },
        BlueprintStageMetadata {
            name: "reputation_update".to_string(),
            kind: "base".to_string(),
            proof_system: "stwo".to_string(),
            constraint_count: 3,
            description: "Aggregates timetoke rewards, consensus participation and penalties into updated reputation tiers.".to_string(),
        },
        BlueprintStageMetadata {
            name: "timetoke_accrual".to_string(),
            kind: "base".to_string(),
            proof_system: "stwo".to_string(),
            constraint_count: 3,
            description: "Checks epoch-bounded uptime proofs and updates timetoke balances.".to_string(),
        },
        BlueprintStageMetadata {
            name: "utxo_transition".to_string(),
            kind: "base".to_string(),
            proof_system: "stwo".to_string(),
            constraint_count: 3,
            description: "Validates consumption and creation of UTXOs across the transaction batch.".to_string(),
        },
        BlueprintStageMetadata {
            name: "zsi_onboarding".to_string(),
            kind: "base".to_string(),
            proof_system: "stwo".to_string(),
            constraint_count: 3,
            description: "Proves correct inclusion of newly approved zero-state identities.".to_string(),
        },
    ]
}

fn render_markdown(report: &ProofMetadataReport) -> String {
    let mut out = String::new();
    out.push_str("# Proof metadata summary\n\n");

    out.push_str("## Plonky3 circuits\n\n");
    out.push_str("| Circuit | Verifying key (BLAKE3) | Bytes | Proving key (BLAKE3) | Bytes |\n");
    out.push_str("| --- | --- | ---: | --- | ---: |\n");
    for circuit in &report.plonky3.circuits {
        writeln!(
            out,
            "| {} | `{}` | {} | `{}` | {} |",
            circuit.name,
            circuit.verifying_key_hash,
            circuit.verifying_key_bytes,
            circuit.proving_key_hash,
            circuit.proving_key_bytes
        )
        .expect("write markdown");
    }
    out.push('\n');

    out.push_str("## STWO circuits\n\n");
    out.push_str("| Circuit | Degree | Commitment |\n");
    out.push_str("| --- | ---: | --- |\n");
    for circuit in &report.stwo.circuits {
        writeln!(
            out,
            "| {} | {} | `{}` |",
            circuit.name, circuit.degree, circuit.commitment
        )
        .expect("write markdown");
    }
    out.push('\n');

    out.push_str("## Blueprint stages\n\n");
    out.push_str("| Stage | Kind | Proof system | Constraints | Description |\n");
    out.push_str("| --- | --- | --- | ---: | --- |\n");
    for stage in &report.blueprint.stages {
        writeln!(
            out,
            "| {} | {} | {} | {} | {} |",
            stage.name,
            stage.kind,
            stage.proof_system,
            stage.constraint_count,
            stage.description.replace('|', "\\|")
        )
        .expect("write markdown");
    }

    out
}

#[derive(Debug, Clone, Copy)]
enum MetadataFormat {
    Json,
    Markdown,
}

#[derive(Debug, Serialize)]
struct ProofMetadataReport {
    plonky3: Plonky3Metadata,
    stwo: StwoMetadata,
    blueprint: BlueprintMetadata,
}

#[derive(Debug, Serialize)]
struct Plonky3Metadata {
    circuits: Vec<Plonky3CircuitMetadata>,
}

#[derive(Debug, Serialize)]
struct Plonky3CircuitMetadata {
    name: String,
    verifying_key_hash: String,
    verifying_key_bytes: usize,
    proving_key_hash: String,
    proving_key_bytes: usize,
}

#[derive(Debug, Deserialize)]
struct Plonky3ArtifactDoc {
    circuit: String,
    #[serde(default)]
    metadata: Option<JsonValue>,
    verifying_key: Plonky3Artifact,
    proving_key: Plonky3Artifact,
}

#[derive(Debug, Deserialize)]
struct Plonky3Artifact {
    value: String,
    #[serde(default)]
    encoding: Option<String>,
    #[serde(default)]
    compression: Option<String>,
    #[serde(default)]
    byte_length: Option<u64>,
}

#[derive(Debug, Serialize)]
struct StwoMetadata {
    version: u64,
    circuits: Vec<StwoCircuitMetadata>,
}

#[derive(Debug, Serialize)]
struct StwoCircuitMetadata {
    name: String,
    degree: u64,
    commitment: String,
}

#[derive(Debug, Deserialize)]
struct StwoVkFile {
    version: u64,
    circuits: BTreeMap<String, StwoVkCircuit>,
}

#[derive(Debug, Deserialize)]
struct StwoVkCircuit {
    degree: u64,
    commitment: String,
}

#[derive(Debug, Serialize)]
struct BlueprintMetadata {
    stages: Vec<BlueprintStageMetadata>,
}

#[derive(Debug, Serialize)]
struct BlueprintStageMetadata {
    name: String,
    kind: String,
    proof_system: String,
    constraint_count: usize,
    description: String,
}
