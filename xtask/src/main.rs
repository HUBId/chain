use std::collections::{BTreeMap, HashSet};
use std::env;
use std::fmt::Write as FmtWrite;
use std::fs;
use std::io::{BufRead, BufReader, Read};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration as StdDuration;

use anyhow::{anyhow, bail, Context, Result};
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use blake3::hash as blake3_hash;
use flate2::read::GzDecoder;
use reqwest::blocking::Client as HttpClient;
use serde::Deserialize;
use serde::Serialize;
use serde_json::Value as JsonValue;
use tempfile::TempDir;
use time::format_description::well_known::Rfc3339;
use time::{Duration as TimeDuration, OffsetDateTime};

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("xtask lives in workspace root")
        .to_path_buf()
}

fn apply_feature_flags(command: &mut Command) {
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
    let mut command = Command::new("cargo");
    command
        .current_dir(workspace_root())
        .arg("test")
        .arg("-p")
        .arg("rpp-chain")
        .arg("--locked")
        .arg("--test")
        .arg("unit");
    apply_feature_flags(&mut command);
    run_command(command, "unit test suite")
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
    apply_feature_flags(&mut command);
    run_command(command, "integration workflows")?;

    let mut restart = Command::new("cargo");
    restart
        .current_dir(&root)
        .arg("test")
        .arg("-p")
        .arg("rpp-chain")
        .arg("--locked")
        .arg("--test")
        .arg("snapshot_checksum_restart");
    apply_feature_flags(&mut restart);
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
    let scenarios = [
        "tools/simnet/scenarios/ci_block_pipeline.ron",
        "tools/simnet/scenarios/ci_state_sync_guard.ron",
        "tools/simnet/scenarios/consensus_quorum_stress.ron",
        "tools/simnet/scenarios/snapshot_partition.ron",
    ];
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
}

#[derive(Default, Deserialize)]
struct ValidatorNetworkSnippet {
    #[serde(default)]
    rpc: Option<ValidatorRpcSnippet>,
}

#[derive(Default, Deserialize)]
struct ValidatorRpcSnippet {
    #[serde(default)]
    listen: Option<String>,
    #[serde(default)]
    auth_token: Option<String>,
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

#[derive(Serialize)]
struct SnapshotHealthReport {
    generated_at: String,
    rpc_base_url: String,
    manifest_sources: Vec<String>,
    sessions: Vec<SnapshotSessionReport>,
}

#[derive(Serialize)]
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
        "xtask commands:\n  pruning-validation    Run pruning receipt conformance checks\n  test-unit            Execute lightweight unit test suites\n  test-integration     Execute integration workflows\n  test-observability   Run Prometheus-backed observability tests\n  test-simnet          Run the CI simnet scenarios\n  test-consensus-manipulation  Exercise consensus tamper detection tests\n  test-all             Run unit, integration, observability, and simnet scenarios\n  proof-metadata       Export circuit/proof metadata as JSON or markdown\n  plonky3-setup        Regenerate Plonky3 setup JSON descriptors\n  plonky3-verify       Validate setup artifacts against embedded hash manifests\n  report-timetoke-slo  Summarise Timetoke replay SLOs from Prometheus or log archives\n  snapshot-health      Audit snapshot streaming progress against manifest totals",
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

fn report_timetoke_slo(args: &[String]) -> Result<()> {
    let mut prometheus_url: Option<String> = None;
    let mut bearer_token: Option<String> = None;
    let mut metrics_log: Option<PathBuf> = None;
    let mut output: Option<PathBuf> = None;

    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--prometheus-url" => {
                let value = iter
                    .next()
                    .ok_or_else(|| anyhow!("--prometheus-url requires a value"))?;
                prometheus_url = normalise_string(Some(value.clone()));
            }
            "--bearer-token" => {
                let value = iter
                    .next()
                    .ok_or_else(|| anyhow!("--bearer-token requires a value"))?;
                bearer_token = normalise_string(Some(value.clone()));
            }
            "--metrics-log" => {
                let value = iter
                    .next()
                    .ok_or_else(|| anyhow!("--metrics-log requires a value"))?;
                if let Some(path) = normalise_string(Some(value.clone())) {
                    metrics_log = Some(PathBuf::from(path));
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
                return Ok(());
            }
            other => bail!("unknown argument '{other}' for report-timetoke-slo"),
        }
    }

    if prometheus_url.is_none() {
        prometheus_url = env::var("TIMETOKE_PROMETHEUS_URL")
            .ok()
            .and_then(|value| normalise_string(Some(value)))
            .or_else(|| {
                env::var("PROMETHEUS_URL")
                    .ok()
                    .and_then(|v| normalise_string(Some(v)))
            });
    }
    if bearer_token.is_none() {
        bearer_token = env::var("TIMETOKE_PROMETHEUS_BEARER")
            .ok()
            .and_then(|value| normalise_string(Some(value)))
            .or_else(|| {
                env::var("PROMETHEUS_BEARER_TOKEN")
                    .ok()
                    .and_then(|v| normalise_string(Some(v)))
            });
    }
    if metrics_log.is_none() {
        metrics_log = env::var("TIMETOKE_METRICS_LOG")
            .ok()
            .and_then(|value| normalise_string(Some(value)))
            .map(PathBuf::from);
    }

    let summary = if let Some(url) = prometheus_url {
        fetch_prometheus_summary(&url, bearer_token.as_deref())?
    } else {
        let path = metrics_log.ok_or_else(|| {
            anyhow!("report-timetoke-slo requires either --prometheus-url or --metrics-log")
        })?;
        parse_log_summary(&path)?
    };

    let report = render_timetoke_report(&summary);
    println!("{report}");

    if let Some(path) = output {
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
        "test-integration" => run_integration_workflows(),
        "test-observability" => run_observability_suite(),
        "test-simnet" => run_simnet_smoke(),
        "test-consensus-manipulation" => run_consensus_manipulation_tests(),
        "test-all" => run_full_test_matrix(),
        "proof-metadata" => generate_proof_metadata(&argv),
        "plonky3-setup" => regenerate_plonky3_setup(&argv),
        "plonky3-verify" => verify_plonky3_setup(),
        "report-timetoke-slo" => report_timetoke_slo(&argv),
        "snapshot-health" => run_snapshot_health(&argv),
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
