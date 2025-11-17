use std::collections::HashSet;
use std::fmt;
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use crate::{BootstrapError, RuntimeMode, RuntimeOptions};
use anyhow::{anyhow, Context, Result};
use clap::{Args, Parser, Subcommand};
use hex;
use reqwest::Client;
use rpp_chain::crypto::{
    generate_vrf_keypair, load_or_generate_keypair, vrf_public_key_to_hex, vrf_secret_key_to_hex,
    DynVrfKeyStore, VrfKeyIdentifier, VrfKeyStore, VrfKeypair,
};
use rpp_chain::runtime::config::{
    NodeConfig, SecretsBackendConfig, SecretsConfig, WalletConfig, WalletConfigExt,
};
use rpp_chain::runtime::RuntimeMetrics;
use rpp_chain::storage::Storage;
use rpp_chain::wallet::Wallet;
use rpp_p2p::{
    AdmissionPolicyLogEntry, PolicySignature, PolicySignatureVerifier, PolicyTrustStore, TierLevel,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use snapshot_verify::{
    run_verification as run_snapshot_verification, write_report as write_snapshot_report,
    DataSource as SnapshotVerifySource, Execution as SnapshotVerifyExecution,
    ExitCode as SnapshotVerifyExitCode, VerificationReport as SnapshotVerificationReport,
    VerifyArgs as SnapshotVerifyArgs,
};
use tokio::task;

const DEFAULT_VALIDATOR_CONFIG: &str = "config/validator.toml";
const DEFAULT_WALLET_CONFIG: &str = "config/wallet.toml";

pub type CliResult<T = ()> = std::result::Result<T, CliError>;

#[derive(Debug)]
pub enum CliError {
    Bootstrap(BootstrapError),
    Other(anyhow::Error),
}

impl CliError {
    pub fn exit_code(&self) -> i32 {
        match self {
            CliError::Bootstrap(err) => err.exit_code(),
            CliError::Other(_) => 1,
        }
    }
}

impl fmt::Display for CliError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CliError::Bootstrap(err) => write!(f, "{err}"),
            CliError::Other(err) => write!(f, "{err}"),
        }
    }
}

impl std::error::Error for CliError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            CliError::Bootstrap(err) => Some(err),
            CliError::Other(err) => Some(err.as_ref()),
        }
    }
}

impl From<BootstrapError> for CliError {
    fn from(err: BootstrapError) -> Self {
        CliError::Bootstrap(err)
    }
}

impl From<anyhow::Error> for CliError {
    fn from(err: anyhow::Error) -> Self {
        CliError::Other(err)
    }
}

#[derive(Parser)]
#[command(
    author,
    version,
    propagate_version = true,
    about = "Run an rpp node",
    long_about = None,
    after_help = "Exit codes:\n  0 - runtime exited cleanly\n  2 - configuration validation failed\n  3 - runtime startup failed\n  4 - unexpected runtime error"
)]
struct RootCli {
    #[command(subcommand)]
    command: RootCommand,
}

#[derive(Subcommand)]
enum RootCommand {
    /// Run the node runtime
    Node(RuntimeCommand),
    /// Run the wallet runtime
    Wallet(RuntimeCommand),
    /// Run the hybrid runtime (node + wallet)
    Hybrid(RuntimeCommand),
    /// Validator runtime and tooling
    Validator(ValidatorArgs),
}

#[derive(Args, Clone)]
struct RuntimeCommand {
    #[command(flatten)]
    options: RuntimeOptions,
}

#[derive(Args)]
struct ValidatorArgs {
    #[command(flatten)]
    runtime: RuntimeOptions,

    #[command(subcommand)]
    command: Option<ValidatorCommand>,
}

#[derive(Subcommand)]
enum ValidatorCommand {
    /// Manage VRF key material backed by the configured secrets backend
    Vrf(VrfCommand),
    /// Fetch validator telemetry snapshots from the RPC service
    Telemetry(TelemetryCommand),
    /// Manage uptime proofs via the validator RPC
    Uptime(UptimeCommand),
    /// Run validator setup checks and rotate VRF material
    Setup(ValidatorSetupCommand),
    /// Control snapshot streaming sessions through the RPC service
    Snapshot(SnapshotCommand),
    /// Manage admission policy backups through the RPC service
    Admission(AdmissionCommand),
}

#[derive(Subcommand)]
enum VrfCommand {
    /// Rotate the VRF keypair and persist it through the configured keystore
    Rotate(VrfRotateCommand),
    /// Inspect the currently stored VRF keypair
    Inspect(VrfInspectCommand),
    /// Export the VRF keypair in JSON format (includes the secret key)
    Export(VrfExportCommand),
}

#[derive(Args, Clone)]
struct ValidatorConfigArgs {
    /// Path to the validator node configuration
    #[arg(long, value_name = "PATH", default_value = DEFAULT_VALIDATOR_CONFIG)]
    config: PathBuf,
}

#[derive(Args, Clone)]
struct VrfRotateCommand {
    #[command(flatten)]
    config: ValidatorConfigArgs,
}

#[derive(Args, Clone)]
struct VrfInspectCommand {
    #[command(flatten)]
    config: ValidatorConfigArgs,
}

#[derive(Args, Clone)]
struct VrfExportCommand {
    #[command(flatten)]
    config: ValidatorConfigArgs,

    /// Optional path to write the exported VRF keypair JSON payload
    #[arg(long, value_name = "PATH")]
    output: Option<PathBuf>,
}

#[derive(Args, Clone)]
struct TelemetryCommand {
    /// Base URL of the validator RPC endpoint
    #[arg(long, value_name = "URL", default_value = "http://127.0.0.1:7070")]
    rpc_url: String,

    /// Optional bearer token for secured RPC deployments
    #[arg(long)]
    auth_token: Option<String>,

    /// Pretty-print the JSON response
    #[arg(long, default_value_t = false)]
    pretty: bool,
}

#[derive(Subcommand)]
enum UptimeCommand {
    /// Generate and submit an uptime proof through the validator RPC
    Submit(UptimeSubmitCommand),
    /// Inspect pending uptime proof submissions queued in the node
    Status(UptimeStatusCommand),
}

#[derive(Subcommand)]
enum SnapshotCommand {
    /// Start a new snapshot streaming session
    Start(SnapshotStartCommand),
    /// Inspect the current status of a snapshot streaming session
    Status(SnapshotStatusCommand),
    /// Resume a previously started snapshot streaming session
    Resume(SnapshotResumeCommand),
    /// Cancel an in-flight snapshot streaming session
    Cancel(SnapshotCancelCommand),
    /// Verify snapshot manifests and chunks using the configured signing key
    Verify(SnapshotVerifyCommand),
    /// Inspect Timetoke replay telemetry exported by the validator RPC
    Replay(SnapshotReplayCommand),
}

#[derive(Args, Clone)]
struct SnapshotConnectionArgs {
    #[command(flatten)]
    config: ValidatorConfigArgs,

    /// Override the RPC base URL derived from the validator configuration
    #[arg(long, value_name = "URL")]
    rpc_url: Option<String>,

    /// Override the RPC bearer token; defaults to the configured token when omitted
    #[arg(long, value_name = "TOKEN")]
    auth_token: Option<String>,
}

#[derive(Subcommand)]
enum AdmissionCommand {
    /// Inspect admission policy backups exposed by the validator RPC
    Backups(AdmissionBackupsCommand),
    /// Restore admission policies from a downloaded backup archive
    Restore(AdmissionRestoreCommand),
    /// Verify admission policy snapshot and audit log signatures via the RPC service
    Verify(AdmissionVerifyCommand),
}

#[derive(Subcommand)]
enum SnapshotReplayCommand {
    /// Summarise Timetoke replay telemetry and check SLO thresholds
    Status(SnapshotReplayStatusCommand),
}

#[derive(Args, Clone)]
struct SnapshotReplayStatusCommand {
    #[command(flatten)]
    connection: SnapshotConnectionArgs,
}

#[derive(Subcommand)]
enum AdmissionBackupsCommand {
    /// List available admission policy backup archives
    List(AdmissionBackupsListCommand),
    /// Download an admission policy backup archive
    Download(AdmissionBackupsDownloadCommand),
}

#[derive(Args, Clone)]
struct AdmissionConnectionArgs {
    #[command(flatten)]
    config: ValidatorConfigArgs,

    /// Override the RPC base URL derived from the validator configuration
    #[arg(long, value_name = "URL")]
    rpc_url: Option<String>,

    /// Override the RPC bearer token; defaults to the configured token when omitted
    #[arg(long, value_name = "TOKEN")]
    auth_token: Option<String>,
}

#[derive(Args, Clone)]
struct AdmissionBackupsListCommand {
    #[command(flatten)]
    connection: AdmissionConnectionArgs,

    /// Emit the raw JSON payload instead of a formatted table
    #[arg(long, default_value_t = false)]
    json: bool,
}

#[derive(Args, Clone)]
struct AdmissionBackupsDownloadCommand {
    #[command(flatten)]
    connection: AdmissionConnectionArgs,

    /// Name of the backup archive to download
    #[arg(long, value_name = "NAME")]
    backup: String,

    /// Optional path to write the downloaded backup (stdout when omitted)
    #[arg(long, value_name = "PATH")]
    output: Option<PathBuf>,
}

#[derive(Args, Clone)]
struct AdmissionRestoreCommand {
    #[command(flatten)]
    connection: AdmissionConnectionArgs,

    /// Name of the backup archive to restore
    #[arg(long, value_name = "NAME")]
    backup: String,

    /// Actor attributed in the admission audit log
    #[arg(long, value_name = "NAME")]
    actor: String,

    /// Optional reason recorded in the admission audit log
    #[arg(long, value_name = "TEXT")]
    reason: Option<String>,

    /// Optional approval entries in ROLE:APPROVER format
    #[arg(long = "approval", value_name = "ROLE:APPROVER")]
    approvals: Vec<String>,
}

#[derive(Args, Clone)]
struct AdmissionVerifyCommand {
    #[command(flatten)]
    connection: AdmissionConnectionArgs,

    /// Number of audit log entries to verify (0 fetches the full log)
    #[arg(long, value_name = "COUNT", default_value_t = 50)]
    audit_limit: usize,
}

#[derive(Args, Clone)]
struct SnapshotStartCommand {
    #[command(flatten)]
    connection: SnapshotConnectionArgs,

    /// Peer ID of the snapshot provider
    #[arg(long, value_name = "PEER")]
    peer: String,

    /// Chunk size requested from the provider
    #[arg(long, value_name = "BYTES", default_value_t = 32_768)]
    chunk_size: u32,
}

#[derive(Args, Clone)]
struct SnapshotStatusCommand {
    #[command(flatten)]
    connection: SnapshotConnectionArgs,

    /// Snapshot session identifier
    #[arg(long, value_name = "ID")]
    session: u64,
}

#[derive(Args, Clone)]
struct SnapshotResumeCommand {
    #[command(flatten)]
    connection: SnapshotConnectionArgs,

    /// Snapshot session identifier to resume
    #[arg(long, value_name = "ID")]
    session: u64,

    /// Peer ID of the snapshot provider
    #[arg(long, value_name = "PEER")]
    peer: String,

    /// Plan identifier advertised by the snapshot provider
    #[arg(long, value_name = "PLAN")]
    plan_id: String,

    /// Chunk size requested from the provider
    #[arg(long, value_name = "BYTES", default_value_t = 32_768)]
    chunk_size: u32,
}

#[derive(Args, Clone)]
struct SnapshotCancelCommand {
    #[command(flatten)]
    connection: SnapshotConnectionArgs,

    /// Snapshot session identifier to cancel
    #[arg(long, value_name = "ID")]
    session: u64,
}

#[derive(Args, Clone)]
struct SnapshotVerifyCommand {
    #[command(flatten)]
    config: ValidatorConfigArgs,

    /// Override the manifest path derived from the validator configuration
    #[arg(long, value_name = "PATH")]
    manifest: Option<PathBuf>,

    /// Override the signature path; defaults to <manifest>.sig when omitted
    #[arg(long, value_name = "PATH")]
    signature: Option<PathBuf>,

    /// Override the chunk directory derived from the validator configuration
    #[arg(long = "chunk-root", value_name = "PATH")]
    chunk_root: Option<PathBuf>,

    /// Optional path to write the verification report to instead of stdout
    #[arg(long, value_name = "PATH")]
    output: Option<PathBuf>,

    /// Use a specific public key file instead of the configured signing key
    #[arg(long = "public-key", value_name = "PATH")]
    public_key: Option<PathBuf>,
}

#[derive(Args, Clone)]
struct UptimeSubmitCommand {
    #[arg(long, value_name = "PATH", default_value = DEFAULT_WALLET_CONFIG)]
    wallet_config: PathBuf,

    #[arg(long, value_name = "URL", default_value = "http://127.0.0.1:7070")]
    rpc_url: String,

    #[arg(long)]
    auth_token: Option<String>,
}

#[derive(Args, Clone)]
struct UptimeStatusCommand {
    #[arg(long, value_name = "URL", default_value = "http://127.0.0.1:7070")]
    rpc_url: String,

    #[arg(long)]
    auth_token: Option<String>,

    #[arg(long, default_value_t = false)]
    json: bool,

    #[arg(long, value_name = "COUNT", default_value_t = 5)]
    limit: usize,
}

#[derive(Args, Clone)]
struct ValidatorSetupCommand {
    #[command(flatten)]
    config: ValidatorConfigArgs,

    /// Timeout (seconds) when probing telemetry HTTP endpoints
    #[arg(long, value_name = "SECONDS", default_value_t = 5)]
    telemetry_timeout: u64,

    /// Skip contacting telemetry endpoints while still validating configuration
    #[arg(long, default_value_t = false)]
    skip_telemetry_probe: bool,
}

#[derive(Deserialize)]
struct ValidatorProofQueueStatus {
    uptime_proofs: Vec<PendingUptimeSummary>,
    totals: ValidatorProofTotals,
}

#[derive(Deserialize)]
struct PendingUptimeSummary {
    identity: String,
    window_start: u64,
    window_end: u64,
    credited_hours: u64,
}

#[derive(Deserialize)]
struct ValidatorProofTotals {
    transactions: usize,
    identities: usize,
    votes: usize,
    uptime_proofs: usize,
}

#[derive(Deserialize)]
struct SubmitUptimeResponse {
    credited_hours: u64,
}

pub async fn run_cli() -> ExitCode {
    match run_cli_inner().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("{err}");
            ExitCode::from(err.exit_code() as u8)
        }
    }
}

async fn run_cli_inner() -> CliResult<()> {
    let RootCli { command } = RootCli::parse();
    match command {
        RootCommand::Node(RuntimeCommand { options }) => {
            run_runtime(RuntimeMode::Node, options).await
        }
        RootCommand::Wallet(RuntimeCommand { options }) => {
            run_runtime(RuntimeMode::Wallet, options).await
        }
        RootCommand::Hybrid(RuntimeCommand { options }) => {
            run_runtime(RuntimeMode::Hybrid, options).await
        }
        RootCommand::Validator(args) => match args.command {
            Some(ValidatorCommand::Vrf(command)) => {
                handle_vrf_command(command).map_err(CliError::from)
            }
            Some(ValidatorCommand::Telemetry(command)) => {
                fetch_telemetry(command).await.map_err(CliError::from)
            }
            Some(ValidatorCommand::Uptime(command)) => {
                handle_uptime_command(command).await.map_err(CliError::from)
            }
            Some(ValidatorCommand::Setup(command)) => run_validator_setup(command).await,
            Some(ValidatorCommand::Snapshot(command)) => handle_snapshot_command(command)
                .await
                .map_err(CliError::from),
            Some(ValidatorCommand::Admission(command)) => handle_admission_command(command)
                .await
                .map_err(CliError::from),
            None => run_runtime(RuntimeMode::Validator, args.runtime).await,
        },
    }
}

async fn run_runtime(mode: RuntimeMode, options: RuntimeOptions) -> CliResult<()> {
    crate::run(mode, options).await.map_err(CliError::from)
}

fn handle_vrf_command(command: VrfCommand) -> Result<()> {
    match command {
        VrfCommand::Rotate(args) => rotate_vrf_key(&args.config),
        VrfCommand::Inspect(args) => inspect_vrf_key(&args.config),
        VrfCommand::Export(args) => export_vrf_key(&args.config, args.output.as_ref()),
    }
}

struct VrfRotationOutcome {
    secrets: SecretsConfig,
    identifier: VrfKeyIdentifier,
    keypair: VrfKeypair,
}

fn rotate_vrf_key(args: &ValidatorConfigArgs) -> Result<()> {
    let rotation = rotate_vrf_key_material(&args.config)?;

    println!(
        "VRF key rotated; backend={} location={} public_key={}",
        backend_name(&rotation.secrets),
        format_identifier(&rotation.identifier),
        vrf_public_key_to_hex(&rotation.keypair.public)
    );
    Ok(())
}

fn rotate_vrf_key_material(config_path: &Path) -> Result<VrfRotationOutcome> {
    let (secrets, identifier, store) = prepare_vrf_store(config_path)?;
    let keypair = generate_vrf_keypair().map_err(|err| anyhow!(err))?;
    store
        .store(&identifier, &keypair)
        .map_err(|err| anyhow!(err))?;

    Ok(VrfRotationOutcome {
        secrets,
        identifier,
        keypair,
    })
}

fn inspect_vrf_key(args: &ValidatorConfigArgs) -> Result<()> {
    let (secrets, identifier, store) = prepare_vrf_store(&args.config)?;
    match store.load(&identifier).map_err(|err| anyhow!(err))? {
        Some(keypair) => {
            println!(
                "VRF key available; backend={} location={} public_key={} secret_key={}",
                backend_name(&secrets),
                format_identifier(&identifier),
                vrf_public_key_to_hex(&keypair.public),
                vrf_secret_key_to_hex(&keypair.secret)
            );
        }
        None => {
            println!(
                "No VRF key material found at backend={} location={}",
                backend_name(&secrets),
                format_identifier(&identifier)
            );
        }
    }
    Ok(())
}

fn export_vrf_key(args: &ValidatorConfigArgs, output: Option<&PathBuf>) -> Result<()> {
    let (secrets, identifier, store) = prepare_vrf_store(&args.config)?;
    let Some(keypair) = store.load(&identifier).map_err(|err| anyhow!(err))? else {
        println!(
            "No VRF key material found at backend={} location={}",
            backend_name(&secrets),
            format_identifier(&identifier)
        );
        return Ok(());
    };

    let payload = serde_json::json!({
        "backend": backend_name(&secrets),
        "location": format_identifier(&identifier),
        "public_key": vrf_public_key_to_hex(&keypair.public),
        "secret_key": vrf_secret_key_to_hex(&keypair.secret),
    });

    if let Some(path) = output {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).with_context(|| {
                format!("failed to create export directory {}", parent.display())
            })?;
        }
        let encoded = serde_json::to_string_pretty(&payload).context("encode VRF payload")?;
        fs::write(path, encoded)
            .with_context(|| format!("failed to export VRF key to {}", path.display()))?;
        println!("VRF key exported to {}", path.display());
    } else {
        println!("{}", serde_json::to_string_pretty(&payload)?);
    }

    Ok(())
}

async fn fetch_telemetry(command: TelemetryCommand) -> Result<()> {
    let client = Client::builder()
        .build()
        .context("failed to build telemetry HTTP client")?;
    let base = command.rpc_url.trim_end_matches('/');
    let mut request = client.get(format!("{}/validator/telemetry", base));
    if let Some(token) = command.auth_token.as_ref() {
        request = request.bearer_auth(token);
    }

    let response = request
        .send()
        .await
        .context("failed to query validator telemetry")?;
    let status = response.status();
    let body = response
        .text()
        .await
        .context("failed to decode validator telemetry response")?;
    if !status.is_success() {
        anyhow::bail!("RPC returned {}: {}", status, body.trim());
    }

    if command.pretty {
        let value: Value = serde_json::from_str(&body).context("invalid telemetry payload")?;
        println!("{}", serde_json::to_string_pretty(&value)?);
    } else {
        println!("{}", body);
    }
    Ok(())
}

async fn handle_uptime_command(command: UptimeCommand) -> Result<()> {
    match command {
        UptimeCommand::Submit(args) => submit_uptime_proof(args).await,
        UptimeCommand::Status(args) => fetch_uptime_status(args).await,
    }
}

async fn handle_snapshot_command(command: SnapshotCommand) -> Result<()> {
    match command {
        SnapshotCommand::Start(args) => start_snapshot_session(args).await,
        SnapshotCommand::Status(args) => fetch_snapshot_status(args).await,
        SnapshotCommand::Resume(args) => resume_snapshot_session(args).await,
        SnapshotCommand::Cancel(args) => cancel_snapshot_session(args).await,
        SnapshotCommand::Verify(args) => verify_snapshot_manifest(args).await,
        SnapshotCommand::Replay(args) => match args {
            SnapshotReplayCommand::Status(status) => snapshot_replay_status(status).await,
        },
    }
}

async fn handle_admission_command(command: AdmissionCommand) -> Result<()> {
    match command {
        AdmissionCommand::Backups(command) => handle_admission_backups(command).await,
        AdmissionCommand::Restore(command) => restore_admission_backup_cli(command).await,
        AdmissionCommand::Verify(command) => verify_admission_signatures(command).await,
    }
}

async fn handle_admission_backups(command: AdmissionBackupsCommand) -> Result<()> {
    match command {
        AdmissionBackupsCommand::List(args) => list_admission_backups(args).await,
        AdmissionBackupsCommand::Download(args) => download_admission_backup(args).await,
    }
}

struct AdmissionRpcClient {
    client: Client,
    base_url: String,
    auth_token: Option<String>,
}

struct SnapshotRpcClient {
    client: Client,
    base_url: String,
    auth_token: Option<String>,
}

impl AdmissionRpcClient {
    fn new(args: &AdmissionConnectionArgs) -> Result<Self> {
        let config = load_validator_config(&args.config.config)?;
        let base_url = args
            .rpc_url
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(|value| value.trim_end_matches('/').to_string())
            .unwrap_or_else(|| default_rpc_base_url(&config));

        let cli_token = args
            .auth_token
            .as_deref()
            .and_then(normalize_cli_bearer_token);
        let config_token = config
            .network
            .rpc
            .auth_token
            .as_deref()
            .and_then(normalize_cli_bearer_token);
        let auth_token = cli_token.or(config_token);

        let client = Client::builder()
            .build()
            .context("failed to build admission RPC client")?;

        Ok(Self {
            client,
            base_url,
            auth_token,
        })
    }

    fn endpoint(&self, path: &str) -> String {
        format!("{}/{}", self.base_url, path.trim_start_matches('/'))
    }

    fn with_auth(&self, request: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        if let Some(token) = self.auth_token.as_ref() {
            request.bearer_auth(token)
        } else {
            request
        }
    }
}

#[derive(Deserialize)]
struct AdmissionBackupsRpcResponse {
    backups: Vec<AdmissionBackupRpcEntry>,
}

#[derive(Deserialize)]
struct AdmissionBackupRpcEntry {
    name: String,
    timestamp_ms: u64,
    size: u64,
}

#[derive(Serialize, Deserialize, Clone)]
struct AdmissionPolicyEntry {
    peer_id: String,
    tier: TierLevel,
}

#[derive(Deserialize)]
struct AdmissionPoliciesRpcResponse {
    allowlist: Vec<AdmissionPolicyEntry>,
    blocklist: Vec<String>,
    #[serde(default)]
    signature: Option<PolicySignature>,
}

#[derive(Serialize)]
struct AdmissionSnapshotCanonical {
    allowlist: Vec<AdmissionPolicyEntry>,
    blocklist: Vec<String>,
}

#[derive(Deserialize)]
struct AdmissionAuditRpcResponse {
    offset: usize,
    limit: usize,
    total: usize,
    entries: Vec<AdmissionPolicyLogEntry>,
}

#[derive(Serialize)]
struct AdmissionApprovalPayload {
    role: String,
    approver: String,
}

#[derive(Serialize)]
struct RestoreAdmissionBackupRpcRequest {
    backup: String,
    actor: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    reason: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    approvals: Vec<AdmissionApprovalPayload>,
}

#[derive(Debug, Deserialize)]
struct SnapshotStreamStatusResponse {
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

#[derive(Debug, Deserialize)]
struct TimetokeReplayStatusResponse {
    success_total: u64,
    failure_total: u64,
    success_rate: Option<f64>,
    latency_p50_ms: Option<u64>,
    latency_p95_ms: Option<u64>,
    latency_p99_ms: Option<u64>,
    last_attempt_epoch: Option<u64>,
    last_success_epoch: Option<u64>,
    seconds_since_attempt: Option<u64>,
    seconds_since_success: Option<u64>,
    stall_warning: bool,
    stall_critical: bool,
    failure_breakdown: Vec<TimetokeReplayFailureBreakdown>,
}

#[derive(Debug, Deserialize)]
struct TimetokeReplayFailureBreakdown {
    reason: String,
    total: u64,
}

#[derive(Serialize)]
struct StartSnapshotStreamRequest<'a> {
    peer: &'a str,
    chunk_size: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    resume: Option<ResumeMarker<'a>>,
}

#[derive(Serialize)]
struct ResumeMarker<'a> {
    session: u64,
    plan_id: &'a str,
}

impl SnapshotRpcClient {
    fn new(args: &SnapshotConnectionArgs) -> Result<Self> {
        let config = load_validator_config(&args.config.config)?;
        let base_url = args
            .rpc_url
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(|value| value.trim_end_matches('/').to_string())
            .unwrap_or_else(|| default_rpc_base_url(&config));

        let cli_token = args
            .auth_token
            .as_deref()
            .and_then(normalize_cli_bearer_token);
        let config_token = config
            .network
            .rpc
            .auth_token
            .as_deref()
            .and_then(normalize_cli_bearer_token);
        let auth_token = cli_token.or(config_token);

        let client = Client::builder()
            .build()
            .context("failed to build snapshot RPC client")?;

        Ok(Self {
            client,
            base_url,
            auth_token,
        })
    }

    fn endpoint(&self, path: &str) -> String {
        format!("{}/{}", self.base_url, path.trim_start_matches('/'))
    }

    fn with_auth(&self, request: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        if let Some(token) = self.auth_token.as_ref() {
            request.bearer_auth(token)
        } else {
            request
        }
    }
}

async fn start_snapshot_session(args: SnapshotStartCommand) -> Result<()> {
    let client = SnapshotRpcClient::new(&args.connection)?;
    let request = StartSnapshotStreamRequest {
        peer: &args.peer,
        chunk_size: args.chunk_size,
        resume: None,
    };
    let mut builder = client
        .client
        .post(client.endpoint("/p2p/snapshots"))
        .json(&request);
    builder = client.with_auth(builder);

    let response = builder
        .send()
        .await
        .context("failed to start snapshot session")?;
    let status = response.status();
    let body = response
        .text()
        .await
        .context("failed to decode snapshot start response")?;
    if !status.is_success() {
        anyhow::bail!("RPC returned {}: {}", status, body.trim());
    }

    let payload: SnapshotStreamStatusResponse =
        serde_json::from_str(&body).context("invalid snapshot status payload")?;
    print_snapshot_status("snapshot session started", &payload);
    Ok(())
}

async fn fetch_snapshot_status(args: SnapshotStatusCommand) -> Result<()> {
    let client = SnapshotRpcClient::new(&args.connection)?;
    let mut builder = client
        .client
        .get(client.endpoint(&format!("/p2p/snapshots/{}", args.session)));
    builder = client.with_auth(builder);

    let response = builder
        .send()
        .await
        .context("failed to query snapshot status")?;
    let status = response.status();
    let body = response
        .text()
        .await
        .context("failed to decode snapshot status response")?;
    if !status.is_success() {
        anyhow::bail!("RPC returned {}: {}", status, body.trim());
    }

    let payload: SnapshotStreamStatusResponse =
        serde_json::from_str(&body).context("invalid snapshot status payload")?;
    print_snapshot_status("snapshot status", &payload);
    Ok(())
}

async fn resume_snapshot_session(args: SnapshotResumeCommand) -> Result<()> {
    let client = SnapshotRpcClient::new(&args.connection)?;
    let request = StartSnapshotStreamRequest {
        peer: &args.peer,
        chunk_size: args.chunk_size,
        resume: Some(ResumeMarker {
            session: args.session,
            plan_id: &args.plan_id,
        }),
    };
    let mut builder = client
        .client
        .post(client.endpoint("/p2p/snapshots"))
        .json(&request);
    builder = client.with_auth(builder);

    let response = builder
        .send()
        .await
        .context("failed to resume snapshot session")?;
    let status = response.status();
    let body = response
        .text()
        .await
        .context("failed to decode snapshot resume response")?;
    if !status.is_success() {
        anyhow::bail!("RPC returned {}: {}", status, body.trim());
    }

    let payload: SnapshotStreamStatusResponse =
        serde_json::from_str(&body).context("invalid snapshot status payload")?;
    print_snapshot_status("snapshot session resumed", &payload);
    Ok(())
}

async fn cancel_snapshot_session(args: SnapshotCancelCommand) -> Result<()> {
    let client = SnapshotRpcClient::new(&args.connection)?;
    let mut builder = client
        .client
        .delete(client.endpoint(&format!("/p2p/snapshots/{}", args.session)));
    builder = client.with_auth(builder);

    let response = builder
        .send()
        .await
        .context("failed to cancel snapshot session")?;
    let status = response.status();
    let body = response
        .text()
        .await
        .context("failed to decode snapshot cancel response")?;
    if !status.is_success() {
        anyhow::bail!("RPC returned {}: {}", status, body.trim());
    }

    println!("snapshot session {} cancelled", args.session);
    Ok(())
}

async fn snapshot_replay_status(args: SnapshotReplayStatusCommand) -> Result<()> {
    let client = SnapshotRpcClient::new(&args.connection)?;
    let mut builder = client
        .client
        .get(client.endpoint("/observability/timetoke/replay"));
    builder = client.with_auth(builder);

    let response = builder
        .send()
        .await
        .context("failed to query timetoke replay telemetry")?;
    let status = response.status();
    let body = response
        .text()
        .await
        .context("failed to decode timetoke replay telemetry response")?;
    if !status.is_success() {
        anyhow::bail!("RPC returned {}: {}", status, body.trim());
    }

    let payload: TimetokeReplayStatusResponse =
        serde_json::from_str(&body).context("invalid timetoke replay telemetry payload")?;

    println!("Timetoke replay telemetry:");
    println!("  success_total: {}", payload.success_total);
    println!("  failure_total: {}", payload.failure_total);
    match payload.success_rate {
        Some(rate) => println!("  success_rate: {:.2}%", rate * 100.0),
        None => println!("  success_rate: <unknown>"),
    }
    match payload.latency_p50_ms {
        Some(value) => println!("  latency_p50_ms: {}", value),
        None => println!("  latency_p50_ms: <unknown>"),
    }
    match payload.latency_p95_ms {
        Some(value) => println!("  latency_p95_ms: {}", value),
        None => println!("  latency_p95_ms: <unknown>"),
    }
    match payload.latency_p99_ms {
        Some(value) => println!("  latency_p99_ms: {}", value),
        None => println!("  latency_p99_ms: <unknown>"),
    }
    match payload.seconds_since_attempt {
        Some(value) => println!("  seconds_since_attempt: {}", value),
        None => println!("  seconds_since_attempt: <unknown>"),
    }
    match payload.seconds_since_success {
        Some(value) => println!("  seconds_since_success: {}", value),
        None => println!("  seconds_since_success: <unknown>"),
    }
    if !payload.failure_breakdown.is_empty() {
        println!("  failure_breakdown:");
        for entry in &payload.failure_breakdown {
            println!("    - {}: {}", entry.reason, entry.total);
        }
    }

    let mut warnings = Vec::new();
    if let Some(rate) = payload.success_rate {
        if rate < 0.99 {
            warnings.push(format!(
                "success rate {:.2}% below 99% target",
                rate * 100.0
            ));
        }
    }
    if let Some(p95) = payload.latency_p95_ms {
        if p95 > 60_000 {
            warnings.push(format!("p95 latency {} ms exceeds 60_000 ms SLO", p95));
        }
    }
    if let Some(p99) = payload.latency_p99_ms {
        if p99 > 120_000 {
            warnings.push(format!("p99 latency {} ms exceeds 120_000 ms SLO", p99));
        }
    }
    if payload.stall_warning {
        warnings.push("last successful replay older than 60 seconds".to_string());
    }
    if payload.stall_critical {
        warnings.push("last successful replay older than 120 seconds".to_string());
    }

    if warnings.is_empty() {
        println!("  slo_status: ok");
        Ok(())
    } else {
        for warning in &warnings {
            println!("WARNING: {warning}");
        }
        let summary = warnings.join("; ");
        anyhow::bail!("Timetoke replay SLO violations detected: {summary}");
    }
}

async fn verify_snapshot_manifest(args: SnapshotVerifyCommand) -> Result<()> {
    let config = load_validator_config(&args.config.config)?;
    let manifest_path = args
        .manifest
        .unwrap_or_else(|| config.snapshot_dir.join("manifest/chunks.json"));
    let signature_path = match args.signature {
        Some(path) => path,
        None => default_snapshot_signature_path(&manifest_path)?,
    };
    let chunk_root = args
        .chunk_root
        .unwrap_or_else(|| config.snapshot_dir.join("chunks"));

    let public_key_source = if let Some(path) = args.public_key {
        SnapshotVerifySource::Path(path)
    } else {
        let signing_key = config
            .load_timetoke_snapshot_signing_key()
            .map_err(|err| anyhow!(err))?;
        let verifying_key = signing_key.verifying_key();
        SnapshotVerifySource::Inline {
            label: config.timetoke_snapshot_key_path.display().to_string(),
            data: hex::encode(verifying_key.to_bytes()),
        }
    };

    let verify_args = SnapshotVerifyArgs {
        manifest: manifest_path.clone(),
        signature: signature_path.clone(),
        public_key: public_key_source,
        chunk_root: Some(chunk_root.clone()),
    };

    let mut report = SnapshotVerificationReport::new(&verify_args);
    let execution = run_snapshot_verification(&verify_args, &mut report);
    let exit_code = match execution {
        SnapshotVerifyExecution::Completed { exit_code } => exit_code,
        SnapshotVerifyExecution::Fatal { exit_code, error } => {
            report.errors.push(error);
            exit_code
        }
    };

    write_snapshot_report(&report, args.output.as_deref())
        .context("write snapshot verification report")?;

    if let Some(path) = args.output.as_ref() {
        println!("snapshot verification report written to {}", path.display());
    }

    if exit_code == SnapshotVerifyExitCode::Success {
        Ok(())
    } else {
        std::process::exit(exit_code.code());
    }
}

fn default_snapshot_signature_path(manifest_path: &Path) -> Result<PathBuf> {
    let file_name = manifest_path.file_name().ok_or_else(|| {
        anyhow!(
            "manifest {} is missing a file name",
            manifest_path.display()
        )
    })?;
    let mut signature_name = file_name.to_os_string();
    signature_name.push(".sig");
    Ok(manifest_path.with_file_name(signature_name))
}

async fn list_admission_backups(args: AdmissionBackupsListCommand) -> Result<()> {
    let client = AdmissionRpcClient::new(&args.connection)?;
    let mut builder = client.client.get(client.endpoint("/p2p/admission/backups"));
    builder = client.with_auth(builder);

    let response = builder
        .send()
        .await
        .context("failed to fetch admission policy backups")?;
    let status = response.status();
    let body = response
        .text()
        .await
        .context("failed to decode admission backup list response")?;
    if !status.is_success() {
        anyhow::bail!("RPC returned {}: {}", status, body.trim());
    }

    if args.json {
        println!("{}", body.trim());
        return Ok(());
    }

    let payload: AdmissionBackupsRpcResponse =
        serde_json::from_str(&body).context("invalid admission backups payload")?;
    if payload.backups.is_empty() {
        println!("no admission policy backups found");
        return Ok(());
    }

    println!("{:<48} {:>16} {:>10}", "NAME", "TIMESTAMP_MS", "SIZE");
    for backup in payload.backups {
        println!(
            "{:<48} {:>16} {:>10}",
            backup.name, backup.timestamp_ms, backup.size
        );
    }
    Ok(())
}

async fn download_admission_backup(args: AdmissionBackupsDownloadCommand) -> Result<()> {
    let backup = args.backup.trim();
    if backup.is_empty() {
        anyhow::bail!("backup name must not be empty");
    }
    let client = AdmissionRpcClient::new(&args.connection)?;
    let mut builder = client
        .client
        .get(client.endpoint("/p2p/admission/backups"))
        .query(&[("download", backup)]);
    builder = client.with_auth(builder);

    let response = builder
        .send()
        .await
        .context("failed to download admission policy backup")?;
    let status = response.status();
    let bytes = response
        .bytes()
        .await
        .context("failed to decode admission backup payload")?;
    if !status.is_success() {
        let body = String::from_utf8_lossy(&bytes);
        anyhow::bail!("RPC returned {}: {}", status, body.trim());
    }

    if let Some(path) = args.output.as_ref() {
        fs::write(path, &bytes)
            .with_context(|| format!("failed to write backup to {}", path.display()))?;
        println!(
            "admission policy backup `{}` written to {}",
            backup,
            path.display()
        );
    } else {
        io::stdout().write_all(&bytes)?;
    }
    Ok(())
}

async fn restore_admission_backup_cli(args: AdmissionRestoreCommand) -> Result<()> {
    let AdmissionRestoreCommand {
        connection,
        backup,
        actor,
        reason,
        approvals,
    } = args;

    let backup = backup.trim();
    if backup.is_empty() {
        anyhow::bail!("backup name must not be empty");
    }
    let actor = actor.trim();
    if actor.is_empty() {
        anyhow::bail!("actor must not be empty");
    }
    let reason = reason
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(|value| value.to_string());

    let mut payload_approvals = Vec::with_capacity(approvals.len());
    let mut approval_roles = HashSet::new();
    for entry in approvals {
        let mut parts = entry.splitn(2, ':');
        let role = parts
            .next()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| {
                anyhow::anyhow!("invalid approval `{entry}` (expected ROLE:APPROVER)")
            })?;
        let approver = parts
            .next()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| {
                anyhow::anyhow!("invalid approval `{entry}` (expected ROLE:APPROVER)")
            })?;
        let normalized = role.to_ascii_lowercase();
        if !approval_roles.insert(normalized) {
            anyhow::bail!("duplicate approval role `{role}`");
        }
        payload_approvals.push(AdmissionApprovalPayload {
            role: role.to_string(),
            approver: approver.to_string(),
        });
    }

    let client = AdmissionRpcClient::new(&connection)?;
    let request = RestoreAdmissionBackupRpcRequest {
        backup: backup.to_string(),
        actor: actor.to_string(),
        reason,
        approvals: payload_approvals,
    };
    let mut builder = client
        .client
        .post(client.endpoint("/p2p/admission/backups"))
        .json(&request);
    builder = client.with_auth(builder);

    let response = builder
        .send()
        .await
        .context("failed to restore admission policies from backup")?;
    let status = response.status();
    let body = response
        .text()
        .await
        .context("failed to decode admission restore response")?;
    if !status.is_success() {
        anyhow::bail!("RPC returned {}: {}", status, body.trim());
    }

    println!("admission policies restored from `{}`", request.backup);
    Ok(())
}

async fn verify_admission_signatures(args: AdmissionVerifyCommand) -> Result<()> {
    let AdmissionVerifyCommand {
        connection,
        audit_limit,
    } = args;
    const ADMISSION_AUDIT_PAGE_SIZE: usize = 512;
    let client = AdmissionRpcClient::new(&connection)?;
    let config = load_validator_config(&connection.config.config)?;
    if config.network.admission.signing.trust_store.is_empty() {
        anyhow::bail!(
            "network.admission.signing.trust_store is empty; configure trusted signing keys"
        );
    }
    let trust_store =
        PolicyTrustStore::from_hex(config.network.admission.signing.trust_store.clone())
            .map_err(|err| anyhow!(err.to_string()))?;
    let verifier = PolicySignatureVerifier::new(trust_store);

    let mut policies_request = client
        .client
        .get(client.endpoint("/p2p/admission/policies"));
    policies_request = client.with_auth(policies_request);
    let response = policies_request
        .send()
        .await
        .context("failed to fetch admission policies")?;
    let status = response.status();
    let body = response
        .text()
        .await
        .context("failed to decode admission policies payload")?;
    if !status.is_success() {
        anyhow::bail!("RPC returned {}: {}", status, body.trim());
    }
    let policies: AdmissionPoliciesRpcResponse =
        serde_json::from_str(&body).context("invalid admission policies payload")?;
    let signature = policies
        .signature
        .clone()
        .ok_or_else(|| anyhow!("admission policy snapshot is missing a signature"))?;
    let snapshot_bytes = canonical_snapshot_bytes(&policies)?;
    verifier
        .verify(&signature, &snapshot_bytes)
        .map_err(|err| anyhow!(err.to_string()))?;
    println!(
        "admission policy snapshot signature verified with key `{}`",
        signature.key_id
    );

    let mut limit = audit_limit;
    if limit == 0 {
        let mut meta_request = client
            .client
            .get(client.endpoint("/p2p/admission/audit"))
            .query(&[("offset", 0usize), ("limit", 0usize)]);
        meta_request = client.with_auth(meta_request);
        let response = meta_request
            .send()
            .await
            .context("failed to fetch admission audit metadata")?;
        let status = response.status();
        let body = response
            .text()
            .await
            .context("failed to decode admission audit metadata")?;
        if !status.is_success() {
            anyhow::bail!("RPC returned {}: {}", status, body.trim());
        }
        let payload: AdmissionAuditRpcResponse =
            serde_json::from_str(&body).context("invalid admission audit metadata")?;
        limit = payload.total;
    }

    let mut verified_entries = 0usize;
    if limit > 0 {
        let mut offset = 0usize;
        while verified_entries < limit {
            let remaining = limit - verified_entries;
            let page_size = remaining.min(ADMISSION_AUDIT_PAGE_SIZE).max(1);
            let mut audit_request = client
                .client
                .get(client.endpoint("/p2p/admission/audit"))
                .query(&[("offset", offset), ("limit", page_size)]);
            audit_request = client.with_auth(audit_request);
            let response = audit_request
                .send()
                .await
                .context("failed to fetch admission audit log")?;
            let status = response.status();
            let body = response
                .text()
                .await
                .context("failed to decode admission audit payload")?;
            if !status.is_success() {
                anyhow::bail!("RPC returned {}: {}", status, body.trim());
            }
            let payload: AdmissionAuditRpcResponse =
                serde_json::from_str(&body).context("invalid admission audit payload")?;
            if payload.entries.is_empty() {
                break;
            }
            for entry in &payload.entries {
                let signature = entry.signature.as_ref().ok_or_else(|| {
                    anyhow!(format!(
                        "admission audit entry {} missing signature",
                        entry.id
                    ))
                })?;
                let message = entry.canonical_bytes().map_err(|err| {
                    anyhow!(format!("failed to encode audit entry {}: {err}", entry.id))
                })?;
                verifier.verify(signature, &message).map_err(|err| {
                    anyhow!(format!(
                        "audit entry {} verification failed: {err}",
                        entry.id
                    ))
                })?;
            }
            verified_entries += payload.entries.len();
            offset += payload.entries.len();
            if offset >= payload.total {
                break;
            }
        }
    }

    println!(
        "verified {} admission audit log entries with configured trust store",
        verified_entries
    );
    Ok(())
}

fn canonical_snapshot_bytes(snapshot: &AdmissionPoliciesRpcResponse) -> Result<Vec<u8>> {
    let mut blocklist = snapshot.blocklist.clone();
    blocklist.sort();
    let canonical = AdmissionSnapshotCanonical {
        allowlist: snapshot.allowlist.clone(),
        blocklist,
    };
    serde_json::to_vec(&canonical).context("failed to encode policies for verification")
}

fn print_snapshot_status(label: &str, status: &SnapshotStreamStatusResponse) {
    println!("{label}:");
    println!("  session: {}", status.session);
    println!("  peer: {}", status.peer);
    println!("  root: {}", status.root);
    let plan_id = status
        .plan_id
        .as_deref()
        .filter(|value| !value.is_empty())
        .unwrap_or(&status.root);
    println!("  plan_id: {plan_id}");
    println!(
        "  last_chunk_index: {}",
        status
            .last_chunk_index
            .map(|value| value.to_string())
            .unwrap_or_else(|| "none".to_string())
    );
    println!(
        "  last_update_index: {}",
        status
            .last_update_index
            .map(|value| value.to_string())
            .unwrap_or_else(|| "none".to_string())
    );
    println!(
        "  last_update_height: {}",
        status
            .last_update_height
            .map(|value| value.to_string())
            .unwrap_or_else(|| "none".to_string())
    );
    let verified = status
        .verified
        .map(|value| value.to_string())
        .unwrap_or_else(|| "unknown".to_string());
    println!("  verified: {verified}");
    println!(
        "  error: {}",
        status
            .error
            .as_deref()
            .filter(|value| !value.is_empty())
            .unwrap_or("none")
    );
}

fn default_rpc_base_url(config: &NodeConfig) -> String {
    let listen = config.network.rpc.listen;
    let host = if listen.ip().is_unspecified() {
        "127.0.0.1".to_string()
    } else if listen.ip().is_ipv6() {
        format!("[{}]", listen.ip())
    } else {
        listen.ip().to_string()
    };
    format!("http://{host}:{}", listen.port())
}

fn normalize_cli_bearer_token(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }
    let token = if trimmed.to_ascii_lowercase().starts_with("bearer ") {
        trimmed[7..].trim()
    } else {
        trimmed
    };
    if token.is_empty() {
        None
    } else {
        Some(token.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    #[test]
    fn canonical_snapshot_bytes_sorts_blocklist_and_preserves_allowlist() {
        let snapshot = AdmissionPoliciesRpcResponse {
            allowlist: vec![AdmissionPolicyEntry {
                peer_id: "peer-a".into(),
                tier: TierLevel::Tl1,
            }],
            blocklist: vec!["peer-z".into(), "peer-b".into()],
            signature: None,
        };
        let bytes = canonical_snapshot_bytes(&snapshot).expect("canonical bytes");
        let value: Value = serde_json::from_slice(&bytes).expect("json");
        assert_eq!(
            value["allowlist"].as_array().expect("allowlist len")[0]["peer_id"],
            Value::String("peer-a".into())
        );
        let block: Vec<String> = value["blocklist"]
            .as_array()
            .expect("blocklist")
            .iter()
            .map(|entry| entry.as_str().expect("string").to_string())
            .collect();
        assert_eq!(block, vec!["peer-b", "peer-z"]);
    }

    #[test]
    fn normalize_cli_bearer_token_handles_prefix_and_whitespace() {
        assert_eq!(
            normalize_cli_bearer_token("   bearer example-token  "),
            Some("example-token".into())
        );
        assert_eq!(
            normalize_cli_bearer_token("ExplicitToken"),
            Some("ExplicitToken".into())
        );
        assert_eq!(normalize_cli_bearer_token("   "), None);
    }
}

async fn submit_uptime_proof(command: UptimeSubmitCommand) -> Result<()> {
    let wallet = build_wallet_for_uptime(&command.wallet_config)?;
    let address = wallet.address().to_string();
    let wallet_for_task = Arc::clone(&wallet);
    let proof = task
        .spawn_blocking(move || {
            wallet_for_task
                .generate_uptime_proof()
                .map_err(|err| anyhow!(err))
        })
        .await
        .context("uptime proof generation task failed")??;

    let client = Client::builder()
        .build()
        .context("failed to build uptime submission client")?;
    let base = command.rpc_url.trim_end_matches('/');
    let mut request = client
        .post(format!("{}/validator/uptime", base))
        .json(&proof);
    if let Some(token) = command.auth_token.as_ref() {
        request = request.bearer_auth(token);
    }

    let response = request
        .send()
        .await
        .context("failed to submit uptime proof")?;
    let status = response.status();
    let body = response
        .text()
        .await
        .context("failed to decode uptime submission response")?;
    if !status.is_success() {
        anyhow::bail!("RPC returned {}: {}", status, body.trim());
    }

    let SubmitUptimeResponse { credited_hours } =
        serde_json::from_str(&body).context("invalid uptime submission payload")?;

    println!(
        "uptime proof submitted; address={} window={}..{} credited_hours={}",
        address, proof.window_start, proof.window_end, credited_hours
    );
    Ok(())
}

async fn fetch_uptime_status(command: UptimeStatusCommand) -> Result<()> {
    let client = Client::builder()
        .build()
        .context("failed to build uptime status client")?;
    let base = command.rpc_url.trim_end_matches('/');
    let mut request = client.get(format!("{}/validator/proofs", base));
    if let Some(token) = command.auth_token.as_ref() {
        request = request.bearer_auth(token);
    }

    let response = request
        .send()
        .await
        .context("failed to query uptime status")?;
    let status = response.status();
    let body = response
        .text()
        .await
        .context("failed to decode uptime status response")?;
    if !status.is_success() {
        anyhow::bail!("RPC returned {}: {}", status, body.trim());
    }

    let value: Value = serde_json::from_str(&body).context("invalid uptime status payload")?;
    if command.json {
        println!("{}", serde_json::to_string_pretty(&value)?);
        return Ok(());
    }

    let queue: ValidatorProofQueueStatus =
        serde_json::from_value(value).context("invalid uptime status payload")?;

    println!("uptime proofs queued: {}", queue.totals.uptime_proofs);
    println!("transactions queued: {}", queue.totals.transactions);
    println!("identity attestations queued: {}", queue.totals.identities);
    println!("votes queued: {}", queue.totals.votes);

    if queue.uptime_proofs.is_empty() {
        println!("no pending uptime proofs in the mempool");
        return Ok(());
    }

    let limit = command.limit.min(queue.uptime_proofs.len());
    if limit == 0 {
        println!("pending uptime proofs present but limit=0 suppressed output");
        return Ok(());
    }

    println!("showing {} pending uptime proofs:", limit);
    for proof in queue.uptime_proofs.iter().take(limit) {
        println!(
            "  - identity={} window={}..{} credited_hours={}",
            proof.identity, proof.window_start, proof.window_end, proof.credited_hours
        );
    }
    if queue.uptime_proofs.len() > limit {
        println!(
            "  ... {} additional entries not shown",
            queue.uptime_proofs.len() - limit
        );
    }

    Ok(())
}

async fn run_validator_setup(command: ValidatorSetupCommand) -> CliResult<()> {
    let config = load_validator_config(&command.config.config).map_err(CliError::from)?;
    let options = crate::ValidatorSetupOptions {
        telemetry_probe_timeout: Duration::from_secs(command.telemetry_timeout.max(1)),
        skip_telemetry_probe: command.skip_telemetry_probe,
    };

    let report = crate::validator_setup(&config, options)
        .await
        .map_err(|err| CliError::from(err.into_bootstrap_error()))?;

    let crate::ValidatorSetupReport {
        secrets_backend,
        identifier,
        public_key,
        telemetry,
    } = report;

    println!("validator setup completed successfully:");
    println!("  secrets backend: {}", backend_label(&secrets_backend));
    println!("  vrf key location: {}", format_identifier(&identifier));
    println!("  vrf public key: {public_key}");

    if !telemetry.enabled {
        println!("  telemetry probe: telemetry disabled in configuration");
    } else if telemetry.skipped {
        let endpoint = telemetry.http_endpoint.as_deref().unwrap_or("<unknown>");
        let auth = if telemetry.auth_applied {
            "bearer"
        } else {
            "none"
        };
        println!("  telemetry probe: skipped (endpoint={endpoint}, auth={auth})");
    } else {
        let endpoint = telemetry.http_endpoint.as_deref().unwrap_or("<unknown>");
        let status = telemetry
            .http_status
            .map(|code| code.to_string())
            .unwrap_or_else(|| "unknown".to_string());
        let auth = if telemetry.auth_applied {
            "bearer"
        } else {
            "none"
        };
        println!("  telemetry probe: endpoint={endpoint} status={status} auth={auth}");
        if let Some(code) = telemetry.http_status {
            if !code.is_success() {
                println!("    warning: telemetry endpoint responded with non-success status");
            }
        }
    }

    Ok(())
}

fn prepare_vrf_store(
    config_path: &Path,
) -> Result<(SecretsConfig, VrfKeyIdentifier, DynVrfKeyStore)> {
    let config = load_validator_config(config_path)?;
    let secrets = config.secrets.clone();
    secrets
        .ensure_directories(&config.vrf_key_path)
        .map_err(|err| anyhow!(err))?;
    let identifier = secrets
        .vrf_identifier(&config.vrf_key_path)
        .map_err(|err| anyhow!(err))?;
    let store = secrets.build_keystore().map_err(|err| anyhow!(err))?;
    Ok((secrets, identifier, store))
}

fn build_wallet_for_uptime(config_path: &Path) -> Result<Arc<Wallet>> {
    if !config_path.exists() {
        anyhow::bail!(
            "wallet configuration not found at {}",
            config_path.display()
        );
    }

    let config = WalletConfig::load(config_path)
        .map_err(|err| anyhow!(err))
        .with_context(|| {
            format!(
                "failed to load wallet configuration from {}",
                config_path.display()
            )
        })?;
    config.ensure_directories().map_err(|err| anyhow!(err))?;

    let storage_path = config.data_dir.join("db");
    let storage = Storage::open(&storage_path)
        .map_err(|err| anyhow!(err))
        .with_context(|| {
            format!(
                "failed to open wallet storage at {}",
                storage_path.display()
            )
        })?;
    let keypair =
        load_or_generate_keypair(&config.wallet.keys.key_path).map_err(|err| anyhow!(err))?;

    Ok(Arc::new(Wallet::new(
        storage,
        keypair,
        RuntimeMetrics::noop(),
    )))
}

fn load_validator_config(path: &Path) -> Result<NodeConfig> {
    if !path.exists() {
        anyhow::bail!("validator configuration not found at {}", path.display());
    }
    NodeConfig::load(path)
        .map_err(|err| anyhow!(err))
        .with_context(|| {
            format!(
                "failed to load validator configuration from {}",
                path.display()
            )
        })
}

fn backend_name(secrets: &SecretsConfig) -> &'static str {
    backend_label(&secrets.backend)
}

fn backend_label(backend: &SecretsBackendConfig) -> &'static str {
    match backend {
        SecretsBackendConfig::Filesystem(_) => "filesystem",
        SecretsBackendConfig::Vault(_) => "vault",
        SecretsBackendConfig::Hsm(_) => "hsm",
    }
}

fn format_identifier(identifier: &VrfKeyIdentifier) -> String {
    match identifier {
        VrfKeyIdentifier::Filesystem(path) => path.display().to_string(),
        VrfKeyIdentifier::Remote(key) => key.clone(),
    }
}
