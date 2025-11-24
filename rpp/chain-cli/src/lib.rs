#![doc = include_str!("../SDK.md")]

use std::collections::HashSet;
use std::fmt;
use std::fs;
use std::future::Future;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use clap::{ArgAction, Args, CommandFactory, Parser, Subcommand};
use hex;
use reqwest::{Certificate, Client, ClientBuilder, Identity, Proxy, StatusCode};
use rpp_chain::crypto::{
    generate_vrf_keypair, load_or_generate_keypair, vrf_public_key_to_hex, vrf_secret_key_to_hex,
    DynVrfKeyStore, VrfKeyIdentifier, VrfKeyStore, VrfKeypair,
};
use rpp_chain::runtime::config::{
    NodeConfig, SecretsBackendConfig, SecretsConfig, SnapshotChecksumAlgorithm, TelemetryConfig,
    WalletConfig, WalletConfigExt, DEFAULT_SNAPSHOT_MAX_CONCURRENT_CHUNK_DOWNLOADS,
};
use rpp_chain::runtime::node_runtime::node::SnapshotDownloadErrorCode;
use rpp_chain::runtime::{RuntimeMetrics, TelemetryExporterBuilder};
use rpp_chain::storage::Storage;
use rpp_chain::wallet::Wallet;
use rpp_node_runtime_api::{BootstrapError, BootstrapResult, RuntimeMode, RuntimeOptions};
use rpp_p2p::{
    AdmissionPolicyLogEntry, PolicySignature, PolicySignatureVerifier, PolicyTrustStore, TierLevel,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use snapshot_verify::{
    run_verification as run_snapshot_verification, write_report as write_snapshot_report,
    ChecksumAlgorithm as SnapshotVerifyChecksumAlgorithm, DataSource as SnapshotVerifySource,
    Execution as SnapshotVerifyExecution, ExitCode as SnapshotVerifyExitCode,
    VerificationReport as SnapshotVerificationReport, VerifyArgs as SnapshotVerifyArgs,
};
use tokio::task;

mod rate_limit;
mod snapshot_errors;
pub use rate_limit::{compute_retry_delay, rate_limit_window, RateLimitWindow};
pub use snapshot_errors::{classify_snapshot_error, SnapshotError, SnapshotErrorKind};

const DEFAULT_VALIDATOR_CONFIG: &str = "config/validator.toml";
const DEFAULT_WALLET_CONFIG: &str = "config/wallet.toml";

pub type CliResult<T = ()> = std::result::Result<T, CliError>;

pub trait RuntimeExecutor: Send + Sync {
    type Future: Future<Output = BootstrapResult<()>> + Send;

    fn launch(&self, mode: RuntimeMode, options: RuntimeOptions) -> Self::Future;
}

impl<F, Fut> RuntimeExecutor for F
where
    F: Fn(RuntimeMode, RuntimeOptions) -> Fut + Send + Sync,
    Fut: Future<Output = BootstrapResult<()>> + Send,
{
    type Future = Fut;

    fn launch(&self, mode: RuntimeMode, options: RuntimeOptions) -> Self::Future {
        (self)(mode, options)
    }
}

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
    after_help = "Exit codes:\n  0 - runtime exited cleanly\n  2 - configuration validation failed\n  3 - runtime startup failed\n  4 - unexpected runtime error\n\nCleanup runbook: docs/mempool_cleanup.md"
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
    #[arg(long, value_name = "TOKEN", env = "RPP_SNAPSHOT_AUTH_TOKEN")]
    auth_token: Option<String>,

    /// Path to an additional CA certificate used to verify the snapshot RPC server
    #[arg(long, value_name = "PATH", env = "RPP_SNAPSHOT_CA_CERT")]
    tls_ca_certificate: Option<PathBuf>,

    /// Client certificate used when the snapshot RPC server enforces mTLS
    #[arg(long, value_name = "PATH", env = "RPP_SNAPSHOT_CLIENT_CERT")]
    tls_client_certificate: Option<PathBuf>,

    /// Private key paired with the provided snapshot RPC client certificate
    #[arg(long, value_name = "PATH", env = "RPP_SNAPSHOT_CLIENT_KEY")]
    tls_client_private_key: Option<PathBuf>,

    /// Skip TLS certificate verification when downloading snapshots
    #[arg(
        long,
        action = ArgAction::SetTrue,
        env = "RPP_SNAPSHOT_INSECURE_TLS",
        alias = "snapshot-insecure-tls",
        help = "Bypass TLS verification for snapshot downloads (useful for tests)"
    )]
    tls_insecure_skip_verify: bool,

    /// Total request attempts before surfacing a snapshot download error
    #[arg(long, value_name = "N", default_value_t = DEFAULT_SNAPSHOT_RETRY_ATTEMPTS)]
    retry_attempts: u32,

    /// Initial backoff delay (ms) used when retrying snapshot downloads
    #[arg(long, value_name = "MILLIS", default_value_t = DEFAULT_SNAPSHOT_RETRY_BACKOFF_MS)]
    retry_backoff_ms: u64,

    /// Maximum number of chunks to download concurrently
    #[arg(
        long,
        value_name = "COUNT",
        default_value_t = DEFAULT_SNAPSHOT_MAX_CONCURRENT_CHUNK_DOWNLOADS as u32,
        env = "RPP_SNAPSHOT_MAX_CONCURRENT_DOWNLOADS"
    )]
    max_concurrent_downloads: u32,

    /// HTTP proxy used for snapshot RPC requests
    #[arg(long, value_name = "URL", env = "RPP_SNAPSHOT_HTTP_PROXY")]
    http_proxy: Option<String>,

    /// HTTPS proxy used for snapshot RPC requests
    #[arg(long, value_name = "URL", env = "RPP_SNAPSHOT_HTTPS_PROXY")]
    https_proxy: Option<String>,
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

    /// Emit verbose checksum progress while validating snapshot chunks
    #[arg(long, default_value_t = false)]
    verbose_progress: bool,

    /// Override the checksum algorithm when the manifest omits the field
    #[arg(long, value_enum)]
    checksum_algorithm: Option<SnapshotChecksumAlgorithm>,
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

pub async fn run_cli<R>(runtime: R) -> ExitCode
where
    R: RuntimeExecutor,
{
    match run_cli_inner(&runtime).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("{err}");
            ExitCode::from(err.exit_code() as u8)
        }
    }
}

async fn run_cli_inner<R>(runtime: &R) -> CliResult<()>
where
    R: RuntimeExecutor,
{
    let RootCli { command } = RootCli::parse();
    match command {
        RootCommand::Node(RuntimeCommand { options }) => {
            run_runtime(runtime, RuntimeMode::Node, options).await
        }
        RootCommand::Wallet(RuntimeCommand { options }) => {
            run_runtime(runtime, RuntimeMode::Wallet, options).await
        }
        RootCommand::Hybrid(RuntimeCommand { options }) => {
            run_runtime(runtime, RuntimeMode::Hybrid, options).await
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
            None => run_runtime(runtime, RuntimeMode::Validator, args.runtime).await,
        },
    }
}

async fn run_runtime<R>(runtime: &R, mode: RuntimeMode, options: RuntimeOptions) -> CliResult<()>
where
    R: RuntimeExecutor,
{
    runtime.launch(mode, options).await.map_err(CliError::from)
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
    retry_attempts: u32,
    retry_backoff: Duration,
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
    chunk_size: Option<u64>,
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
    error_code: Option<SnapshotDownloadErrorCode>,
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
    max_concurrent_downloads: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    resume: Option<ResumeMarker<'a>>,
}

#[derive(Serialize)]
struct ResumeMarker<'a> {
    session: u64,
    plan_id: &'a str,
}

const DEFAULT_SNAPSHOT_RETRY_ATTEMPTS: u32 = 3;
const DEFAULT_SNAPSHOT_RETRY_BACKOFF_MS: u64 = 200;

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

        let mut builder = Client::builder();
        if args.tls_insecure_skip_verify {
            builder = builder.danger_accept_invalid_certs(true);
        }

        if let Some(ca) = args.tls_ca_certificate.as_ref() {
            let pem = fs::read(ca).with_context(|| {
                format!("failed to read snapshot CA certificate {}", ca.display())
            })?;
            let certificate =
                Certificate::from_pem(&pem).context("failed to parse snapshot CA certificate")?;
            builder = builder.add_root_certificate(certificate);
        }

        if let (Some(cert), Some(key)) = (
            args.tls_client_certificate.as_ref(),
            args.tls_client_private_key.as_ref(),
        ) {
            let mut identity_bytes = fs::read(cert).with_context(|| {
                format!(
                    "failed to read snapshot client certificate {}",
                    cert.display()
                )
            })?;
            let key_bytes = fs::read(key)
                .with_context(|| format!("failed to read snapshot client key {}", key.display()))?;
            identity_bytes.extend_from_slice(&key_bytes);
            let identity = Identity::from_pem(&identity_bytes)
                .context("failed to parse snapshot client identity")?;
            builder = builder.identity(identity);
        }

        let client = build_snapshot_client(builder, args)?;

        Ok(Self {
            client,
            base_url,
            auth_token,
            retry_attempts: args.retry_attempts.max(1),
            retry_backoff: Duration::from_millis(args.retry_backoff_ms.max(1)),
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

    async fn send_with_retry<F>(&self, label: &str, mut build: F) -> Result<reqwest::Response>
    where
        F: FnMut() -> reqwest::RequestBuilder,
    {
        let mut delay = self.retry_backoff;
        for attempt in 1..=self.retry_attempts {
            let response = build().send().await;
            match response {
                Ok(resp) if resp.status().is_server_error() => {
                    if attempt == self.retry_attempts {
                        anyhow::bail!(
                            "snapshot RPC returned {} after {attempt} attempts",
                            resp.status()
                        );
                    }
                }
                Ok(resp) => return Ok(resp),
                Err(err) => {
                    if attempt == self.retry_attempts {
                        return Err(err)
                            .context(format!("failed to {label} after {attempt} attempts"));
                    }
                }
            }

            tokio::time::sleep(delay).await;
            delay = delay.saturating_mul(2);
        }

        anyhow::bail!("failed to {label}: retries exhausted")
    }
}

fn build_snapshot_client(builder: ClientBuilder, args: &SnapshotConnectionArgs) -> Result<Client> {
    let builder = apply_snapshot_proxies(builder, args)?;
    builder
        .build()
        .context("failed to build snapshot RPC client")
}

fn apply_snapshot_proxies(
    mut builder: ClientBuilder,
    args: &SnapshotConnectionArgs,
) -> Result<ClientBuilder> {
    if let Some(proxy) = snapshot_proxy_url(args.http_proxy.as_deref()) {
        builder = builder.proxy(Proxy::http(proxy)?);
    }

    if let Some(proxy) = snapshot_proxy_url(args.https_proxy.as_deref()) {
        builder = builder.proxy(Proxy::https(proxy)?);
    }

    Ok(builder)
}

fn snapshot_proxy_url(value: Option<&str>) -> Option<String> {
    value.and_then(|raw| {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            None
        } else {
            Some(trimmed.to_string())
        }
    })
}

#[cfg(test)]
mod tests {
    use super::{build_snapshot_client, SnapshotConnectionArgs, ValidatorConfigArgs};
    use hyper::header::PROXY_AUTHORIZATION;
    use hyper::service::{make_service_fn, service_fn};
    use hyper::{Body, Request, Response, Server};
    use std::convert::Infallible;
    use std::net::SocketAddr;
    use std::path::PathBuf;
    use std::sync::{Arc, Mutex};
    use tokio::sync::oneshot;

    struct CapturedProxyRequest {
        uri: String,
        proxy_authorization: Option<String>,
    }

    #[tokio::test]
    async fn routes_requests_through_configured_proxy() {
        let (proxy_addr, request_rx, shutdown_tx) = spawn_mock_proxy();
        let proxy_url = format!("http://{}", proxy_addr);
        let args = test_connection_args(Some(proxy_url), None);

        let client = build_snapshot_client(reqwest::Client::builder(), &args).unwrap();
        let target = "http://example.invalid/proxied";
        let response = client.get(target).send().await.unwrap();

        assert_eq!(response.text().await.unwrap(), "proxied");

        let observed = request_rx.await.expect("proxy captured request");
        assert_eq!(observed.uri, target);
        shutdown_tx.send(()).ok();
    }

    #[tokio::test]
    async fn forwards_proxy_authorization_headers() {
        let (proxy_addr, request_rx, shutdown_tx) = spawn_mock_proxy();
        let proxy_url = format!("http://user:password@{}", proxy_addr);
        let args = test_connection_args(Some(proxy_url), None);

        let client = build_snapshot_client(reqwest::Client::builder(), &args).unwrap();
        let response = client
            .get("http://example.invalid/authorized")
            .send()
            .await
            .unwrap();

        assert_eq!(response.text().await.unwrap(), "proxied");

        let observed = request_rx.await.expect("proxy captured request");
        assert_eq!(
            observed.proxy_authorization.as_deref(),
            Some("Basic dXNlcjpwYXNzd29yZA==")
        );
        shutdown_tx.send(()).ok();
    }

    fn test_connection_args(
        http_proxy: Option<String>,
        https_proxy: Option<String>,
    ) -> SnapshotConnectionArgs {
        SnapshotConnectionArgs {
            config: ValidatorConfigArgs {
                config: PathBuf::from("/tmp/unused.toml"),
            },
            rpc_url: None,
            auth_token: None,
            tls_ca_certificate: None,
            tls_client_certificate: None,
            tls_client_private_key: None,
            tls_insecure_skip_verify: false,
            retry_attempts: 1,
            retry_backoff_ms: 1,
            max_concurrent_downloads: 4,
            http_proxy,
            https_proxy,
        }
    }

    fn spawn_mock_proxy() -> (
        SocketAddr,
        oneshot::Receiver<CapturedProxyRequest>,
        oneshot::Sender<()>,
    ) {
        let (request_tx, request_rx) = oneshot::channel();
        let (shutdown_tx, shutdown_rx) = oneshot::channel();
        let captured = Arc::new(Mutex::new(Some(request_tx)));

        let make_service = make_service_fn(move |_conn| {
            let captured = captured.clone();
            async move {
                Ok::<_, Infallible>(service_fn(move |req: Request<Body>| {
                    let captured = captured.clone();
                    async move {
                        if let Some(sender) = captured.lock().unwrap().take() {
                            let _ = sender.send(CapturedProxyRequest {
                                uri: req.uri().to_string(),
                                proxy_authorization: req
                                    .headers()
                                    .get(PROXY_AUTHORIZATION)
                                    .and_then(|value| value.to_str().ok())
                                    .map(|value| value.to_string()),
                            });
                        }

                        Ok::<_, Infallible>(Response::new(Body::from("proxied")))
                    }
                }))
            }
        });

        let server = Server::bind(&SocketAddr::from(([127, 0, 0, 1], 0))).serve(make_service);
        let proxy_addr = server.local_addr();
        tokio::spawn(server.with_graceful_shutdown(async move {
            let _ = shutdown_rx.await;
        }));

        (proxy_addr, request_rx, shutdown_tx)
    }
}

async fn start_snapshot_session(args: SnapshotStartCommand) -> Result<()> {
    let client = SnapshotRpcClient::new(&args.connection)?;
    let request = StartSnapshotStreamRequest {
        peer: &args.peer,
        chunk_size: args.chunk_size,
        max_concurrent_downloads: args.connection.max_concurrent_downloads,
        resume: None,
    };
    let response = client
        .send_with_retry("start snapshot session", || {
            let mut builder = client
                .client
                .post(client.endpoint("/p2p/snapshots"))
                .json(&request);
            builder = client.with_auth(builder);
            builder
        })
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
    let response = client
        .send_with_retry("query snapshot status", || {
            let mut builder = client
                .client
                .get(client.endpoint(&format!("/p2p/snapshots/{}", args.session)));
            builder = client.with_auth(builder);
            builder
        })
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
        max_concurrent_downloads: args.connection.max_concurrent_downloads,
        resume: Some(ResumeMarker {
            session: args.session,
            plan_id: &args.plan_id,
        }),
    };
    let response = client
        .send_with_retry("resume snapshot session", || {
            let mut builder = client
                .client
                .post(client.endpoint("/p2p/snapshots"))
                .json(&request);
            builder = client.with_auth(builder);
            builder
        })
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
    let response = client
        .send_with_retry("cancel snapshot session", || {
            let mut builder = client
                .client
                .delete(client.endpoint(&format!("/p2p/snapshots/{}", args.session)));
            builder = client.with_auth(builder);
            builder
        })
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
        let verifying_key = signing_key.signing_key.verifying_key();
        SnapshotVerifySource::Inline {
            label: config.timetoke_snapshot_key_path.display().to_string(),
            data: hex::encode(verifying_key.to_bytes()),
        }
    };

    let checksum_algorithm = args
        .checksum_algorithm
        .unwrap_or(config.snapshot_checksum_algorithm);

    let verify_args = SnapshotVerifyArgs {
        manifest: manifest_path.clone(),
        signature: signature_path.clone(),
        public_key: public_key_source,
        chunk_root: Some(chunk_root.clone()),
        verbose_progress: args.verbose_progress,
        checksum_algorithm: Some(to_snapshot_verify_algorithm(checksum_algorithm)),
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

fn to_snapshot_verify_algorithm(
    algorithm: SnapshotChecksumAlgorithm,
) -> SnapshotVerifyChecksumAlgorithm {
    match algorithm {
        SnapshotChecksumAlgorithm::Sha256 => SnapshotVerifyChecksumAlgorithm::Sha256,
        SnapshotChecksumAlgorithm::Blake2b => SnapshotVerifyChecksumAlgorithm::Blake2b,
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
    println!(
        "  chunk_size: {}",
        status
            .chunk_size
            .map(|value| value.to_string())
            .unwrap_or_else(|| "unknown".to_string())
    );
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
    let error_code = status
        .error_code
        .as_ref()
        .map(|value| format!("{value:?}"))
        .unwrap_or_else(|| "none".to_string());
    println!("  error_code: {error_code}");
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

#[derive(Debug, Clone)]
pub struct ValidatorSetupOptions {
    pub telemetry_probe_timeout: Duration,
    pub skip_telemetry_probe: bool,
}

impl Default for ValidatorSetupOptions {
    fn default() -> Self {
        Self {
            telemetry_probe_timeout: Duration::from_secs(5),
            skip_telemetry_probe: false,
        }
    }
}

#[derive(Debug, Clone)]
pub struct ValidatorSetupTelemetryReport {
    pub enabled: bool,
    pub skipped: bool,
    pub http_endpoint: Option<String>,
    pub http_status: Option<StatusCode>,
    pub auth_applied: bool,
}

#[derive(Debug, Clone)]
pub struct ValidatorSetupReport {
    pub secrets_backend: SecretsBackendConfig,
    pub identifier: VrfKeyIdentifier,
    pub public_key: String,
    pub telemetry: ValidatorSetupTelemetryReport,
}

#[derive(Debug)]
pub enum ValidatorSetupError {
    Configuration(anyhow::Error),
    Network(anyhow::Error),
}

impl ValidatorSetupError {
    pub fn configuration<E>(error: E) -> Self
    where
        E: Into<anyhow::Error>,
    {
        Self::Configuration(error.into())
    }

    pub fn network<E>(error: E) -> Self
    where
        E: Into<anyhow::Error>,
    {
        Self::Network(error.into())
    }

    pub fn into_bootstrap_error(self) -> BootstrapError {
        match self {
            ValidatorSetupError::Configuration(err) => BootstrapError::configuration(err),
            ValidatorSetupError::Network(err) => BootstrapError::startup(err),
        }
    }
}

pub async fn validator_setup(
    config: &NodeConfig,
    options: ValidatorSetupOptions,
) -> Result<ValidatorSetupReport, ValidatorSetupError> {
    config
        .secrets
        .validate_with_path(&config.vrf_key_path)
        .map_err(ValidatorSetupError::configuration)?;
    config
        .secrets
        .ensure_directories(&config.vrf_key_path)
        .map_err(ValidatorSetupError::configuration)?;

    let identifier = config
        .secrets
        .vrf_identifier(&config.vrf_key_path)
        .map_err(ValidatorSetupError::configuration)?;
    let store = config
        .secrets
        .build_keystore()
        .map_err(ValidatorSetupError::configuration)?;
    let keypair = generate_vrf_keypair().map_err(ValidatorSetupError::configuration)?;
    store
        .store(&identifier, &keypair)
        .map_err(ValidatorSetupError::configuration)?;

    let telemetry = probe_telemetry_endpoints(&config.rollout.telemetry, &options).await?;

    Ok(ValidatorSetupReport {
        secrets_backend: config.secrets.backend.clone(),
        identifier,
        public_key: vrf_public_key_to_hex(&keypair.public),
        telemetry,
    })
}

async fn probe_telemetry_endpoints(
    telemetry: &TelemetryConfig,
    options: &ValidatorSetupOptions,
) -> Result<ValidatorSetupTelemetryReport, ValidatorSetupError> {
    if !telemetry.enabled {
        return Ok(ValidatorSetupTelemetryReport {
            enabled: false,
            skipped: false,
            http_endpoint: None,
            http_status: None,
            auth_applied: false,
        });
    }

    let builder = TelemetryExporterBuilder::new(telemetry);
    let outcome = builder
        .build_metric_exporter()
        .map_err(ValidatorSetupError::configuration)?;
    if outcome.exporter.is_none() {
        return Err(ValidatorSetupError::configuration(
            "telemetry enabled but metrics exporter could not be constructed",
        ));
    }

    let endpoint = builder.http_endpoint().map(str::to_string).ok_or_else(|| {
        ValidatorSetupError::configuration("telemetry enabled but no HTTP endpoint configured")
    })?;
    let auth_token = telemetry_auth_token(telemetry);
    let auth_applied = auth_token.is_some();
    let client = telemetry_probe_client(telemetry, options.telemetry_probe_timeout)?;

    if options.skip_telemetry_probe {
        return Ok(ValidatorSetupTelemetryReport {
            enabled: true,
            skipped: true,
            http_endpoint: Some(endpoint),
            http_status: None,
            auth_applied,
        });
    }

    let mut request = client.get(endpoint.clone());
    if let Some(token) = auth_token.as_ref() {
        request = request.header("Authorization", token);
    }

    let response = request.send().await.map_err(ValidatorSetupError::network)?;
    let status = response.status();

    Ok(ValidatorSetupTelemetryReport {
        enabled: true,
        skipped: false,
        http_endpoint: Some(endpoint),
        http_status: Some(status),
        auth_applied,
    })
}

fn telemetry_probe_client(
    telemetry: &TelemetryConfig,
    timeout: Duration,
) -> Result<Client, ValidatorSetupError> {
    let mut builder = Client::builder().timeout(timeout);

    if let Some(tls) = telemetry.http_tls.as_ref().or(telemetry.grpc_tls.as_ref()) {
        if tls.insecure_skip_verify {
            builder = builder.danger_accept_invalid_certs(true);
        }

        if let Some(ca) = tls.ca_certificate.as_ref() {
            let pem = fs::read(ca).with_context(|| {
                format!("failed to read telemetry CA certificate {}", ca.display())
            });
            let pem = pem.map_err(ValidatorSetupError::configuration)?;
            let certificate = Certificate::from_pem(&pem)
                .context("failed to parse telemetry CA certificate")
                .map_err(ValidatorSetupError::configuration)?;
            builder = builder.add_root_certificate(certificate);
        }

        if let (Some(cert), Some(key)) = (
            tls.client_certificate.as_ref(),
            tls.client_private_key.as_ref(),
        ) {
            let mut identity_bytes = fs::read(cert).with_context(|| {
                format!(
                    "failed to read telemetry client certificate {}",
                    cert.display()
                )
            });
            let mut identity_bytes = identity_bytes.map_err(ValidatorSetupError::configuration)?;
            let key_bytes = fs::read(key)
                .with_context(|| format!("failed to read telemetry client key {}", key.display()));
            let key_bytes = key_bytes.map_err(ValidatorSetupError::configuration)?;
            identity_bytes.extend_from_slice(&key_bytes);
            let identity = Identity::from_pem(&identity_bytes)
                .context("failed to parse telemetry client identity")
                .map_err(ValidatorSetupError::configuration)?;
            builder = builder.identity(identity);
        }
    }

    builder
        .build()
        .context("failed to build telemetry probe client")
        .map_err(ValidatorSetupError::configuration)
}

fn telemetry_auth_token(telemetry: &TelemetryConfig) -> Option<String> {
    normalize_bearer_token(&telemetry.auth_token)
}

fn normalize_bearer_token(raw: &Option<String>) -> Option<String> {
    raw.as_ref()
        .map(|token| token.trim())
        .filter(|token| !token.is_empty())
        .map(|token| {
            if token.to_ascii_lowercase().starts_with("bearer ") {
                token.to_string()
            } else {
                format!("Bearer {token}")
            }
        })
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

    #[test]
    fn root_help_mentions_cleanup_runbook() {
        const CLEANUP_RUNBOOK: &str = "docs/mempool_cleanup.md";

        let mut command = RootCli::command();
        let mut help = Vec::new();

        command
            .write_long_help(&mut help)
            .expect("render root help output");

        let help = String::from_utf8(help).expect("UTF-8 help text");
        assert!(
            help.contains(CLEANUP_RUNBOOK),
            "help output should mention the cleanup runbook at {CLEANUP_RUNBOOK}"
        );
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
    let options = ValidatorSetupOptions {
        telemetry_probe_timeout: Duration::from_secs(command.telemetry_timeout.max(1)),
        skip_telemetry_probe: command.skip_telemetry_probe,
    };

    let report = validator_setup(&config, options)
        .await
        .map_err(|err| CliError::from(err.into_bootstrap_error()))?;

    let ValidatorSetupReport {
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
