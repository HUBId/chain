use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use clap::{Args, Parser, Subcommand};
use reqwest::Client;
use rpp_chain::crypto::{
    generate_vrf_keypair, load_or_generate_keypair, vrf_public_key_to_hex, vrf_secret_key_to_hex,
    DynVrfKeyStore, VrfKeyIdentifier, VrfKeyStore, VrfKeypair,
};
use rpp_chain::runtime::config::{NodeConfig, SecretsBackendConfig, SecretsConfig, WalletConfig};
use rpp_chain::runtime::RuntimeMetrics;
use rpp_chain::storage::Storage;
use rpp_chain::wallet::Wallet;
use rpp_node::{BootstrapError, RuntimeMode};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::task;

const DEFAULT_VALIDATOR_CONFIG: &str = "config/validator.toml";
const DEFAULT_WALLET_CONFIG: &str = "config/wallet.toml";

#[derive(Parser)]
#[command(
    author,
    version,
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
    options: rpp_node::RuntimeOptions,
}

#[derive(Args)]
struct ValidatorArgs {
    #[command(flatten)]
    runtime: rpp_node::RuntimeOptions,

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

#[tokio::main]
async fn main() -> Result<()> {
    let RootCli { command } = RootCli::parse();
    match command {
        RootCommand::Node(RuntimeCommand { options }) => {
            handle_runtime(run_runtime(RuntimeMode::Node, options).await)
        }
        RootCommand::Wallet(RuntimeCommand { options }) => {
            handle_runtime(run_runtime(RuntimeMode::Wallet, options).await)
        }
        RootCommand::Hybrid(RuntimeCommand { options }) => {
            handle_runtime(run_runtime(RuntimeMode::Hybrid, options).await)
        }
        RootCommand::Validator(args) => match args.command {
            Some(ValidatorCommand::Vrf(command)) => handle_vrf_command(command),
            Some(ValidatorCommand::Telemetry(command)) => fetch_telemetry(command).await,
            Some(ValidatorCommand::Uptime(command)) => handle_uptime_command(command).await,
            Some(ValidatorCommand::Setup(command)) => run_validator_setup(command).await,
            Some(ValidatorCommand::Snapshot(command)) => handle_snapshot_command(command).await,
            None => handle_runtime(run_runtime(RuntimeMode::Validator, args.runtime).await),
        },
    }
}

async fn run_runtime(
    mode: RuntimeMode,
    options: rpp_node::RuntimeOptions,
) -> rpp_node::BootstrapResult<()> {
    rpp_node::ensure_prover_backend(mode)?;
    rpp_node::run(mode, options).await
}

fn handle_runtime(result: rpp_node::BootstrapResult<()>) -> Result<()> {
    match result {
        Ok(()) => Ok(()),
        Err(err) => exit_with_bootstrap_error(err),
    }
}

fn exit_with_bootstrap_error(err: BootstrapError) -> ! {
    eprintln!("{err}");
    std::process::exit(err.exit_code());
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
    }
}

struct SnapshotRpcClient {
    client: Client,
    base_url: String,
    auth_token: Option<String>,
}

#[derive(Debug, Deserialize)]
struct SnapshotStreamStatusResponse {
    session: u64,
    peer: String,
    root: String,
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

#[derive(Serialize)]
struct StartSnapshotStreamRequest<'a> {
    peer: &'a str,
    chunk_size: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    resume: Option<ResumeMarker>,
}

#[derive(Serialize)]
struct ResumeMarker {
    session: u64,
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

fn print_snapshot_status(label: &str, status: &SnapshotStreamStatusResponse) {
    println!("{label}:");
    println!("  session: {}", status.session);
    println!("  peer: {}", status.peer);
    println!("  root: {}", status.root);
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

async fn run_validator_setup(command: ValidatorSetupCommand) -> Result<()> {
    let config = load_validator_config(&command.config.config)?;
    let options = rpp_node::ValidatorSetupOptions {
        telemetry_probe_timeout: Duration::from_secs(command.telemetry_timeout.max(1)),
        skip_telemetry_probe: command.skip_telemetry_probe,
    };

    let report = match rpp_node::validator_setup(&config, options).await {
        Ok(report) => report,
        Err(err) => exit_with_bootstrap_error(err.into_bootstrap_error()),
    };

    let rpp_node::ValidatorSetupReport {
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
