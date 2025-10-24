use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, anyhow};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use clap::{Args, Parser, Subcommand};
use reqwest::{Client, Response};
use rpp_chain::crypto::{
    DynVrfKeyStore, VrfKeyIdentifier, VrfKeyStore, generate_vrf_keypair, vrf_public_key_to_hex,
    vrf_secret_key_to_hex,
};
use rpp_chain::runtime::config::{NodeConfig, SecretsBackendConfig, SecretsConfig};
use serde::Deserialize;
use serde_json::Value;

const DEFAULT_VALIDATOR_CONFIG: &str = "config/validator.toml";

#[derive(Parser)]
#[command(author, version, about = "Run an rpp node", long_about = None)]
struct RootCli {
    #[command(flatten)]
    run: rpp_node::Cli,

    #[command(subcommand)]
    command: Option<RootCommand>,
}

#[derive(Subcommand)]
enum RootCommand {
    Validator(ValidatorArgs),
    LightClient(LightClientArgs),
}

#[derive(Args)]
struct ValidatorArgs {
    #[command(subcommand)]
    command: ValidatorCommand,
}

#[derive(Args)]
struct LightClientArgs {
    #[command(subcommand)]
    command: LightClientCommand,
}

#[derive(Subcommand)]
enum ValidatorCommand {
    /// Manage VRF key material backed by the configured secrets backend
    Vrf(VrfCommand),
    /// Fetch validator telemetry snapshots from the RPC service
    Telemetry(TelemetryCommand),
}

#[derive(Subcommand)]
enum LightClientCommand {
    /// Follow verified light-client heads from the RPC service
    HeadFollow(HeadFollowCommand),
    /// Fetch a state-sync chunk by its identifier
    FetchChunk(FetchChunkCommand),
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
    #[command(flatten)]
    rpc: RpcArgs,

    /// Pretty-print the JSON response
    #[arg(long, default_value_t = false)]
    pretty: bool,
}

#[derive(Args, Clone)]
struct RpcArgs {
    /// Base URL of the validator RPC endpoint
    #[arg(long, value_name = "URL", default_value = "http://127.0.0.1:7070")]
    rpc_url: String,

    /// Optional bearer token for secured RPC deployments
    #[arg(long)]
    auth_token: Option<String>,
}

#[derive(Args, Clone)]
struct HeadFollowCommand {
    #[command(flatten)]
    rpc: RpcArgs,

    /// Pretty-print each light-client head
    #[arg(long, default_value_t = false, conflicts_with = "minimal")]
    pretty: bool,

    /// Emit a compact summary of each head
    #[arg(long, default_value_t = false, conflicts_with = "pretty")]
    minimal: bool,
}

#[derive(Args, Clone)]
struct FetchChunkCommand {
    #[command(flatten)]
    rpc: RpcArgs,

    /// Identifier of the chunk to retrieve
    #[arg(value_name = "ID")]
    id: u32,

    /// Pretty-print the JSON response
    #[arg(long, default_value_t = false)]
    pretty: bool,

    /// Optional path to write the raw chunk payload bytes
    #[arg(long, value_name = "PATH")]
    output: Option<PathBuf>,
}

#[tokio::main]
async fn main() -> Result<()> {
    let RootCli { run, command } = RootCli::parse();
    match command {
        Some(RootCommand::Validator(args)) => match args.command {
            ValidatorCommand::Vrf(command) => handle_vrf_command(command),
            ValidatorCommand::Telemetry(command) => fetch_telemetry(command).await,
        },
        Some(RootCommand::LightClient(args)) => match args.command {
            LightClientCommand::HeadFollow(command) => follow_light_client_heads(command).await,
            LightClientCommand::FetchChunk(command) => fetch_chunk(command).await,
        },
        None => rpp_node::run(run).await,
    }
}

fn handle_vrf_command(command: VrfCommand) -> Result<()> {
    match command {
        VrfCommand::Rotate(args) => rotate_vrf_key(&args.config),
        VrfCommand::Inspect(args) => inspect_vrf_key(&args.config),
        VrfCommand::Export(args) => export_vrf_key(&args.config, args.output.as_ref()),
    }
}

fn rotate_vrf_key(args: &ValidatorConfigArgs) -> Result<()> {
    let (secrets, identifier, store) = prepare_vrf_store(&args.config)?;
    let keypair = generate_vrf_keypair().map_err(|err| anyhow!(err))?;
    store
        .store(&identifier, &keypair)
        .map_err(|err| anyhow!(err))?;

    println!(
        "VRF key rotated; backend={} location={} public_key={}",
        backend_name(&secrets),
        format_identifier(&identifier),
        vrf_public_key_to_hex(&keypair.public)
    );
    Ok(())
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
    let rpc = RpcClient::new(&command.rpc).context("failed to build telemetry HTTP client")?;
    let response = rpc
        .get("/validator/telemetry")
        .send()
        .await
        .context("failed to query validator telemetry")?;

    let (status, body) = read_response_body(response)
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

async fn follow_light_client_heads(command: HeadFollowCommand) -> Result<()> {
    let rpc = RpcClient::new(&command.rpc).context("failed to build light-client HTTP client")?;
    let mut response = rpc
        .get("/state-sync/head")
        .header("accept", "text/event-stream")
        .send()
        .await
        .context("failed to connect to light-client head stream")?;

    let status = response.status();
    if !status.is_success() {
        let (_, body) = read_response_body(response)
            .await
            .context("failed to decode light-client head error response")?;
        anyhow::bail!("RPC returned {}: {}", status, body.trim());
    }

    let mut buffer = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .context("failed to read light-client head stream")?
    {
        buffer.extend_from_slice(&chunk);
        while let Some(event) = next_sse_event(&mut buffer)? {
            if let Some(data) = extract_sse_data(&event) {
                let value: Value =
                    serde_json::from_str(&data).context("invalid light-client head payload")?;
                if command.minimal {
                    let summary: LightHeadSummary = serde_json::from_value(value.clone())
                        .context("failed to parse light-client head summary")?;
                    println!("{} {}", summary.height, summary.hash);
                } else if command.pretty {
                    println!("{}", serde_json::to_string_pretty(&value)?);
                } else {
                    println!("{}", serde_json::to_string(&value)?);
                }
            }
        }
    }
    Ok(())
}

async fn fetch_chunk(command: FetchChunkCommand) -> Result<()> {
    let rpc = RpcClient::new(&command.rpc).context("failed to build light-client HTTP client")?;
    let response = rpc
        .get(&format!("/state-sync/chunk/{}", command.id))
        .send()
        .await
        .context("failed to fetch state-sync chunk")?;

    let (status, body) = read_response_body(response)
        .await
        .context("failed to decode state-sync chunk response")?;
    if !status.is_success() {
        anyhow::bail!("RPC returned {}: {}", status, body.trim());
    }

    let value: Value = serde_json::from_str(&body).context("invalid state-sync chunk payload")?;
    if let Some(path) = command.output.as_ref() {
        let chunk: SnapshotChunkResponse = serde_json::from_value(value.clone())
            .context("failed to parse state-sync chunk response")?;
        let data = BASE64_STANDARD
            .decode(chunk.payload.as_bytes())
            .context("failed to decode chunk payload")?;
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).with_context(|| {
                format!("failed to create output directory {}", parent.display())
            })?;
        }
        fs::write(path, data).with_context(|| {
            format!(
                "failed to write chunk {} payload to {}",
                chunk.index,
                path.display()
            )
        })?;
        println!(
            "chunk {} ({} bytes) written to {}",
            chunk.index,
            chunk.length,
            path.display()
        );
    } else if command.pretty {
        println!("{}", serde_json::to_string_pretty(&value)?);
    } else {
        println!("{}", body);
    }

    Ok(())
}

#[derive(Deserialize)]
struct SnapshotChunkResponse {
    index: u32,
    length: u32,
    payload: String,
}

#[derive(Deserialize)]
struct LightHeadSummary {
    height: u64,
    hash: String,
}

struct RpcClient {
    client: Client,
    base_url: String,
    auth_token: Option<String>,
}

impl RpcClient {
    fn new(args: &RpcArgs) -> Result<Self> {
        let client = Client::builder()
            .build()
            .context("failed to build RPC HTTP client")?;
        Ok(Self {
            client,
            base_url: args.rpc_url.trim_end_matches('/').to_string(),
            auth_token: args.auth_token.clone(),
        })
    }

    fn get(&self, path: &str) -> reqwest::RequestBuilder {
        let url = if path.starts_with('/') {
            format!("{}{}", self.base_url, path)
        } else {
            format!("{}/{}", self.base_url, path)
        };
        let mut request = self.client.get(url);
        if let Some(token) = self.auth_token.as_ref() {
            request = request.bearer_auth(token);
        }
        request
    }
}

async fn read_response_body(response: Response) -> Result<(reqwest::StatusCode, String)> {
    let status = response.status();
    let body = response.text().await?;
    Ok((status, body))
}

fn next_sse_event(buffer: &mut Vec<u8>) -> Result<Option<String>> {
    if let Some((event, advance)) =
        extract_event_bytes(buffer.as_slice(), b"\r\n\r\n").or_else(|| {
            extract_event_bytes(buffer.as_slice(), b"\n\n")
                .or_else(|| extract_event_bytes(buffer.as_slice(), b"\r\r"))
        })
    {
        buffer.drain(..advance);
        return Ok(Some(
            String::from_utf8(event).context("invalid UTF-8 in SSE stream")?,
        ));
    }
    Ok(None)
}

fn extract_event_bytes(buffer: &[u8], delimiter: &[u8]) -> Option<(Vec<u8>, usize)> {
    if delimiter.len() > buffer.len() {
        return None;
    }
    buffer
        .windows(delimiter.len())
        .position(|window| window == delimiter)
        .map(|index| {
            let end = index + delimiter.len();
            (buffer[..index].to_vec(), end)
        })
}

fn extract_sse_data(event: &str) -> Option<String> {
    let mut lines = Vec::new();
    for line in event.lines() {
        if let Some(data) = line.strip_prefix("data:") {
            lines.push(data.trim_start());
        }
    }
    if lines.is_empty() {
        None
    } else {
        Some(lines.join("\n"))
    }
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
    match &secrets.backend {
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
