use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{anyhow, Context, Result};
use clap::{Args, Parser, Subcommand};
use reqwest::Client;
use rpp_chain::crypto::{
    generate_vrf_keypair, vrf_public_key_to_hex, vrf_secret_key_to_hex, DynVrfKeyStore,
    VrfKeyIdentifier, VrfKeyStore,
};
use rpp_chain::runtime::config::{NodeConfig, SecretsBackendConfig, SecretsConfig};
use rpp_node::RuntimeMode;
use serde_json::Value;

const DEFAULT_VALIDATOR_CONFIG: &str = "config/validator.toml";

#[derive(Parser)]
#[command(author, version, about = "Run an rpp node", long_about = None)]
struct RootCli {
    #[command(subcommand)]
    command: RootCommand,
}

#[derive(Subcommand)]
enum RootCommand {
    /// Run the node runtime
    Node(rpp_node::RunArgs),
    /// Run the wallet runtime
    Wallet(rpp_node::RunArgs),
    /// Run the hybrid runtime (node + wallet)
    Hybrid(rpp_node::RunArgs),
    /// Validator runtime and tooling
    Validator(ValidatorArgs),
}

#[derive(Args)]
struct ValidatorArgs {
    #[command(flatten)]
    run: rpp_node::RunArgs,

    #[command(subcommand)]
    command: Option<ValidatorCommand>,
}

#[derive(Subcommand)]
enum ValidatorCommand {
    /// Manage VRF key material backed by the configured secrets backend
    Vrf(VrfCommand),
    /// Fetch validator telemetry snapshots from the RPC service
    Telemetry(TelemetryCommand),
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

#[tokio::main]
async fn main() -> Result<()> {
    let RootCli { command } = RootCli::parse();
    match command {
        RootCommand::Node(args) => run_runtime(RuntimeMode::Node, args).await,
        RootCommand::Wallet(args) => run_runtime(RuntimeMode::Wallet, args).await,
        RootCommand::Hybrid(args) => run_runtime(RuntimeMode::Hybrid, args).await,
        RootCommand::Validator(args) => match args.command {
            Some(ValidatorCommand::Vrf(command)) => handle_vrf_command(command),
            Some(ValidatorCommand::Telemetry(command)) => fetch_telemetry(command).await,
            None => run_runtime(RuntimeMode::Validator, args.run).await,
        },
    }
}

async fn run_runtime(mode: RuntimeMode, args: rpp_node::RunArgs) -> Result<()> {
    let options = args.into_bootstrap_options(mode);
    rpp_node::bootstrap(mode, options).await
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
