use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{bail, Context, Result};
use clap::{Args, Parser, Subcommand};
use ed25519_dalek::Keypair;
use rand_core::OsRng;
use reqwest::Url;
use serde::Deserialize;
use serde::Serialize;
use serde_json::Value;

use crate::rpc::dto::{
    BalanceResponse, BroadcastParams, BroadcastResponse, CreateTxParams, CreateTxResponse,
    DeriveAddressParams, DeriveAddressResponse, DraftInputDto, DraftOutputDto,
    DraftSpendModelDto, JsonRpcRequest, JsonRpcResponse, PolicyPreviewResponse,
    RescanParams, RescanResponse, SignTxParams, SignTxResponse, SyncStatusResponse,
    JSONRPC_VERSION,
};

const DEFAULT_RPC_ENDPOINT: &str = "http://127.0.0.1:9090";

#[derive(Debug, thiserror::Error)]
pub enum WalletCliError {
    #[error("invalid RPC endpoint: {0}")]
    InvalidEndpoint(String),
    #[error("wallet RPC transport error: {0}")]
    Transport(String),
    #[error("wallet RPC error ({code}): {message}")]
    RpcError { code: i32, message: String },
    #[error("wallet RPC returned an empty response")]
    EmptyResponse,
    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

impl From<reqwest::Error> for WalletCliError {
    fn from(value: reqwest::Error) -> Self {
        WalletCliError::Transport(value.to_string())
    }
}

impl From<serde_json::Error> for WalletCliError {
    fn from(value: serde_json::Error) -> Self {
        WalletCliError::Other(value.into())
    }
}

#[derive(Debug, Clone, Args)]
pub struct RpcOptions {
    /// URL of the wallet RPC endpoint (without the trailing /rpc path).
    #[arg(long, value_name = "URL", env = "RPP_WALLET_RPC_ENDPOINT", default_value = DEFAULT_RPC_ENDPOINT)]
    pub endpoint: String,
    /// Bearer token used to authenticate with the wallet RPC (if enabled).
    #[arg(long, value_name = "TOKEN", env = "RPP_WALLET_RPC_AUTH_TOKEN")]
    pub auth_token: Option<String>,
    /// Timeout for RPC requests in seconds.
    #[arg(long, value_name = "SECONDS", default_value = "30")]
    pub timeout: u64,
}

impl RpcOptions {
    fn rpc_url(&self) -> Result<Url, WalletCliError> {
        let mut url = Url::parse(&self.endpoint)
            .map_err(|err| WalletCliError::InvalidEndpoint(err.to_string()))?;
        let mut path = url.path().to_string();
        if path.is_empty() || path == "/" {
            url.set_path("/rpc");
        } else if !path.ends_with("/rpc") {
            if path.ends_with('/') {
                path.truncate(path.len() - 1);
            }
            path.push_str("/rpc");
            url.set_path(&path);
        }
        Ok(url)
    }
}

struct WalletRpcClient {
    inner: reqwest::Client,
    url: Url,
    auth_token: Option<String>,
}

impl WalletRpcClient {
    fn new(options: &RpcOptions) -> Result<Self, WalletCliError> {
        let timeout = Duration::from_secs(options.timeout);
        let client = reqwest::Client::builder()
            .timeout(timeout)
            .build()
            .map_err(|err| WalletCliError::Transport(err.to_string()))?;
        let url = options.rpc_url()?;
        Ok(Self {
            inner: client,
            url,
            auth_token: options.auth_token.clone(),
        })
    }

    async fn request<T: Serialize>(&self, method: &str, params: Option<T>) -> Result<Value, WalletCliError> {
        let payload = JsonRpcRequest {
            jsonrpc: Some(JSONRPC_VERSION.to_string()),
            id: Some(Value::from(1)),
            method: method.to_string(),
            params: params
                .map(|value| serde_json::to_value(value))
                .transpose()
                .map_err(WalletCliError::from)?,
        };

        let mut request = self.inner.post(self.url.clone()).json(&payload);
        if let Some(token) = &self.auth_token {
            request = request.bearer_auth(token);
        }

        let response = request.send().await?;
        if !response.status().is_success() {
            return Err(WalletCliError::Transport(format!(
                "HTTP status {} returned by wallet RPC",
                response.status()
            )));
        }

        let response: JsonRpcResponse = response.json().await?;
        if let Some(error) = response.error {
            return Err(WalletCliError::RpcError {
                code: error.code,
                message: error.message,
            });
        }

        response
            .result
            .ok_or(WalletCliError::EmptyResponse)
    }

    async fn get_balance(&self) -> Result<BalanceResponse, WalletCliError> {
        let value = self.request::<Value>("get_balance", None).await?;
        Ok(serde_json::from_value(value)?)
    }

    async fn derive_address(&self, change: bool) -> Result<DeriveAddressResponse, WalletCliError> {
        let params = DeriveAddressParams { change };
        let value = self.request("derive_address", Some(params)).await?;
        Ok(serde_json::from_value(value)?)
    }

    async fn policy_preview(&self) -> Result<PolicyPreviewResponse, WalletCliError> {
        let value = self.request::<Value>("policy_preview", None).await?;
        Ok(serde_json::from_value(value)?)
    }

    async fn create_tx(
        &self,
        params: &CreateTxParams,
    ) -> Result<CreateTxResponse, WalletCliError> {
        let value = self.request("create_tx", Some(params)).await?;
        Ok(serde_json::from_value(value)?)
    }

    async fn sign_tx(&self, draft_id: &str) -> Result<SignTxResponse, WalletCliError> {
        let params = SignTxParams {
            draft_id: draft_id.to_string(),
        };
        let value = self.request("sign_tx", Some(params)).await?;
        Ok(serde_json::from_value(value)?)
    }

    async fn broadcast(&self, draft_id: &str) -> Result<BroadcastResponse, WalletCliError> {
        let params = BroadcastParams {
            draft_id: draft_id.to_string(),
        };
        let value = self.request("broadcast", Some(params)).await?;
        Ok(serde_json::from_value(value)?)
    }

    async fn sync_status(&self) -> Result<SyncStatusResponse, WalletCliError> {
        let value = self.request::<Value>("sync_status", None).await?;
        Ok(serde_json::from_value(value)?)
    }

    async fn rescan(&self, from_height: u64) -> Result<RescanResponse, WalletCliError> {
        let params = RescanParams { from_height };
        let value = self.request("rescan", Some(params)).await?;
        Ok(serde_json::from_value(value)?)
    }
}

#[derive(Debug, Args)]
pub struct InitCommand {
    /// Override the keys path defined in the wallet configuration file.
    #[arg(long, value_name = "PATH")]
    pub keys_path: Option<PathBuf>,
    /// Override the wallet engine data directory.
    #[arg(long, value_name = "PATH")]
    pub data_dir: Option<PathBuf>,
    /// Override the wallet engine keystore path.
    #[arg(long, value_name = "PATH")]
    pub keystore_path: Option<PathBuf>,
    /// Overwrite existing key material if present.
    #[arg(long)]
    pub force: bool,
}

#[derive(Debug, Clone)]
pub struct InitContext {
    pub wallet_config: Option<PathBuf>,
    pub data_dir_override: Option<PathBuf>,
}

impl InitContext {
    pub fn new(wallet_config: Option<PathBuf>, data_dir_override: Option<PathBuf>) -> Self {
        Self {
            wallet_config,
            data_dir_override,
        }
    }
}

impl InitCommand {
    pub async fn execute(&self, context: &InitContext) -> Result<(), WalletCliError> {
        let mut paths = ConfigPaths::default();

        if let Some(path) = context.wallet_config.as_ref() {
            if path.exists() {
                let raw = fs::read_to_string(path)
                    .with_context(|| format!("failed to read wallet config at {}", path.display()))?;
                let file: WalletFile = toml::from_str(&raw)
                    .with_context(|| format!("failed to parse wallet config at {}", path.display()))?;
                paths = file.paths();
            }
        }

        if let Some(override_dir) = context.data_dir_override.as_ref() {
            paths.engine_data_dir = override_dir.clone();
        }

        if let Some(dir) = self.data_dir.as_ref() {
            paths.engine_data_dir = dir.clone();
        }

        if let Some(keystore) = self.keystore_path.as_ref() {
            paths.engine_keystore = keystore.clone();
        }

        if let Some(keys) = self.keys_path.as_ref() {
            paths.keys_path = keys.clone();
        }

        fs::create_dir_all(&paths.engine_data_dir)
            .with_context(|| format!("failed to create data directory at {}", paths.engine_data_dir.display()))?;

        if let Some(parent) = paths.engine_keystore.parent() {
            fs::create_dir_all(parent).with_context(|| {
                format!(
                    "failed to create keystore directory at {}",
                    parent.display()
                )
            })?;
        }

        if let Some(parent) = paths.keys_path.parent() {
            fs::create_dir_all(parent).with_context(|| {
                format!(
                    "failed to create keys directory at {}",
                    parent.display()
                )
            })?;
        }

        if paths.keys_path.exists() && !self.force {
            bail!("wallet key already exists at {} — rerun with --force to overwrite", paths.keys_path.display());
        }

        let keypair = Keypair::generate(&mut OsRng);
        persist_keypair(&paths.keys_path, &keypair)
            .with_context(|| format!("failed to persist wallet key at {}", paths.keys_path.display()))?;

        println!("Wallet initialised successfully\n");
        println!("  Data directory : {}", paths.engine_data_dir.display());
        println!("  Keystore path   : {}", paths.engine_keystore.display());
        println!("  Keys path       : {}", paths.keys_path.display());
        println!("  Public key      : {}", hex::encode(keypair.public.to_bytes()));

        Ok(())
    }
}

#[derive(Debug, Args)]
pub struct SyncCommand {
    #[command(flatten)]
    pub rpc: RpcOptions,
}

impl SyncCommand {
    pub async fn execute(&self) -> Result<(), WalletCliError> {
        let client = WalletRpcClient::new(&self.rpc)?;
        let status = client.sync_status().await?;
        println!("Synchronisation status\n");
        println!("  Syncing           : {}", format_bool(status.syncing));
        if let Some(height) = status.latest_height {
            println!("  Latest height     : {height}");
        }
        if let Some(range) = status.pending_range {
            println!("  Pending range     : {} → {}", range.0, range.1);
        }
        if let Some(scripthashes) = status.scanned_scripthashes {
            println!("  Scanned scripts   : {scripthashes}");
        }
        if let Some(error) = status.last_error {
            println!("  Last error        : {error}");
        }
        Ok(())
    }
}

#[derive(Debug, Args)]
pub struct AddrCommand {
    #[command(subcommand)]
    pub command: AddrSubcommand,
}

#[derive(Debug, Subcommand)]
pub enum AddrSubcommand {
    /// Derive a new wallet address.
    New(AddrNewCommand),
}

#[derive(Debug, Args)]
pub struct AddrNewCommand {
    #[command(flatten)]
    pub rpc: RpcOptions,
    /// Derive a change (internal) address instead of an external receive address.
    #[arg(long)]
    pub change: bool,
}

impl AddrNewCommand {
    pub async fn execute(&self) -> Result<(), WalletCliError> {
        let client = WalletRpcClient::new(&self.rpc)?;
        let response = client.derive_address(self.change).await?;
        println!("Generated address\n");
        println!("  Kind   : {}", if self.change { "change" } else { "external" });
        println!("  Address: {}", response.address);
        Ok(())
    }
}

#[derive(Debug, Args)]
pub struct BalanceCommand {
    #[command(flatten)]
    pub rpc: RpcOptions,
}

impl BalanceCommand {
    pub async fn execute(&self) -> Result<(), WalletCliError> {
        let client = WalletRpcClient::new(&self.rpc)?;
        let balance = client.get_balance().await?;
        println!("Wallet balance\n");
        println!("  Confirmed : {}", format_amount(balance.confirmed));
        println!("  Pending   : {}", format_amount(balance.pending));
        println!("  Total     : {}", format_amount(balance.total));
        Ok(())
    }
}

#[derive(Debug, Args)]
pub struct SendCommand {
    #[command(subcommand)]
    pub command: SendSubcommand,
}

#[derive(Debug, Subcommand)]
pub enum SendSubcommand {
    /// Display wallet policy guidance applied during transaction construction.
    Preview(SendPreviewCommand),
    /// Create a draft transaction and display the resulting spend model.
    Create(SendCreateCommand),
    /// Sign the specified draft transaction using the configured backend.
    Sign(SendSignCommand),
    /// Broadcast a signed draft transaction to the execution node.
    Broadcast(SendBroadcastCommand),
}

#[derive(Debug, Args)]
pub struct SendPreviewCommand {
    #[command(flatten)]
    pub rpc: RpcOptions,
}

impl SendPreviewCommand {
    pub async fn execute(&self) -> Result<(), WalletCliError> {
        let client = WalletRpcClient::new(&self.rpc)?;
        let preview = client.policy_preview().await?;
        println!("Wallet policy preview\n");
        println!("  Min confirmations : {}", preview.min_confirmations);
        println!("  Dust limit        : {}", format_amount(preview.dust_limit));
        Ok(())
    }
}

#[derive(Debug, Args)]
pub struct SendCreateCommand {
    #[command(flatten)]
    pub rpc: RpcOptions,
    /// Recipient address for the transaction output.
    #[arg(long)]
    pub to: String,
    /// Amount to transfer in satoshis.
    #[arg(long)]
    pub amount: u128,
    /// Optional fee rate override (satoshis per virtual byte).
    #[arg(long, value_name = "SAT/VBYTE")]
    pub fee_rate: Option<u64>,
}

impl SendCreateCommand {
    pub async fn execute(&self) -> Result<(), WalletCliError> {
        let client = WalletRpcClient::new(&self.rpc)?;
        let params = CreateTxParams {
            to: self.to.clone(),
            amount: self.amount,
            fee_rate: self.fee_rate,
        };
        let draft = client.create_tx(&params).await?;
        println!("Draft transaction created\n");
        render_draft_summary(&draft);
        Ok(())
    }
}

#[derive(Debug, Args)]
pub struct SendSignCommand {
    #[command(flatten)]
    pub rpc: RpcOptions,
    /// Identifier returned by the `send create` command.
    #[arg(long)]
    pub draft_id: String,
}

impl SendSignCommand {
    pub async fn execute(&self) -> Result<(), WalletCliError> {
        let client = WalletRpcClient::new(&self.rpc)?;
        let result = client.sign_tx(&self.draft_id).await?;
        println!("Draft signed successfully\n");
        println!("  Draft ID      : {}", result.draft_id);
        println!("  Backend       : {}", result.backend);
        println!("  Witness bytes : {}", result.witness_bytes);
        println!("  Proof generated: {}", format_bool(result.proof_generated));
        if let Some(size) = result.proof_size {
            println!("  Proof size    : {} bytes", size);
        }
        println!("  Duration      : {} ms", result.duration_ms);
        Ok(())
    }
}

#[derive(Debug, Args)]
pub struct SendBroadcastCommand {
    #[command(flatten)]
    pub rpc: RpcOptions,
    /// Identifier returned by the `send create` command.
    #[arg(long)]
    pub draft_id: String,
}

impl SendBroadcastCommand {
    pub async fn execute(&self) -> Result<(), WalletCliError> {
        let client = WalletRpcClient::new(&self.rpc)?;
        let response = client.broadcast(&self.draft_id).await?;
        println!("Broadcast result\n");
        println!("  Draft ID : {}", response.draft_id);
        println!("  Accepted : {}", format_bool(response.accepted));
        Ok(())
    }
}

#[derive(Debug, Args)]
pub struct RescanCommand {
    #[command(flatten)]
    pub rpc: RpcOptions,
    /// Block height to start rescanning from.
    #[arg(long)]
    pub from_height: u64,
}

impl RescanCommand {
    pub async fn execute(&self) -> Result<(), WalletCliError> {
        let client = WalletRpcClient::new(&self.rpc)?;
        let response = client.rescan(self.from_height).await?;
        println!("Rescan request submitted\n");
        println!("  Scheduled : {}", format_bool(response.scheduled));
        Ok(())
    }
}

#[derive(Debug, Subcommand)]
pub enum WalletCommand {
    /// Initialise wallet directories and key material.
    Init(InitCommand),
    /// Inspect the synchronisation status of the wallet runtime.
    Sync(SyncCommand),
    /// Derive wallet addresses.
    Addr(AddrCommand),
    /// Display wallet balance information.
    Balance(BalanceCommand),
    /// Manage transaction drafts.
    Send(SendCommand),
    /// Trigger a historical rescan.
    Rescan(RescanCommand),
}

impl WalletCommand {
    pub async fn execute(
        &self,
        init_context: &InitContext,
    ) -> Result<(), WalletCliError> {
        match self {
            WalletCommand::Init(cmd) => cmd.execute(init_context).await,
            WalletCommand::Sync(cmd) => cmd.execute().await,
            WalletCommand::Addr(AddrCommand { command }) => match command {
                AddrSubcommand::New(cmd) => cmd.execute().await,
            },
            WalletCommand::Balance(cmd) => cmd.execute().await,
            WalletCommand::Send(SendCommand { command }) => match command {
                SendSubcommand::Preview(cmd) => cmd.execute().await,
                SendSubcommand::Create(cmd) => cmd.execute().await,
                SendSubcommand::Sign(cmd) => cmd.execute().await,
                SendSubcommand::Broadcast(cmd) => cmd.execute().await,
            },
            WalletCommand::Rescan(cmd) => cmd.execute().await,
        }
    }
}

fn render_draft_summary(draft: &CreateTxResponse) {
    println!("  Draft ID      : {}", draft.draft_id);
    println!("  Fee rate      : {} sat/vB", draft.fee_rate);
    println!("  Fee           : {}", format_amount(draft.fee));
    println!("  Total inputs  : {}", format_amount(draft.total_input_value));
    println!("  Total outputs : {}", format_amount(draft.total_output_value));
    println!("  Spend model   : {}", format_spend_model(&draft.spend_model));

    if !draft.inputs.is_empty() {
        println!("\n  Inputs:");
        println!("    {:<68} {:>12} {:>14}", "Outpoint", "Value", "Confirmations");
        for DraftInputDto {
            txid,
            index,
            value,
            confirmations,
        } in &draft.inputs
        {
            println!(
                "    {:<68} {:>12} {:>14}",
                format!("{}:{}", &txid, index),
                format_amount(*value),
                confirmations
            );
        }
    }

    if !draft.outputs.is_empty() {
        println!("\n  Outputs:");
        println!("    {:<50} {:>12} {:>10}", "Address", "Value", "Change");
        for DraftOutputDto {
            address,
            value,
            change,
        } in &draft.outputs
        {
            println!(
                "    {:<50} {:>12} {:>10}",
                address,
                format_amount(*value),
                format_bool(*change)
            );
        }
    }
}

fn format_spend_model(model: &DraftSpendModelDto) -> &'static str {
    match model {
        DraftSpendModelDto::Exact { .. } => "exact",
        DraftSpendModelDto::Sweep => "sweep",
    }
}

fn format_amount(value: u128) -> String {
    let mut string = value.to_string();
    let mut output = String::with_capacity(string.len() + string.len() / 3);
    while string.len() > 3 {
        let remainder = string.split_off(string.len() - 3);
        output = format!(",{remainder}{output}");
    }
    format!("{string}{output} sats")
}

fn format_bool(value: bool) -> &'static str {
    if value {
        "yes"
    } else {
        "no"
    }
}

fn persist_keypair(path: &Path, keypair: &Keypair) -> Result<()> {
    #[derive(Serialize)]
    struct StoredKeypair<'a> {
        public_key: String,
        secret_key: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        signature: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        message: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        format: Option<&'a str>,
    }

    let stored = StoredKeypair {
        public_key: hex::encode(keypair.public.to_bytes()),
        secret_key: hex::encode(keypair.secret.to_bytes()),
        signature: None,
        message: None,
        format: Some("ed25519"),
    };
    let encoded = toml::to_string_pretty(&stored)?;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(path, encoded)?;
    Ok(())
}

#[derive(Debug, Deserialize)]
struct WalletFile {
    #[serde(default)]
    wallet: WalletSection,
}

impl WalletFile {
    fn paths(self) -> ConfigPaths {
        ConfigPaths {
            keys_path: self.wallet.keys.key_path,
            engine_data_dir: self.wallet.engine.data_dir,
            engine_keystore: self.wallet.engine.keystore_path,
        }
    }
}

#[derive(Debug, Deserialize, Default)]
struct WalletSection {
    #[serde(default)]
    keys: WalletKeysSection,
    #[serde(default)]
    engine: WalletEngineSection,
}

#[derive(Debug, Deserialize)]
struct WalletKeysSection {
    #[serde(default = "default_keys_path")]
    key_path: PathBuf,
}

impl Default for WalletKeysSection {
    fn default() -> Self {
        Self {
            key_path: default_keys_path(),
        }
    }
}

#[derive(Debug, Deserialize)]
struct WalletEngineSection {
    #[serde(default = "default_engine_data_dir")]
    data_dir: PathBuf,
    #[serde(default = "default_engine_keystore")]
    keystore_path: PathBuf,
}

impl Default for WalletEngineSection {
    fn default() -> Self {
        Self {
            data_dir: default_engine_data_dir(),
            keystore_path: default_engine_keystore(),
        }
    }
}

#[derive(Debug, Clone)]
struct ConfigPaths {
    keys_path: PathBuf,
    engine_data_dir: PathBuf,
    engine_keystore: PathBuf,
}

impl Default for ConfigPaths {
    fn default() -> Self {
        Self {
            keys_path: default_keys_path(),
            engine_data_dir: default_engine_data_dir(),
            engine_keystore: default_engine_keystore(),
        }
    }
}

fn default_keys_path() -> PathBuf {
    PathBuf::from("./keys/wallet.toml")
}

fn default_engine_data_dir() -> PathBuf {
    PathBuf::from("./data/wallet")
}

fn default_engine_keystore() -> PathBuf {
    PathBuf::from("./data/wallet/keystore.toml")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Parser)]
    struct TestCli {
        #[command(subcommand)]
        command: WalletCommand,
    }

    #[test]
    fn parses_balance_command() {
        let cli = TestCli::parse_from([
            "wallet",
            "balance",
            "--endpoint",
            "http://localhost:9000",
        ]);
        match cli.command {
            WalletCommand::Balance(cmd) => {
                assert_eq!(cmd.rpc.endpoint, "http://localhost:9000");
            }
            other => panic!("parsed unexpected command: {other:?}"),
        }
    }

    #[test]
    fn parses_send_create_command() {
        let cli = TestCli::parse_from([
            "wallet",
            "send",
            "create",
            "--endpoint",
            "https://wallet.test:9443/api",
            "--to",
            "wallet1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh",
            "--amount",
            "1500",
            "--fee-rate",
            "5",
        ]);
        match cli.command {
            WalletCommand::Send(SendCommand {
                command: SendSubcommand::Create(cmd),
            }) => {
                assert_eq!(cmd.rpc.endpoint, "https://wallet.test:9443/api");
                assert_eq!(cmd.to, "wallet1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh");
                assert_eq!(cmd.amount, 1_500);
                assert_eq!(cmd.fee_rate, Some(5));
            }
            other => panic!("parsed unexpected command: {other:?}"),
        }
    }

    #[test]
    fn formats_draft_summary() {
        let draft = CreateTxResponse {
            draft_id: "draft-1".to_string(),
            fee_rate: 5,
            fee: 250,
            total_input_value: 5_000,
            total_output_value: 4_750,
            spend_model: DraftSpendModelDto::Exact { amount: 4_750 },
            inputs: vec![DraftInputDto {
                txid: "abcd".to_string(),
                index: 1,
                value: 5_000,
                confirmations: 12,
            }],
            outputs: vec![DraftOutputDto {
                address: "wallet1...".to_string(),
                value: 4_750,
                change: false,
            }],
        };

        // Ensure formatting function does not panic and includes key fields.
        render_draft_summary(&draft);
    }

    #[test]
    fn format_amount_inserts_separators() {
        assert_eq!(format_amount(0), "0 sats");
        assert_eq!(format_amount(123), "123 sats");
        assert_eq!(format_amount(12_345), "12,345 sats");
        assert_eq!(format_amount(1_234_567), "1,234,567 sats");
    }

    #[test]
    fn rpc_url_appends_rpc_path() {
        let options = RpcOptions {
            endpoint: "https://wallet.test:9443/api".to_string(),
            auth_token: None,
            timeout: 30,
        };
        let url = options.rpc_url().expect("rpc url");
        assert_eq!(url.as_str(), "https://wallet.test:9443/api/rpc");

        let options = RpcOptions {
            endpoint: "http://127.0.0.1:9090/".to_string(),
            auth_token: None,
            timeout: 15,
        };
        let url = options.rpc_url().expect("rpc url trailing slash");
        assert_eq!(url.as_str(), "http://127.0.0.1:9090/rpc");
    }
}
