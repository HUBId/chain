use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use argon2::{Algorithm, Argon2, Params, ParamsBuilder, PasswordHasher, Version};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use chacha20poly1305::{aead::Aead, ChaCha20Poly1305, Key, KeyInit, Nonce};
use clap::{Args, Parser, Subcommand};
use ed25519_dalek::SigningKey;
use rand_core::{OsRng, RngCore};
use reqwest::Identity;
use rpassword::prompt_password;
use serde::Deserialize;
use serde::Serialize;
use serde_json::Value;
use zeroize::{Zeroize, Zeroizing};

use rpp::runtime::config::{WalletConfig as RuntimeWalletConfig, WalletRpcSecurityBinding};
use rpp::runtime::wallet::rpc::{
    WalletIdentity, WalletRbacStore, WalletRole, WalletRoleSet, WalletSecurityBinding,
    WalletSecurityPaths,
};
use rpp::runtime::RuntimeMode;

use crate::multisig::{Cosigner, MultisigScope};
use crate::rpc::client::{WalletRpcClient, WalletRpcClientError};
use crate::rpc::dto::{
    BackupExportParams, BackupExportResponse, BackupImportParams, BackupImportResponse,
    BackupMetadataDto, BackupValidateParams, BackupValidateResponse, BackupValidationModeDto,
    BroadcastRawParams, BroadcastRawResponse, CosignerDto, CreateTxParams, CreateTxResponse,
    DraftInputDto, DraftOutputDto, DraftSpendModelDto, FeeCongestionDto, FeeEstimateSourceDto,
    GetCosignersResponse, GetMultisigScopeResponse, MultisigDraftMetadataDto, MultisigScopeDto,
    PendingLockDto, RescanParams, SetCosignersResponse, SetMultisigScopeResponse, SetPolicyParams,
    SyncModeDto, SyncStatusResponse, WatchOnlyEnableParams, WatchOnlyStatusResponse,
};
#[cfg(feature = "wallet_hw")]
use crate::rpc::dto::{DerivationPathDto, HardwareSignParams};
use crate::rpc::error::WalletRpcErrorCode;

const DEFAULT_RPC_ENDPOINT: &str = "http://127.0.0.1:9090";

#[derive(Debug, thiserror::Error)]
pub enum WalletCliError {
    #[error("invalid RPC endpoint: {0}")]
    InvalidEndpoint(String),
    #[error("wallet RPC transport error: {0}")]
    Transport(String),
    #[error("wallet RPC error [{code}]: {friendly}")]
    RpcError {
        code: WalletRpcErrorCode,
        friendly: String,
        message: String,
        json_code: i32,
        details: Option<Value>,
    },
    #[error("wallet RPC returned an empty response")]
    EmptyResponse,
    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

fn friendly_message(
    code: &WalletRpcErrorCode,
    rpc_message: &str,
    details: Option<&Value>,
) -> String {
    match code {
        WalletRpcErrorCode::WalletPolicyViolation => {
            if let Some(count) = details
                .and_then(|value| value.get("violations"))
                .and_then(|value| value.as_array())
                .map(|array| array.len())
            {
                format!("Draft violates {count} wallet policy rule(s); review the violation list.")
            } else {
                "Draft violates wallet policy rules.".to_string()
            }
        }
        WalletRpcErrorCode::FeeTooLow => {
            if let Some(details) = details.and_then(|value| value.as_object()) {
                if let Some(required) = details.get("required") {
                    return format!(
                        "Fee rate too low (requires at least {} sats/vB).",
                        value_to_string(required)
                    );
                }
                if let Some(minimum) = details.get("minimum") {
                    return format!(
                        "Fee rate too low (minimum is {} sats/vB).",
                        value_to_string(minimum)
                    );
                }
            }
            rpc_message.to_string()
        }
        WalletRpcErrorCode::PendingLockConflict => {
            if let Some(details) = details.and_then(|value| value.as_object()) {
                if let (Some(required), Some(total)) = (
                    details.get("required"),
                    details
                        .get("total_available")
                        .or_else(|| details.get("available")),
                ) {
                    return format!(
                        "Insufficient unlocked funds (required {}, available {}).",
                        value_to_string(required),
                        value_to_string(total)
                    );
                }
            }
            "Wallet inputs are locked by another draft; release them or lower the amount."
                .to_string()
        }
        WalletRpcErrorCode::ProverTimeout => {
            if let Some(timeout) = details.and_then(|value| value.get("timeout_secs")) {
                return format!(
                    "Wallet prover timed out after {} seconds.",
                    value_to_string(timeout)
                );
            }
            rpc_message.to_string()
        }
        WalletRpcErrorCode::RescanInProgress => {
            if let Some(details) = details.and_then(|value| value.as_object()) {
                let requested = details
                    .get("requested")
                    .map(value_to_string)
                    .unwrap_or_else(|| "unknown".to_string());
                let pending = details.get("pending_from").and_then(|value| {
                    if value.is_null() {
                        None
                    } else {
                        Some(value_to_string(value))
                    }
                });
                if let Some(pending) = pending {
                    return format!(
                        "A rescan from height {pending} is already scheduled (requested {requested})."
                    );
                }
                return format!("A rescan is already scheduled (requested {requested}).");
            }
            rpc_message.to_string()
        }
        WalletRpcErrorCode::DraftNotFound => {
            if let Some(id) = details
                .and_then(|value| value.get("draft_id"))
                .map(value_to_string)
            {
                format!("Draft `{id}` was not found; verify the identifier.")
            } else {
                rpc_message.to_string()
            }
        }
        WalletRpcErrorCode::DraftUnsigned => {
            if let Some(id) = details
                .and_then(|value| value.get("draft_id"))
                .map(value_to_string)
            {
                format!("Draft `{id}` must be signed before broadcasting; run `send sign` first.")
            } else {
                rpc_message.to_string()
            }
        }
        WalletRpcErrorCode::WitnessTooLarge => {
            if let Some(details) = details.and_then(|value| value.as_object()) {
                if let (Some(size), Some(limit)) =
                    (details.get("size_bytes"), details.get("limit_bytes"))
                {
                    return format!(
                        "Witness too large ({} bytes > limit {}).",
                        value_to_string(size),
                        value_to_string(limit)
                    );
                }
            }
            rpc_message.to_string()
        }
        WalletRpcErrorCode::WatchOnlyNotEnabled => {
            "Wallet is running in watch-only mode; signing and draft broadcasts are disabled."
                .to_string()
        }
        WalletRpcErrorCode::SyncUnavailable => {
            "Wallet sync coordinator is not configured for this node instance.".to_string()
        }
        WalletRpcErrorCode::SyncError => rpc_message.to_string(),
        WalletRpcErrorCode::RescanOutOfRange => {
            if let Some(details) = details.and_then(|value| value.as_object()) {
                if let (Some(requested), Some(latest)) =
                    (details.get("requested"), details.get("latest"))
                {
                    return format!(
                        "Rescan height {} exceeds the latest indexed height {}.",
                        value_to_string(requested),
                        value_to_string(latest)
                    );
                }
            }
            rpc_message.to_string()
        }
        WalletRpcErrorCode::RbacForbidden => {
            if let Some(details) = details.and_then(|value| value.as_object()) {
                if let Some(required) = details.get("required_roles") {
                    if let Some(array) = required.as_array() {
                        return format!(
                            "Caller lacks required wallet role (needs one of: {}).",
                            join_values(array)
                        );
                    }
                }
            }
            "Caller lacks the required wallet role.".to_string()
        }
        WalletRpcErrorCode::FeeTooHigh => rpc_message.to_string(),
        WalletRpcErrorCode::ProverCancelled => rpc_message.to_string(),
        WalletRpcErrorCode::ProverFailed => rpc_message.to_string(),
        WalletRpcErrorCode::NodeUnavailable
        | WalletRpcErrorCode::NodeRejected
        | WalletRpcErrorCode::NodePolicy
        | WalletRpcErrorCode::NodeStatsUnavailable
        | WalletRpcErrorCode::EngineFailure
        | WalletRpcErrorCode::SerializationFailure
        | WalletRpcErrorCode::StatePoisoned
        | WalletRpcErrorCode::InternalError
        | WalletRpcErrorCode::InvalidRequest
        | WalletRpcErrorCode::MethodNotFound
        | WalletRpcErrorCode::InvalidParams => rpc_message.to_string(),
        WalletRpcErrorCode::Custom(_) => rpc_message.to_string(),
    }
}

impl From<WalletRpcClientError> for WalletCliError {
    fn from(value: WalletRpcClientError) -> Self {
        match value {
            WalletRpcClientError::InvalidEndpoint(endpoint) => {
                WalletCliError::InvalidEndpoint(endpoint)
            }
            WalletRpcClientError::Json(error) => WalletCliError::Other(error.into()),
            WalletRpcClientError::Transport(error) => WalletCliError::Transport(error.to_string()),
            WalletRpcClientError::HttpStatus(status) => {
                WalletCliError::Transport(format!("HTTP status {} returned by wallet RPC", status))
            }
            WalletRpcClientError::EmptyResponse => WalletCliError::EmptyResponse,
            WalletRpcClientError::Rpc {
                code,
                message,
                json_code,
                details,
            } => {
                let friendly = friendly_message(&code, &message, details.as_ref());
                WalletCliError::RpcError {
                    code,
                    friendly,
                    message,
                    json_code,
                    details,
                }
            }
        }
    }
}

fn value_to_string(value: &Value) -> String {
    if let Some(s) = value.as_str() {
        s.to_string()
    } else if let Some(u) = value.as_u64() {
        u.to_string()
    } else if let Some(i) = value.as_i64() {
        i.to_string()
    } else if let Some(f) = value.as_f64() {
        f.to_string()
    } else {
        value.to_string()
    }
}

fn join_values(values: &[Value]) -> String {
    values
        .iter()
        .map(value_to_string)
        .collect::<Vec<_>>()
        .join(", ")
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
    #[arg(long, value_name = "URL")]
    pub endpoint: Option<String>,
    /// Bearer token used to authenticate with the wallet RPC (if enabled).
    #[arg(long, value_name = "TOKEN")]
    pub auth_token: Option<String>,
    /// Client certificate used for mutual TLS authentication (PEM format).
    #[arg(long, value_name = "PATH")]
    pub client_certificate: Option<PathBuf>,
    /// Private key paired with the client certificate (PEM format).
    #[arg(long, value_name = "PATH")]
    pub client_private_key: Option<PathBuf>,
    /// Timeout for RPC requests in seconds.
    #[arg(long, value_name = "SECONDS", default_value = "30")]
    pub timeout: u64,
}

impl RpcOptions {
    fn resolved_endpoint(&self) -> String {
        self.endpoint
            .clone()
            .or_else(|| env::var("RPP_WALLET_RPC_ENDPOINT").ok())
            .unwrap_or_else(|| DEFAULT_RPC_ENDPOINT.to_string())
    }

    fn resolved_auth_token(&self) -> Option<String> {
        self.auth_token
            .clone()
            .or_else(|| env::var("RPP_WALLET_RPC_AUTH_TOKEN").ok())
            .filter(|token| !token.is_empty())
    }

    fn resolved_client_identity(&self) -> Result<Option<Identity>, WalletCliError> {
        let certificate_path = self.client_certificate.clone().or_else(|| {
            env::var("RPP_WALLET_RPC_CLIENT_CERT")
                .ok()
                .filter(|value| !value.trim().is_empty())
                .map(PathBuf::from)
        });
        let Some(cert_path) = certificate_path else {
            return Ok(None);
        };

        let mut pem = fs::read(&cert_path).map_err(|err| WalletCliError::Other(err.into()))?;
        let key_path = self.client_private_key.clone().or_else(|| {
            env::var("RPP_WALLET_RPC_CLIENT_KEY")
                .ok()
                .filter(|value| !value.trim().is_empty())
                .map(PathBuf::from)
        });
        if let Some(key_path) = key_path {
            let key = fs::read(&key_path).map_err(|err| WalletCliError::Other(err.into()))?;
            if !pem.ends_with(b"\n") {
                pem.push(b'\n');
            }
            pem.extend_from_slice(&key);
        }

        Identity::from_pem(&pem)
            .map(Some)
            .map_err(WalletCliError::from)
    }

    fn client(&self) -> Result<WalletRpcClient, WalletCliError> {
        WalletRpcClient::from_endpoint(
            &self.resolved_endpoint(),
            self.resolved_auth_token(),
            self.resolved_client_identity()?,
            Duration::from_secs(self.timeout),
        )
        .map_err(WalletCliError::from)
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
    /// Passphrase configuration for encrypting wallet keys.
    #[command(flatten)]
    pub passphrase: PassphraseOptions,
    /// Write wallet keys in plaintext without encryption.
    #[arg(long)]
    pub no_passphrase: bool,
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

    pub fn resolve_wallet_config_path(&self) -> PathBuf {
        if let Some(path) = self.wallet_config.clone() {
            path
        } else {
            RuntimeMode::Wallet
                .default_wallet_config_path()
                .map(PathBuf::from)
                .unwrap_or_else(|| PathBuf::from("config/wallet.toml"))
        }
    }
}

#[derive(Debug, Clone, Default, Args)]
pub struct PassphraseOptions {
    /// Read the wallet passphrase from the specified file (first line is used).
    #[arg(long, value_name = "PATH")]
    pub passphrase_file: Option<PathBuf>,
    /// Read the wallet passphrase from the specified environment variable.
    #[arg(long, value_name = "ENV")]
    pub passphrase_env: Option<String>,
    /// Provide the wallet passphrase directly (discouraged for security reasons).
    #[arg(long, value_name = "PASSPHRASE")]
    pub passphrase: Option<String>,
}

impl PassphraseOptions {
    fn has_source(&self) -> bool {
        self.passphrase_file.is_some() || self.passphrase_env.is_some() || self.passphrase.is_some()
    }

    fn resolve(&self, confirm: bool) -> Result<Option<Zeroizing<Vec<u8>>>> {
        if let Some(path) = self.passphrase_file.as_ref() {
            let contents = fs::read_to_string(path)
                .with_context(|| format!("failed to read passphrase file at {}", path.display()))?;
            let passphrase = contents.lines().next().unwrap_or_default().to_string();
            return Ok(Some(Zeroizing::new(passphrase.into_bytes())));
        }

        if let Some(var) = self.passphrase_env.as_ref() {
            let value = std::env::var(var).with_context(|| {
                format!("failed to read passphrase from environment variable {var}")
            })?;
            return Ok(Some(Zeroizing::new(value.into_bytes())));
        }

        if let Some(passphrase) = self.passphrase.as_ref() {
            return Ok(Some(Zeroizing::new(passphrase.clone().into_bytes())));
        }

        if confirm {
            let first = prompt_password("Wallet passphrase: ")
                .context("failed to read wallet passphrase")?;
            let second = prompt_password("Confirm passphrase: ")
                .context("failed to confirm wallet passphrase")?;
            if first != second {
                bail!("passphrases did not match");
            }
            return Ok(Some(Zeroizing::new(first.into_bytes())));
        }

        Ok(None)
    }
}

impl InitCommand {
    pub async fn execute(&self, context: &InitContext) -> Result<(), WalletCliError> {
        let mut paths = ConfigPaths::default();

        if let Some(path) = context.wallet_config.as_ref() {
            if path.exists() {
                let raw = fs::read_to_string(path).with_context(|| {
                    format!("failed to read wallet config at {}", path.display())
                })?;
                let file: WalletFile = toml::from_str(&raw).with_context(|| {
                    format!("failed to parse wallet config at {}", path.display())
                })?;
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

        fs::create_dir_all(&paths.engine_data_dir).with_context(|| {
            format!(
                "failed to create data directory at {}",
                paths.engine_data_dir.display()
            )
        })?;

        if let Some(parent) = paths.engine_keystore.parent() {
            fs::create_dir_all(parent).with_context(|| {
                format!(
                    "failed to create keystore directory at {}",
                    parent.display()
                )
            })?;
        }

        fs::create_dir_all(&paths.engine_backup_dir).with_context(|| {
            format!(
                "failed to create backup directory at {}",
                paths.engine_backup_dir.display()
            )
        })?;

        if let Some(parent) = paths.keys_path.parent() {
            fs::create_dir_all(parent).with_context(|| {
                format!("failed to create keys directory at {}", parent.display())
            })?;
        }

        if paths.keys_path.exists() && !self.force {
            bail!(
                "wallet key already exists at {} — rerun with --force to overwrite",
                paths.keys_path.display()
            );
        }

        if self.no_passphrase && self.passphrase.has_source() {
            bail!("--no-passphrase cannot be combined with passphrase inputs");
        }

        let passphrase = if self.no_passphrase {
            None
        } else {
            self.passphrase.resolve(true)?
        };

        let signing_key = SigningKey::generate(&mut OsRng);
        persist_keypair(&paths.keys_path, &signing_key, passphrase.as_ref()).with_context(
            || {
                format!(
                    "failed to persist wallet key at {}",
                    paths.keys_path.display()
                )
            },
        )?;

        println!("Wallet initialised successfully\n");
        println!("  Data directory : {}", paths.engine_data_dir.display());
        println!("  Keystore path   : {}", paths.engine_keystore.display());
        println!("  Backup dir      : {}", paths.engine_backup_dir.display());
        println!("  Keys path       : {}", paths.keys_path.display());
        println!(
            "  Public key      : {}",
            hex::encode(signing_key.verifying_key().to_bytes())
        );

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
        let client = self.rpc.client()?;
        let status = client.sync_status().await?;
        println!("Synchronisation status\n");
        println!("  Syncing           : {}", format_bool(status.syncing));
        if let Some(mode) = status.mode.as_ref() {
            println!("  Mode              : {}", format_sync_mode(mode));
        }
        if let Some(height) = status.latest_height {
            println!("  Latest height     : {height}");
        }
        if !status.pending_ranges.is_empty() {
            for (index, range) in status.pending_ranges.iter().enumerate() {
                let label = if index == 0 {
                    "  Pending ranges   :"
                } else {
                    "                     "
                };
                println!("{label} {} → {}", range.0, range.1);
            }
        }
        if let Some(scripthashes) = status.scanned_scripthashes {
            println!("  Scanned scripts   : {scripthashes}");
        }
        if let Some(ts) = status.last_rescan_timestamp {
            println!("  Last rescan (ts)  : {ts}");
        }
        if let Some(checkpoints) = status.checkpoints.as_ref() {
            if let Some(ts) = checkpoints.last_full_rescan_ts {
                println!("  Last full rescan  : {ts}");
            }
            if let Some(ts) = checkpoints.last_compact_scan_ts {
                println!("  Last compact scan : {ts}");
            }
        }
        if let Some(error) = status.last_error {
            println!("  Last error        : {error}");
        }
        Ok(())
    }
}

fn format_sync_mode(mode: &SyncModeDto) -> String {
    match mode {
        SyncModeDto::Full { start_height } => format!("full (from {start_height})"),
        SyncModeDto::Resume { from_height } => format!("resume (from {from_height})"),
        SyncModeDto::Rescan { from_height } => format!("rescan (from {from_height})"),
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
        let client = self.rpc.client()?;
        let response = client.derive_address(self.change).await?;
        println!("Generated address\n");
        println!(
            "  Kind   : {}",
            if self.change { "change" } else { "external" }
        );
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
        let client = self.rpc.client()?;
        let balance = client.get_balance().await?;
        println!("Wallet balance\n");
        println!("  Confirmed : {}", format_amount(balance.confirmed));
        println!("  Pending   : {}", format_amount(balance.pending));
        println!("  Total     : {}", format_amount(balance.total));
        Ok(())
    }
}

#[derive(Debug, Args)]
pub struct PolicyCommand {
    #[command(subcommand)]
    pub command: PolicySubcommand,
}

#[derive(Debug, Subcommand)]
pub enum PolicySubcommand {
    /// Inspect the persisted policy snapshot.
    Get(PolicyGetCommand),
    /// Update the persisted policy snapshot with new statements.
    Set(PolicySetCommand),
}

#[derive(Debug, Args)]
pub struct PolicyGetCommand {
    #[command(flatten)]
    pub rpc: RpcOptions,
}

impl PolicyGetCommand {
    pub async fn execute(&self) -> Result<(), WalletCliError> {
        let client = self.rpc.client()?;
        let response = client.get_policy().await?;
        println!("Policy snapshot\n");
        match response.snapshot {
            Some(snapshot) => {
                println!("  Revision   : {}", snapshot.revision);
                println!("  Updated at : {}", snapshot.updated_at);
                if snapshot.statements.is_empty() {
                    println!("  Statements : none");
                } else {
                    println!("  Statements :");
                    for statement in snapshot.statements {
                        println!("    - {}", statement);
                    }
                }
            }
            None => println!("  Snapshot   : none recorded"),
        }
        Ok(())
    }
}

#[derive(Debug, Args)]
pub struct PolicySetCommand {
    #[command(flatten)]
    pub rpc: RpcOptions,
    /// Inline policy statement to persist (may be specified multiple times).
    #[arg(long = "statement", value_name = "TEXT")]
    pub statements: Vec<String>,
    /// Optional file containing policy statements, one per line.
    #[arg(long, value_name = "PATH")]
    pub file: Option<PathBuf>,
}

impl PolicySetCommand {
    pub async fn execute(&self) -> Result<(), WalletCliError> {
        let client = self.rpc.client()?;
        let mut statements = self.statements.clone();
        if let Some(path) = &self.file {
            let contents =
                fs::read_to_string(path).map_err(|err| WalletCliError::Other(err.into()))?;
            for line in contents.lines() {
                let trimmed = line.trim();
                if !trimmed.is_empty() {
                    statements.push(trimmed.to_string());
                }
            }
        }
        let params = SetPolicyParams { statements };
        let response = client.set_policy(&params).await?;
        println!("Policy snapshot updated\n");
        println!("  Revision   : {}", response.snapshot.revision);
        println!("  Updated at : {}", response.snapshot.updated_at);
        if response.snapshot.statements.is_empty() {
            println!("  Statements : none");
        } else {
            println!("  Statements :");
            for statement in response.snapshot.statements {
                println!("    - {}", statement);
            }
        }
        Ok(())
    }
}

#[derive(Debug, Args)]
pub struct MultisigCommand {
    #[command(subcommand)]
    pub command: MultisigSubcommand,
}

#[derive(Debug, Subcommand)]
pub enum MultisigSubcommand {
    /// Inspect or update the multisig scope.
    Scope(MultisigScopeCommand),
    /// Manage the cosigner registry.
    Cosigners(MultisigCosignersCommand),
    /// Export multisig collaboration metadata for a draft.
    Export(MultisigExportCommand),
}

impl MultisigCommand {
    pub async fn execute(&self) -> Result<(), WalletCliError> {
        match &self.command {
            MultisigSubcommand::Scope(cmd) => cmd.execute().await,
            MultisigSubcommand::Cosigners(cmd) => cmd.execute().await,
            MultisigSubcommand::Export(cmd) => cmd.execute().await,
        }
    }
}

#[derive(Debug, Args)]
pub struct MultisigScopeCommand {
    #[command(flatten)]
    pub rpc: RpcOptions,
    #[command(subcommand)]
    pub command: MultisigScopeSubcommand,
}

#[derive(Debug, Subcommand)]
pub enum MultisigScopeSubcommand {
    /// Display the currently configured multisig scope.
    Get,
    /// Persist a new multisig scope (format: M-of-N).
    Set {
        #[arg(value_name = "SCOPE")]
        scope: String,
    },
    /// Remove the persisted multisig scope.
    Clear,
}

impl MultisigScopeCommand {
    pub async fn execute(&self) -> Result<(), WalletCliError> {
        let client = self.rpc.client()?;
        match &self.command {
            MultisigScopeSubcommand::Get => {
                let response = client.get_multisig_scope().await?;
                println!("Multisig scope\n");
                render_multisig_scope(response.scope.as_ref());
                Ok(())
            }
            MultisigScopeSubcommand::Set { scope } => {
                let parsed = MultisigScope::parse(scope)
                    .map_err(|err| WalletCliError::Other(anyhow!(err)))?;
                let dto = MultisigScopeDto {
                    threshold: parsed.threshold(),
                    participants: parsed.participants(),
                };
                let response = client.set_multisig_scope(Some(&dto)).await?;
                println!("Updated multisig scope\n");
                render_multisig_scope(response.scope.as_ref());
                Ok(())
            }
            MultisigScopeSubcommand::Clear => {
                client.set_multisig_scope(None).await?;
                println!("Cleared multisig scope");
                Ok(())
            }
        }
    }
}

#[derive(Debug, Args)]
pub struct MultisigCosignersCommand {
    #[command(flatten)]
    pub rpc: RpcOptions,
    #[command(subcommand)]
    pub command: MultisigCosignersSubcommand,
}

#[derive(Debug, Subcommand)]
pub enum MultisigCosignersSubcommand {
    /// List registered cosigners.
    List,
    /// Replace the cosigner registry with the provided entries.
    Set {
        #[arg(long = "cosigner", value_name = "FINGERPRINT[@URL]", required = true)]
        cosigners: Vec<String>,
    },
}

impl MultisigCosignersCommand {
    pub async fn execute(&self) -> Result<(), WalletCliError> {
        let client = self.rpc.client()?;
        match &self.command {
            MultisigCosignersSubcommand::List => {
                let response = client.get_cosigners().await?;
                println!("Cosigner registry\n");
                render_cosigners(&response.cosigners);
                Ok(())
            }
            MultisigCosignersSubcommand::Set { cosigners } => {
                let parsed = cosigners
                    .iter()
                    .map(|value| parse_cosigner(value))
                    .collect::<Result<Vec<_>, _>>()?;
                let response = client.set_cosigners(&parsed).await?;
                println!("Updated cosigner registry\n");
                render_cosigners(&response.cosigners);
                Ok(())
            }
        }
    }
}

#[derive(Debug, Args)]
pub struct MultisigExportCommand {
    #[command(flatten)]
    pub rpc: RpcOptions,
    /// Draft identifier to export metadata for.
    #[arg(value_name = "DRAFT_ID")]
    pub draft_id: String,
}

impl MultisigExportCommand {
    pub async fn execute(&self) -> Result<(), WalletCliError> {
        let client = self.rpc.client()?;
        let response = client.export_multisig_metadata(&self.draft_id).await?;
        println!("Multisig export\n");
        println!("  Draft ID : {}", response.draft_id);
        render_multisig_metadata(response.metadata.as_ref());
        Ok(())
    }
}

#[derive(Debug, Args)]
pub struct FeesCommand {
    #[command(subcommand)]
    pub command: FeesSubcommand,
}

#[derive(Debug, Subcommand)]
pub enum FeesSubcommand {
    /// Estimate a fee rate for the given confirmation target.
    Estimate(FeesEstimateCommand),
}

#[derive(Debug, Args)]
pub struct FeesEstimateCommand {
    #[command(flatten)]
    pub rpc: RpcOptions,
    /// Desired confirmation target in blocks.
    #[arg(long, value_name = "BLOCKS")]
    pub target: u16,
}

impl FeesEstimateCommand {
    pub async fn execute(&self) -> Result<(), WalletCliError> {
        let client = self.rpc.client()?;
        let response = client.estimate_fee(self.target).await?;
        println!("Fee estimate\n");
        println!("  Target confirmations : {}", response.confirmation_target);
        println!("  Fee rate             : {} sat/vB", response.fee_rate);
        Ok(())
    }
}

#[derive(Debug, Args)]
pub struct LocksCommand {
    #[command(subcommand)]
    pub command: LocksSubcommand,
}

#[derive(Debug, Subcommand)]
pub enum LocksSubcommand {
    /// List all pending wallet input locks.
    List(LocksListCommand),
    /// Release all pending wallet input locks.
    Release(LocksReleaseCommand),
}

#[derive(Debug, Args)]
pub struct LocksListCommand {
    #[command(flatten)]
    pub rpc: RpcOptions,
}

impl LocksListCommand {
    pub async fn execute(&self) -> Result<(), WalletCliError> {
        let client = self.rpc.client()?;
        let response = client.list_pending_locks().await?;
        println!("Pending locks\n");
        render_locks(&response.locks);
        Ok(())
    }
}

#[derive(Debug, Args)]
pub struct LocksReleaseCommand {
    #[command(flatten)]
    pub rpc: RpcOptions,
}

impl LocksReleaseCommand {
    pub async fn execute(&self) -> Result<(), WalletCliError> {
        let client = self.rpc.client()?;
        let response = client.release_pending_locks().await?;
        println!("Released pending locks\n");
        render_locks(&response.released);
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
    /// Broadcast an externally signed transaction hex blob.
    BroadcastRaw(SendBroadcastRawCommand),
}

#[derive(Debug, Args)]
pub struct SendPreviewCommand {
    #[command(flatten)]
    pub rpc: RpcOptions,
}

impl SendPreviewCommand {
    pub async fn execute(&self) -> Result<(), WalletCliError> {
        let client = self.rpc.client()?;
        let preview = client.policy_preview().await?;
        println!("Wallet policy preview\n");
        println!("  Min confirmations : {}", preview.min_confirmations);
        println!(
            "  Dust limit        : {}",
            format_amount(preview.dust_limit)
        );
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
        let client = self.rpc.client()?;
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
        let client = self.rpc.client()?;
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
        render_locks(&result.locks);
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
        let client = self.rpc.client()?;
        let response = client.broadcast(&self.draft_id).await?;
        println!("Broadcast result\n");
        println!("  Draft ID : {}", response.draft_id);
        println!("  Accepted : {}", format_bool(response.accepted));
        render_locks(&response.locks);
        Ok(())
    }
}

#[derive(Debug, Args)]
pub struct SendBroadcastRawCommand {
    #[command(flatten)]
    pub rpc: RpcOptions,
    /// Hex-encoded transaction payload signed externally.
    #[arg(long, value_name = "HEX")]
    pub tx_hex: String,
}

impl SendBroadcastRawCommand {
    pub async fn execute(&self) -> Result<(), WalletCliError> {
        let client = self.rpc.client()?;
        let params = BroadcastRawParams {
            tx_hex: self.tx_hex.clone(),
        };
        let BroadcastRawResponse { accepted } = client.broadcast_raw(&params).await?;
        println!("Broadcast raw transaction\n");
        println!("  Accepted : {}", format_bool(accepted));
        Ok(())
    }
}

#[cfg(feature = "wallet_hw")]
#[derive(Debug, Args)]
pub struct HardwareCommand {
    #[command(subcommand)]
    pub command: HardwareSubcommand,
}

#[cfg(feature = "wallet_hw")]
#[derive(Debug, Subcommand)]
pub enum HardwareSubcommand {
    /// List hardware signing devices detected by the wallet.
    Enumerate(HardwareEnumerateCommand),
    /// Ask a hardware device to sign an arbitrary payload.
    Sign(HardwareSignCommand),
}

#[cfg(feature = "wallet_hw")]
impl HardwareCommand {
    pub async fn execute(&self) -> Result<(), WalletCliError> {
        match &self.command {
            HardwareSubcommand::Enumerate(cmd) => cmd.execute().await,
            HardwareSubcommand::Sign(cmd) => cmd.execute().await,
        }
    }
}

#[cfg(feature = "wallet_hw")]
#[derive(Debug, Args)]
pub struct HardwareEnumerateCommand {
    #[command(flatten)]
    pub rpc: RpcOptions,
}

#[cfg(feature = "wallet_hw")]
impl HardwareEnumerateCommand {
    pub async fn execute(&self) -> Result<(), WalletCliError> {
        let client = self.rpc.client()?;
        let response = client.hw_enumerate().await?;
        if response.devices.is_empty() {
            println!("No hardware signing devices detected.");
            return Ok(());
        }
        println!("Detected hardware signing devices:\n");
        for device in response.devices {
            let label = device
                .label
                .as_deref()
                .filter(|value| !value.is_empty())
                .unwrap_or("(no label)");
            println!("  Fingerprint : {}", device.fingerprint);
            println!("    Model     : {}", device.model);
            println!("    Label     : {}\n", label);
        }
        Ok(())
    }
}

#[cfg(feature = "wallet_hw")]
#[derive(Debug, Args)]
pub struct HardwareSignCommand {
    #[command(flatten)]
    pub rpc: RpcOptions,
    /// Hardware device fingerprint to target.
    #[arg(long)]
    pub fingerprint: String,
    /// Account index for the derivation path.
    #[arg(long)]
    pub account: u32,
    /// Use the change branch when deriving the key.
    #[arg(long, default_value_t = false)]
    pub change: bool,
    /// Address index for the derivation path.
    #[arg(long)]
    pub index: u32,
    /// Hex-encoded payload that should be signed.
    #[arg(long, value_name = "HEX")]
    pub payload: String,
}

#[cfg(feature = "wallet_hw")]
impl HardwareSignCommand {
    pub async fn execute(&self) -> Result<(), WalletCliError> {
        let client = self.rpc.client()?;
        let payload_clean = self.payload.trim();
        let payload_bytes = hex::decode(payload_clean)
            .map_err(|err| WalletCliError::Other(anyhow!(format!("invalid payload hex: {err}"))))?;
        let params = HardwareSignParams {
            fingerprint: self.fingerprint.clone(),
            path: DerivationPathDto {
                account: self.account,
                change: self.change,
                index: self.index,
            },
            payload: hex::encode(payload_bytes),
        };
        let response = client.hw_sign(&params).await?;
        println!("Hardware signature\n");
        println!("  Fingerprint : {}", response.fingerprint);
        println!(
            "  Path        : m/{}/{}/{}",
            response.path.account,
            if response.path.change { 1 } else { 0 },
            response.path.index
        );
        println!("  Signature   : {}", response.signature);
        println!("  Public key  : {}", response.public_key);
        Ok(())
    }
}

#[derive(Debug, Args)]
pub struct WatchOnlyCommand {
    #[command(subcommand)]
    pub command: WatchOnlySubcommand,
}

#[derive(Debug, Subcommand)]
pub enum WatchOnlySubcommand {
    /// Display the current watch-only status of the wallet.
    Status(WatchOnlyStatusCommand),
    /// Enable watch-only mode using externally provided descriptors.
    Enable(WatchOnlyEnableCommand),
    /// Disable watch-only mode and restore signing operations.
    Disable(WatchOnlyDisableCommand),
}

#[derive(Debug, Args)]
pub struct WatchOnlyStatusCommand {
    #[command(flatten)]
    pub rpc: RpcOptions,
}

impl WatchOnlyStatusCommand {
    pub async fn execute(&self) -> Result<(), WalletCliError> {
        let client = self.rpc.client()?;
        let status = client.watch_only_status().await?;
        println!("Watch-only status\n");
        render_watch_only_status(&status);
        Ok(())
    }
}

#[derive(Debug, Args)]
pub struct WatchOnlyEnableCommand {
    #[command(flatten)]
    pub rpc: RpcOptions,
    /// External receive descriptor or xpub string.
    #[arg(long, value_name = "DESCRIPTOR")]
    pub external_descriptor: String,
    /// Optional internal/change descriptor.
    #[arg(long, value_name = "DESCRIPTOR")]
    pub internal_descriptor: Option<String>,
    /// Optional account-level xpub associated with the descriptors.
    #[arg(long, value_name = "XPUB")]
    pub account_xpub: Option<String>,
    /// Optional birthday height used to bootstrap scanning.
    #[arg(long, value_name = "HEIGHT")]
    pub birthday_height: Option<u64>,
}

impl WatchOnlyEnableCommand {
    pub async fn execute(&self) -> Result<(), WalletCliError> {
        let client = self.rpc.client()?;
        let params = WatchOnlyEnableParams {
            external_descriptor: self.external_descriptor.clone(),
            internal_descriptor: self.internal_descriptor.clone(),
            account_xpub: self.account_xpub.clone(),
            birthday_height: self.birthday_height,
        };
        let status = client.watch_only_enable(&params).await?;
        println!("Watch-only mode enabled\n");
        render_watch_only_status(&status);
        Ok(())
    }
}

#[derive(Debug, Args)]
pub struct WatchOnlyDisableCommand {
    #[command(flatten)]
    pub rpc: RpcOptions,
}

impl WatchOnlyDisableCommand {
    pub async fn execute(&self) -> Result<(), WalletCliError> {
        let client = self.rpc.client()?;
        let status = client.watch_only_disable().await?;
        println!("Watch-only mode disabled\n");
        render_watch_only_status(&status);
        Ok(())
    }
}

#[derive(Debug, Args)]
pub struct BackupCommand {
    #[command(subcommand)]
    pub command: BackupSubcommand,
}

#[derive(Debug, Subcommand)]
pub enum BackupSubcommand {
    /// Export an encrypted wallet backup archive.
    Export(BackupExportCommand),
    /// Validate an encrypted wallet backup archive.
    Validate(BackupValidateCommand),
    /// Import an encrypted wallet backup archive and schedule a rescan.
    Import(BackupImportCommand),
}

#[derive(Debug, Args)]
pub struct BackupExportCommand {
    #[command(flatten)]
    pub rpc: RpcOptions,
    /// Export only metadata and policies without bundling the keystore.
    #[arg(long)]
    pub metadata_only: bool,
    /// Skip computing component checksums for the archive.
    #[arg(long)]
    pub skip_checksums: bool,
}

impl BackupExportCommand {
    pub async fn execute(&self) -> Result<(), WalletCliError> {
        let client = self.rpc.client()?;
        let passphrase = Zeroizing::new(
            prompt_password("Enter backup passphrase: ")
                .context("failed to read backup passphrase")?,
        );
        let confirmation = Zeroizing::new(
            prompt_password("Confirm backup passphrase: ")
                .context("failed to read backup passphrase confirmation")?,
        );
        if passphrase.as_ref() != confirmation.as_ref() {
            return Err(WalletCliError::Other(anyhow!("passphrases did not match")));
        }

        let mut params = BackupExportParams {
            passphrase: (*passphrase).clone(),
            confirmation: (*confirmation).clone(),
            metadata_only: self.metadata_only,
            include_checksums: !self.skip_checksums,
        };
        let response: BackupExportResponse = client.backup_export(&params).await?;
        params.passphrase.zeroize();
        params.confirmation.zeroize();

        println!("Backup exported\n");
        println!("  Path             : {}", response.path);
        render_backup_metadata(&response.metadata);
        Ok(())
    }
}

#[derive(Debug, Args)]
pub struct BackupValidateCommand {
    #[command(flatten)]
    pub rpc: RpcOptions,
    /// Name of the backup file located under the configured backup directory.
    #[arg(value_name = "NAME")]
    pub name: String,
    /// Perform a dry-run validation without verifying checksums.
    #[arg(long)]
    pub dry_run: bool,
}

impl BackupValidateCommand {
    pub async fn execute(&self) -> Result<(), WalletCliError> {
        let client = self.rpc.client()?;
        let passphrase = Zeroizing::new(
            prompt_password("Enter backup passphrase: ")
                .context("failed to read backup passphrase")?,
        );
        let mut params = BackupValidateParams {
            name: self.name.clone(),
            passphrase: (*passphrase).clone(),
            mode: if self.dry_run {
                BackupValidationModeDto::DryRun
            } else {
                BackupValidationModeDto::Full
            },
        };
        let response: BackupValidateResponse = client.backup_validate(&params).await?;
        params.passphrase.zeroize();

        println!("Backup validation\n");
        render_backup_metadata(&response.metadata);
        println!(
            "  Contains keystore : {}",
            format_bool(response.has_keystore)
        );
        println!("  Policy entries    : {}", response.policy_count);
        println!("  Metadata entries  : {}", response.meta_entries);
        Ok(())
    }
}

#[derive(Debug, Args)]
pub struct BackupImportCommand {
    #[command(flatten)]
    pub rpc: RpcOptions,
    /// Name of the backup file located under the configured backup directory.
    #[arg(value_name = "NAME")]
    pub name: String,
}

impl BackupImportCommand {
    pub async fn execute(&self) -> Result<(), WalletCliError> {
        let client = self.rpc.client()?;
        let passphrase = Zeroizing::new(
            prompt_password("Enter backup passphrase: ")
                .context("failed to read backup passphrase")?,
        );
        let mut params = BackupImportParams {
            name: self.name.clone(),
            passphrase: (*passphrase).clone(),
        };
        let response: BackupImportResponse = client.backup_import(&params).await?;
        params.passphrase.zeroize();

        println!("Backup import completed\n");
        render_backup_metadata(&response.metadata);
        println!(
            "  Restored keystore : {}",
            format_bool(response.restored_keystore)
        );
        println!(
            "  Restored policy   : {}",
            format_bool(response.restored_policy)
        );
        println!("  Rescan from       : {}", response.rescan_from_height);
        Ok(())
    }
}

#[derive(Debug, Args)]
pub struct RescanCommand {
    #[command(flatten)]
    pub rpc: RpcOptions,
    /// Block height to start rescanning from.
    #[arg(long, value_name = "HEIGHT")]
    pub from_height: Option<u64>,
    /// Number of blocks to look back from the latest indexed height.
    #[arg(long, value_name = "BLOCKS")]
    pub lookback_blocks: Option<u64>,
}

impl RescanCommand {
    pub async fn execute(&self) -> Result<(), WalletCliError> {
        if self.from_height.is_none() && self.lookback_blocks.is_none() {
            return Err(WalletCliError::Other(anyhow!(
                "rescan requires --from-height or --lookback-blocks"
            )));
        }
        let client = self.rpc.client()?;
        let params = RescanParams {
            from_height: self.from_height,
            lookback_blocks: self.lookback_blocks,
        };
        let response = client.rescan(&params).await?;
        println!("Rescan request submitted\n");
        println!("  Scheduled   : {}", format_bool(response.scheduled));
        println!("  From height : {}", response.from_height);
        Ok(())
    }
}

#[derive(Debug, Clone, Args)]
pub struct SecurityIdentityOptions {
    /// Bearer token presented by the identity.
    #[arg(
        long,
        value_name = "TOKEN",
        conflicts_with_all = ["token_hash", "fingerprint", "certificate"]
    )]
    pub token: Option<String>,
    /// Pre-hashed token identifier (as reported by `security roles`).
    #[arg(
        long = "token-hash",
        value_name = "HASH",
        conflicts_with_all = ["token", "fingerprint", "certificate"]
    )]
    pub token_hash: Option<String>,
    /// Certificate fingerprint (hex-encoded SHA-256).
    #[arg(long, value_name = "HEX", conflicts_with_all = ["token", "token_hash", "certificate"])]
    pub fingerprint: Option<String>,
    /// Path to a PEM-encoded certificate whose fingerprint should be used.
    #[arg(long, value_name = "PATH")]
    pub certificate: Option<PathBuf>,
}

impl SecurityIdentityOptions {
    fn resolve(&self) -> Result<WalletIdentity, WalletCliError> {
        if let Some(token) = &self.token {
            let trimmed = token.trim();
            if trimmed.is_empty() {
                return Err(WalletCliError::Other(anyhow!("token must not be empty")));
            }
            return Ok(WalletIdentity::from_bearer_token(trimmed));
        }

        if let Some(hash) = &self.token_hash {
            let trimmed = hash.trim();
            if trimmed.len() != 64 || !trimmed.chars().all(|ch| ch.is_ascii_hexdigit()) {
                return Err(WalletCliError::Other(anyhow!(
                    "token hash must be a 64-character hexadecimal string"
                )));
            }
            return Ok(WalletIdentity::Token(trimmed.to_ascii_lowercase()));
        }

        if let Some(fingerprint) = &self.fingerprint {
            return WalletIdentity::from_certificate_fingerprint(fingerprint)
                .map_err(|err| WalletCliError::Other(anyhow!(err)));
        }

        if let Some(path) = &self.certificate {
            let pem = fs::read_to_string(path).map_err(|err| WalletCliError::Other(err.into()))?;
            return WalletIdentity::from_certificate_pem(&pem)
                .map_err(|err| WalletCliError::Other(anyhow!(err)));
        }

        Err(WalletCliError::Other(anyhow!(
            "identity must be specified using --token, --fingerprint, or --certificate"
        )))
    }
}

#[derive(Debug, Args)]
pub struct SecurityRolesCommand {}

impl SecurityRolesCommand {
    pub async fn execute(&self, context: &InitContext) -> Result<(), WalletCliError> {
        let (config, _) = load_wallet_security_config(context)?;
        let store = open_rbac_store(&config)?;
        let assignments = store.snapshot();
        if assignments.is_empty() {
            println!("No RBAC assignments stored.");
            return Ok(());
        }
        println!("Wallet RBAC assignments:");
        for (identity, roles) in assignments {
            println!(
                "  {} -> {}",
                format_identity(&identity),
                format_roles(&roles)
            );
        }
        Ok(())
    }
}

#[derive(Debug, Args)]
pub struct SecurityAssignCommand {
    #[command(flatten)]
    pub identity: SecurityIdentityOptions,
    /// Wallet roles granted to the identity (repeatable: admin, operator, viewer).
    #[arg(long = "role", value_name = "ROLE")]
    pub roles: Vec<String>,
}

impl SecurityAssignCommand {
    pub async fn execute(&self, context: &InitContext) -> Result<(), WalletCliError> {
        if self.roles.is_empty() {
            return Err(WalletCliError::Other(anyhow!(
                "at least one --role must be specified"
            )));
        }
        let identity = self.identity.resolve()?;
        let role_set = parse_roles(&self.roles)?;
        let roles_vec: Vec<WalletRole> = role_set.iter().copied().collect();

        let (mut config, path) = load_wallet_security_config(context)?;
        let mut replaced = false;
        for binding in &mut config.wallet.security.bindings {
            if binding.identity == identity {
                binding.roles = roles_vec.clone();
                replaced = true;
                break;
            }
        }
        if !replaced {
            config
                .wallet
                .security
                .bindings
                .push(WalletRpcSecurityBinding {
                    identity: identity.clone(),
                    roles: roles_vec.clone(),
                });
        }
        config
            .wallet
            .security
            .bindings
            .sort_by(|a, b| a.identity.cmp(&b.identity));
        config
            .save(&path)
            .map_err(|err| WalletCliError::Other(anyhow!(err)))?;
        persist_security_bindings(&config)?;

        println!(
            "Assigned {} to roles: {}",
            format_identity(&identity),
            format_roles(&role_set)
        );
        Ok(())
    }
}

#[derive(Debug, Args)]
pub struct SecurityRemoveCommand {
    #[command(flatten)]
    pub identity: SecurityIdentityOptions,
}

impl SecurityRemoveCommand {
    pub async fn execute(&self, context: &InitContext) -> Result<(), WalletCliError> {
        let identity = self.identity.resolve()?;
        let (mut config, path) = load_wallet_security_config(context)?;
        let before = config.wallet.security.bindings.len();
        config
            .wallet
            .security
            .bindings
            .retain(|binding| binding.identity != identity);
        if config.wallet.security.bindings.len() == before {
            return Err(WalletCliError::Other(anyhow!(format!(
                "identity {} not found in configuration",
                format_identity(&identity)
            ))));
        }

        config
            .save(&path)
            .map_err(|err| WalletCliError::Other(anyhow!(err)))?;
        persist_security_bindings(&config)?;

        println!(
            "Removed RBAC assignment for {}.",
            format_identity(&identity)
        );
        Ok(())
    }
}

#[derive(Debug, Args)]
pub struct SecurityMtlsCommand {
    /// Enable mutual TLS authentication for the wallet runtime.
    #[arg(long, conflicts_with = "disable")]
    pub enable: bool,
    /// Disable mutual TLS authentication for the wallet runtime.
    #[arg(long, conflicts_with = "enable")]
    pub disable: bool,
}

impl SecurityMtlsCommand {
    pub async fn execute(&self, context: &InitContext) -> Result<(), WalletCliError> {
        let (mut config, path) = load_wallet_security_config(context)?;
        if !self.enable && !self.disable {
            println!(
                "mTLS is currently {}.",
                format_bool(config.wallet.security.mtls_enabled)
            );
            return Ok(());
        }

        let desired = self.enable;
        config.wallet.security.mtls_enabled = desired;
        config
            .save(&path)
            .map_err(|err| WalletCliError::Other(anyhow!(err)))?;
        println!(
            "mTLS has been {}.",
            if desired { "enabled" } else { "disabled" }
        );
        Ok(())
    }
}

#[derive(Debug, Args)]
pub struct SecurityFingerprintsCommand {}

impl SecurityFingerprintsCommand {
    pub async fn execute(&self, context: &InitContext) -> Result<(), WalletCliError> {
        let (config, _) = load_wallet_security_config(context)?;
        let fingerprints = &config.wallet.security.ca_fingerprints;
        if fingerprints.is_empty() {
            println!("No CA fingerprints configured.");
            return Ok(());
        }
        println!("Trusted CA fingerprints:");
        for entry in fingerprints {
            if let Some(description) = entry.description.as_ref().filter(|value| !value.is_empty())
            {
                println!("  {} ({})", entry.fingerprint, description);
            } else {
                println!("  {}", entry.fingerprint);
            }
        }
        Ok(())
    }
}

#[derive(Debug, Args)]
pub struct SecurityCommand {
    #[command(subcommand)]
    pub command: SecuritySubcommand,
}

#[derive(Debug, Subcommand)]
pub enum SecuritySubcommand {
    /// List RBAC assignments stored by the wallet runtime.
    Roles(SecurityRolesCommand),
    /// Assign wallet roles to an identity.
    Assign(SecurityAssignCommand),
    /// Remove an identity from the RBAC store.
    Remove(SecurityRemoveCommand),
    /// Inspect or toggle mutual TLS configuration.
    Mtls(SecurityMtlsCommand),
    /// Display trusted CA fingerprints recorded in configuration.
    Fingerprints(SecurityFingerprintsCommand),
}

impl SecurityCommand {
    pub async fn execute(&self, context: &InitContext) -> Result<(), WalletCliError> {
        match &self.command {
            SecuritySubcommand::Roles(cmd) => cmd.execute(context).await,
            SecuritySubcommand::Assign(cmd) => cmd.execute(context).await,
            SecuritySubcommand::Remove(cmd) => cmd.execute(context).await,
            SecuritySubcommand::Mtls(cmd) => cmd.execute(context).await,
            SecuritySubcommand::Fingerprints(cmd) => cmd.execute(context).await,
        }
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
    /// Inspect or update policy snapshots.
    Policy(PolicyCommand),
    /// Manage multisig configuration and cosigners.
    Multisig(MultisigCommand),
    /// Inspect fee estimates.
    Fees(FeesCommand),
    /// Inspect or manage pending locks.
    Locks(LocksCommand),
    /// Manage transaction drafts.
    Send(SendCommand),
    #[cfg(feature = "wallet_hw")]
    /// Interact with hardware signing devices.
    Hardware(HardwareCommand),
    /// Manage encrypted wallet backups.
    Backup(BackupCommand),
    /// Manage watch-only wallet mode.
    WatchOnly(WatchOnlyCommand),
    /// Manage wallet security configuration and RBAC assignments.
    Security(SecurityCommand),
    /// Trigger a historical rescan.
    Rescan(RescanCommand),
}

impl WalletCommand {
    pub async fn execute(&self, init_context: &InitContext) -> Result<(), WalletCliError> {
        match self {
            WalletCommand::Init(cmd) => cmd.execute(init_context).await,
            WalletCommand::Sync(cmd) => cmd.execute().await,
            WalletCommand::Addr(AddrCommand { command }) => match command {
                AddrSubcommand::New(cmd) => cmd.execute().await,
            },
            WalletCommand::Balance(cmd) => cmd.execute().await,
            WalletCommand::Policy(PolicyCommand { command }) => match command {
                PolicySubcommand::Get(cmd) => cmd.execute().await,
                PolicySubcommand::Set(cmd) => cmd.execute().await,
            },
            WalletCommand::Multisig(cmd) => cmd.execute().await,
            WalletCommand::Fees(FeesCommand { command }) => match command {
                FeesSubcommand::Estimate(cmd) => cmd.execute().await,
            },
            WalletCommand::Locks(LocksCommand { command }) => match command {
                LocksSubcommand::List(cmd) => cmd.execute().await,
                LocksSubcommand::Release(cmd) => cmd.execute().await,
            },
            WalletCommand::Send(SendCommand { command }) => match command {
                SendSubcommand::Preview(cmd) => cmd.execute().await,
                SendSubcommand::Create(cmd) => cmd.execute().await,
                SendSubcommand::Sign(cmd) => cmd.execute().await,
                SendSubcommand::Broadcast(cmd) => cmd.execute().await,
                SendSubcommand::BroadcastRaw(cmd) => cmd.execute().await,
            },
            #[cfg(feature = "wallet_hw")]
            WalletCommand::Hardware(cmd) => cmd.execute().await,
            WalletCommand::Backup(BackupCommand { command }) => match command {
                BackupSubcommand::Export(cmd) => cmd.execute().await,
                BackupSubcommand::Validate(cmd) => cmd.execute().await,
                BackupSubcommand::Import(cmd) => cmd.execute().await,
            },
            WalletCommand::WatchOnly(WatchOnlyCommand { command }) => match command {
                WatchOnlySubcommand::Status(cmd) => cmd.execute().await,
                WatchOnlySubcommand::Enable(cmd) => cmd.execute().await,
                WatchOnlySubcommand::Disable(cmd) => cmd.execute().await,
            },
            WalletCommand::Rescan(cmd) => cmd.execute().await,
            WalletCommand::Security(cmd) => cmd.execute(init_context).await,
        }
    }
}

fn load_wallet_security_config(
    context: &InitContext,
) -> Result<(RuntimeWalletConfig, PathBuf), WalletCliError> {
    let path = context.resolve_wallet_config_path();
    let config = if path.exists() {
        RuntimeWalletConfig::load(&path).map_err(|err| WalletCliError::Other(anyhow!(err)))?
    } else {
        RuntimeWalletConfig::default()
    };
    let mut config = config;
    if let Some(dir) = &context.data_dir_override {
        config.data_dir = dir.clone();
    }
    Ok((config, path))
}

fn open_rbac_store(config: &RuntimeWalletConfig) -> Result<WalletRbacStore, WalletCliError> {
    let paths = WalletSecurityPaths::from_data_dir(&config.data_dir);
    paths
        .ensure()
        .map_err(|err| WalletCliError::Other(anyhow!(err)))?;
    WalletRbacStore::load(paths.rbac_store()).map_err(|err| WalletCliError::Other(anyhow!(err)))
}

fn persist_security_bindings(config: &RuntimeWalletConfig) -> Result<(), WalletCliError> {
    let store = open_rbac_store(config)?;
    let runtime_bindings = config.wallet.security.runtime_bindings();
    let snapshot = store.snapshot();
    let mut removals = Vec::new();
    for identity in snapshot.keys() {
        if !runtime_bindings
            .iter()
            .any(|binding| &binding.identity == identity)
        {
            removals.push(WalletSecurityBinding::new(
                identity.clone(),
                WalletRoleSet::new(),
            ));
        }
    }
    if !removals.is_empty() {
        store.apply_bindings(&removals);
    }
    store.apply_bindings(&runtime_bindings);
    store
        .save()
        .map_err(|err| WalletCliError::Other(anyhow!(err)))
}

fn parse_roles(values: &[String]) -> Result<WalletRoleSet, WalletCliError> {
    let mut roles = WalletRoleSet::new();
    for value in values {
        let trimmed = value.trim();
        if trimmed.is_empty() {
            return Err(WalletCliError::Other(anyhow!(
                "role names must not be empty"
            )));
        }
        let role = match trimmed.to_ascii_lowercase().as_str() {
            "admin" => WalletRole::Admin,
            "operator" => WalletRole::Operator,
            "viewer" => WalletRole::Viewer,
            other => {
                return Err(WalletCliError::Other(anyhow!(format!(
                    "unknown wallet role: {other}"
                ))))
            }
        };
        roles.insert(role);
    }
    if roles.is_empty() {
        return Err(WalletCliError::Other(anyhow!(
            "at least one --role must be specified"
        )));
    }
    Ok(roles)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn make_context(temp: &tempfile::TempDir) -> InitContext {
        let config_path = temp.path().join("wallet.toml");
        InitContext::new(Some(config_path), Some(temp.path().to_path_buf()))
    }

    fn load_security_store(config: &RuntimeWalletConfig) -> WalletRbacStore {
        let paths = WalletSecurityPaths::from_data_dir(&config.data_dir);
        WalletRbacStore::load(paths.rbac_store()).expect("load rbac store")
    }

    #[tokio::test]
    async fn security_assign_and_remove_updates_rbac_store() {
        let temp = tempdir().expect("tempdir");
        let context = make_context(&temp);

        let identity_options = SecurityIdentityOptions {
            token: Some("super-secret".to_string()),
            token_hash: None,
            fingerprint: None,
            certificate: None,
        };

        let assign = SecurityAssignCommand {
            identity: identity_options.clone(),
            roles: vec!["admin".into(), "viewer".into()],
        };
        assign.execute(&context).await.expect("assign roles");

        let config_path = context.resolve_wallet_config_path();
        let config = RuntimeWalletConfig::load(&config_path).expect("load config");
        assert_eq!(config.wallet.security.bindings.len(), 1);
        let binding = &config.wallet.security.bindings[0];
        let expected_identity = WalletIdentity::from_bearer_token("super-secret");
        assert_eq!(binding.identity, expected_identity);
        assert!(binding.roles.contains(&WalletRole::Admin));
        assert!(binding.roles.contains(&WalletRole::Viewer));

        let store = load_security_store(&config);
        let roles = store.roles_for(&expected_identity);
        assert!(roles.contains(&WalletRole::Admin));
        assert!(roles.contains(&WalletRole::Viewer));

        let remove = SecurityRemoveCommand {
            identity: identity_options,
        };
        remove.execute(&context).await.expect("remove identity");

        let config = RuntimeWalletConfig::load(&config_path).expect("reload config");
        assert!(config.wallet.security.bindings.is_empty());
        let store = load_security_store(&config);
        assert!(store.snapshot().is_empty());
    }
}

fn format_identity(identity: &WalletIdentity) -> String {
    match identity {
        WalletIdentity::Token(hash) => format!("token:{hash}"),
        WalletIdentity::Certificate(fingerprint) => format!("certificate:{fingerprint}"),
    }
}

fn format_roles(roles: &WalletRoleSet) -> String {
    if roles.is_empty() {
        "none".to_string()
    } else {
        roles
            .iter()
            .map(WalletRole::as_str)
            .collect::<Vec<_>>()
            .join(", ")
    }
}

fn render_backup_metadata(metadata: &BackupMetadataDto) {
    println!("  Version           : {}", metadata.version);
    println!("  Schema checksum   : {}", metadata.schema_checksum);
    println!("  Created at (ms)   : {}", metadata.created_at_ms);
    println!(
        "  Includes keystore : {}",
        format_bool(metadata.has_keystore)
    );
    println!("  Policy entries    : {}", metadata.policy_entries);
    println!("  Metadata entries  : {}", metadata.meta_entries);
    println!(
        "  Includes checksums: {}",
        format_bool(metadata.include_checksums)
    );
}

fn render_draft_summary(draft: &CreateTxResponse) {
    println!("  Draft ID      : {}", draft.draft_id);
    println!("  Fee rate      : {} sat/vB", draft.fee_rate);
    println!("  Fee           : {}", format_amount(draft.fee));
    if let Some(source) = &draft.fee_source {
        println!("  Fee source    : {}", describe_fee_source(source));
    }
    println!(
        "  Total inputs  : {}",
        format_amount(draft.total_input_value)
    );
    println!(
        "  Total outputs : {}",
        format_amount(draft.total_output_value)
    );
    println!(
        "  Spend model   : {}",
        format_spend_model(&draft.spend_model)
    );

    if !draft.inputs.is_empty() {
        println!("\n  Inputs:");
        println!(
            "    {:<68} {:>12} {:>14}",
            "Outpoint", "Value", "Confirmations"
        );
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

    if draft.multisig.is_some() {
        println!("\n  Multisig:");
        render_multisig_metadata(draft.multisig.as_ref());
    }

    render_locks(&draft.locks);
}

fn render_locks(locks: &[PendingLockDto]) {
    if locks.is_empty() {
        println!("\n  Locks        : none");
        return;
    }
    println!("\n  Locks:");
    println!(
        "    {:<68} {:>16} {:<12} {:>14} {:>14} {:>14} {:>64}",
        "Outpoint",
        "Locked at (ms)",
        "Backend",
        "Witness (B)",
        "Proof (B)",
        "Duration (ms)",
        "Spending txid"
    );
    for PendingLockDto {
        utxo_txid,
        utxo_index,
        locked_at_ms,
        spending_txid,
        backend,
        witness_bytes,
        proof_bytes,
        prove_duration_ms,
    } in locks
    {
        let outpoint = format!("{}:{}", utxo_txid, utxo_index);
        let spending = spending_txid.clone().unwrap_or_else(|| "-".to_string());
        let backend = if backend.is_empty() {
            "-".to_string()
        } else {
            backend.clone()
        };
        let proof = proof_bytes
            .map(|bytes| bytes.to_string())
            .unwrap_or_else(|| "-".to_string());
        println!(
            "    {:<68} {:>16} {:<12} {:>14} {:>14} {:>14} {:>64}",
            outpoint, locked_at_ms, backend, witness_bytes, proof, prove_duration_ms, spending
        );
    }
}

fn render_multisig_scope(scope: Option<&MultisigScopeDto>) {
    match scope {
        Some(scope) => {
            println!(
                "  Scope        : {}-of-{}",
                scope.threshold, scope.participants
            );
            let required = if scope.threshold > 1 {
                "required"
            } else {
                "optional"
            };
            println!("  Collaboration: {}", required);
        }
        None => println!("  Scope        : not configured"),
    }
}

fn render_cosigners(cosigners: &[CosignerDto]) {
    if cosigners.is_empty() {
        println!("  Cosigners    : none");
        return;
    }
    println!("  Cosigners    :");
    for cosigner in cosigners {
        if let Some(endpoint) = &cosigner.endpoint {
            println!("    - {} ({})", cosigner.fingerprint, endpoint);
        } else {
            println!("    - {}", cosigner.fingerprint);
        }
    }
}

fn render_multisig_metadata(metadata: Option<&MultisigDraftMetadataDto>) {
    match metadata {
        Some(metadata) => {
            render_multisig_scope(Some(&metadata.scope));
            render_cosigners(&metadata.cosigners);
        }
        None => println!("  Metadata     : not available"),
    }
}

fn parse_cosigner(value: &str) -> Result<CosignerDto, WalletCliError> {
    let (fingerprint, endpoint) = match value.split_once('@') {
        Some((fingerprint, endpoint)) => (fingerprint.to_string(), Some(endpoint.to_string())),
        None => (value.to_string(), None),
    };
    Cosigner::new(fingerprint.clone(), endpoint.clone())
        .map_err(|err| WalletCliError::Other(anyhow!(err)))?;
    Ok(CosignerDto {
        fingerprint,
        endpoint,
    })
}

fn format_spend_model(model: &DraftSpendModelDto) -> &'static str {
    match model {
        DraftSpendModelDto::Exact { .. } => "exact",
        DraftSpendModelDto::Sweep => "sweep",
        DraftSpendModelDto::Account { .. } => "account",
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

fn describe_fee_source(source: &FeeEstimateSourceDto) -> String {
    match source {
        FeeEstimateSourceDto::Override => "override".to_string(),
        FeeEstimateSourceDto::ConfigFallback => "config fallback".to_string(),
        FeeEstimateSourceDto::Node {
            congestion,
            samples,
        } => {
            let congestion = match congestion {
                FeeCongestionDto::Low => "low",
                FeeCongestionDto::Moderate => "moderate",
                FeeCongestionDto::High => "high",
                FeeCongestionDto::Unknown => "unknown",
            };
            format!("node ({congestion} congestion, {samples} samples)")
        }
    }
}

fn render_watch_only_status(status: &WatchOnlyStatusResponse) {
    println!("  Enabled   : {}", format_bool(status.enabled));
    if let Some(descriptor) = &status.external_descriptor {
        println!("  External  : {}", descriptor);
    }
    if let Some(descriptor) = &status.internal_descriptor {
        println!("  Internal  : {}", descriptor);
    }
    if let Some(xpub) = &status.account_xpub {
        println!("  Account   : {}", xpub);
    }
    if let Some(height) = status.birthday_height {
        println!("  Birthday  : {}", height);
    }
}

fn persist_keypair(
    path: &Path,
    signing_key: &SigningKey,
    passphrase: Option<&Zeroizing<Vec<u8>>>,
) -> Result<()> {
    if let Some(passphrase) = passphrase {
        persist_encrypted_keypair(path, signing_key, passphrase)
    } else {
        persist_plaintext_keypair(path, signing_key)
    }
}

fn persist_plaintext_keypair(path: &Path, signing_key: &SigningKey) -> Result<()> {
    #[derive(Serialize)]
    struct PlaintextKeypair<'a> {
        public_key: String,
        secret_key: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        signature: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        message: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        format: Option<&'a str>,
    }

    let stored = PlaintextKeypair {
        public_key: hex::encode(signing_key.verifying_key().to_bytes()),
        secret_key: hex::encode(signing_key.to_bytes()),
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

fn persist_encrypted_keypair(
    path: &Path,
    signing_key: &SigningKey,
    passphrase: &Zeroizing<Vec<u8>>,
) -> Result<()> {
    let keystore = encrypt_keypair(signing_key, passphrase)?;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let encoded =
        toml::to_string_pretty(&keystore).context("failed to encode encrypted wallet keypair")?;
    fs::write(path, encoded)?;
    Ok(())
}

fn encrypt_keypair(
    signing_key: &SigningKey,
    passphrase: &Zeroizing<Vec<u8>>,
) -> Result<EncryptedKeystore> {
    let mut rng = OsRng;
    let mut salt = [0u8; SALT_LEN];
    rng.fill_bytes(&mut salt);
    let mut nonce = [0u8; NONCE_LEN];
    rng.fill_bytes(&mut nonce);

    let params = build_argon2_params()?;
    let mut key = Zeroizing::new([0u8; SYMMETRIC_KEY_LEN]);
    derive_symmetric_key(passphrase, &salt, &params, &mut key)?;

    let cipher = ChaCha20Poly1305::new(Key::from_slice(&*key));
    let stored = StoredKeypair::from_signing_key(signing_key);
    let plaintext =
        Zeroizing::new(serde_json::to_vec(&stored).context("failed to serialise wallet keypair")?);
    let ciphertext = cipher
        .encrypt(Nonce::from_slice(&nonce), plaintext.as_ref())
        .context("failed to encrypt wallet keypair")?;

    let mut key = key;
    key.zeroize();
    debug_assert_zeroized(&*key);

    let mut plaintext = plaintext;
    plaintext.zeroize();
    debug_assert_zeroized(plaintext.as_ref());

    Ok(EncryptedKeystore {
        version: KEYSTORE_VERSION,
        cipher: CipherMetadata {
            algorithm: CIPHER_ALGORITHM.to_string(),
            nonce: BASE64.encode(nonce),
        },
        kdf: KdfMetadata {
            algorithm: KDF_ALGORITHM.to_string(),
            memory_kib: ARGON2_MEMORY_COST_KIB,
            iterations: ARGON2_TIME_COST,
            parallelism: ARGON2_PARALLELISM,
            salt: BASE64.encode(salt),
        },
        ciphertext: BASE64.encode(ciphertext),
    })
}

fn derive_symmetric_key(
    passphrase: &Zeroizing<Vec<u8>>,
    salt: &[u8],
    params: &Params,
    out: &mut [u8; SYMMETRIC_KEY_LEN],
) -> Result<()> {
    let argon2 = Argon2::new_with_secret(&[], Algorithm::Argon2id, Version::V0x13, params.clone())
        .context("failed to initialise argon2")?;
    argon2
        .hash_password_into(passphrase.as_ref(), salt, out)
        .context("failed to derive wallet keystore key")?;
    Ok(())
}

fn build_argon2_params() -> Result<Params> {
    ParamsBuilder::new()
        .m_cost(ARGON2_MEMORY_COST_KIB)
        .t_cost(ARGON2_TIME_COST)
        .p_cost(ARGON2_PARALLELISM)
        .output_len(SYMMETRIC_KEY_LEN)
        .context("invalid argon2 parameter set")?
        .build()
        .context("invalid argon2 parameter set")
}

fn debug_assert_zeroized(buf: &[u8]) {
    debug_assert!(buf.iter().all(|byte| *byte == 0));
}

const KEYSTORE_VERSION: u32 = 1;
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 12;
const SYMMETRIC_KEY_LEN: usize = 32;
const ARGON2_MEMORY_COST_KIB: u32 = 64 * 1024;
const ARGON2_TIME_COST: u32 = 3;
const ARGON2_PARALLELISM: u32 = 1;
const CIPHER_ALGORITHM: &str = "chacha20poly1305";
const KDF_ALGORITHM: &str = "argon2id";

#[derive(Serialize, Deserialize)]
struct StoredKeypair {
    public_key: String,
    secret_key: String,
}

impl StoredKeypair {
    fn from_signing_key(signing_key: &SigningKey) -> Self {
        let verifying = signing_key.verifying_key();
        Self {
            public_key: hex::encode(verifying.to_bytes()),
            secret_key: hex::encode(signing_key.to_bytes()),
        }
    }
}

#[derive(Serialize, Deserialize)]
struct CipherMetadata {
    algorithm: String,
    nonce: String,
}

#[derive(Serialize, Deserialize)]
struct KdfMetadata {
    algorithm: String,
    memory_kib: u32,
    iterations: u32,
    parallelism: u32,
    salt: String,
}

#[derive(Serialize, Deserialize)]
struct EncryptedKeystore {
    version: u32,
    cipher: CipherMetadata,
    kdf: KdfMetadata,
    ciphertext: String,
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
            engine_backup_dir: self.wallet.engine.backup_path,
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
    #[serde(default = "default_engine_backup_dir")]
    backup_path: PathBuf,
}

impl Default for WalletEngineSection {
    fn default() -> Self {
        Self {
            data_dir: default_engine_data_dir(),
            keystore_path: default_engine_keystore(),
            backup_path: default_engine_backup_dir(),
        }
    }
}

#[derive(Debug, Clone)]
struct ConfigPaths {
    keys_path: PathBuf,
    engine_data_dir: PathBuf,
    engine_keystore: PathBuf,
    engine_backup_dir: PathBuf,
}

impl Default for ConfigPaths {
    fn default() -> Self {
        Self {
            keys_path: default_keys_path(),
            engine_data_dir: default_engine_data_dir(),
            engine_keystore: default_engine_keystore(),
            engine_backup_dir: default_engine_backup_dir(),
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

fn default_engine_backup_dir() -> PathBuf {
    PathBuf::from("./data/wallet/backups")
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
        let cli = TestCli::parse_from(["wallet", "balance", "--endpoint", "http://localhost:9000"]);
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
    fn parses_backup_export_command() {
        let cli = TestCli::parse_from([
            "wallet",
            "backup",
            "export",
            "--metadata-only",
            "--skip-checksums",
        ]);
        match cli.command {
            WalletCommand::Backup(BackupCommand {
                command: BackupSubcommand::Export(cmd),
            }) => {
                assert!(cmd.metadata_only);
                assert!(cmd.skip_checksums);
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
            fee_source: Some(FeeEstimateSourceDto::Override),
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
            locks: Vec::new(),
            multisig: None,
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
