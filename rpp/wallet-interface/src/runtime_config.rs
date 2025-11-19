use std::collections::BTreeSet;
use std::net::SocketAddr;
use std::path::PathBuf;

use base64ct::{Base64, Encoding};
use clap::ValueEnum;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use thiserror::Error;

const QUEUE_WEIGHT_SUM_TOLERANCE: f64 = 1e-6;
const WALLET_GUI_DEFAULT_POLL_INTERVAL_MS: u64 = 5_000;
const WALLET_GUI_MIN_POLL_INTERVAL_MS: u64 = 1_000;
const WALLET_GUI_DEFAULT_MAX_HISTORY_ROWS: u32 = 20;
const WALLET_GUI_MIN_HISTORY_ROWS: u32 = 5;
const DEFAULT_GAP_LIMIT: u32 = 20;
const DEFAULT_MIN_CONFIRMATIONS: u32 = 1;
const DEFAULT_MIN_FEE_RATE: u64 = 1;
const DEFAULT_MAX_FEE_RATE: u64 = 200;
const DEFAULT_FEE_RATE: u64 = 5;
const DEFAULT_DUST_LIMIT: u128 = 546;
const DEFAULT_MAX_CHANGE_OUTPUTS: u32 = 1;
const DEFAULT_PENDING_LOCK_TIMEOUT_SECS: u64 = 600;
const DEFAULT_FEE_TARGET_CONFIRMATIONS: u16 = 3;
const DEFAULT_HEURISTIC_MIN_FEE_RATE: u64 = 2;
const DEFAULT_HEURISTIC_MAX_FEE_RATE: u64 = 100;
const DEFAULT_FEE_CACHE_TTL_SECS: u64 = 30;
const DEFAULT_PROVER_TIMEOUT_SECS: u64 = 300;
const DEFAULT_PROVER_MAX_WITNESS_BYTES: u64 = 16 * 1024 * 1024;
const DEFAULT_PROVER_MAX_CONCURRENCY: u32 = 1;

/// Result type returned by runtime configuration helpers.
pub type RuntimeConfigResult<T> = Result<T, RuntimeConfigError>;

/// Errors surfaced when validating runtime configuration payloads.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum RuntimeConfigError {
    /// Configuration values failed validation.
    #[error("invalid runtime configuration: {0}")]
    InvalidConfig(String),
}

/// Supported runtime modes for the binary.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, ValueEnum)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeMode {
    /// Run the full node stack.
    Node,
    /// Run the wallet runtime.
    Wallet,
    /// Run both the node and wallet runtimes.
    Hybrid,
    /// Run the validator runtime.
    Validator,
}

impl RuntimeMode {
    /// Returns true when the mode requires the node runtime.
    pub const fn includes_node(self) -> bool {
        matches!(
            self,
            RuntimeMode::Node | RuntimeMode::Hybrid | RuntimeMode::Validator
        )
    }

    /// Returns true when the mode requires the wallet runtime.
    pub const fn includes_wallet(self) -> bool {
        matches!(
            self,
            RuntimeMode::Wallet | RuntimeMode::Hybrid | RuntimeMode::Validator
        )
    }

    /// Returns a stable string representation for the mode.
    pub const fn as_str(self) -> &'static str {
        match self {
            RuntimeMode::Node => "node",
            RuntimeMode::Wallet => "wallet",
            RuntimeMode::Hybrid => "hybrid",
            RuntimeMode::Validator => "validator",
        }
    }

    /// Default configuration path for the node runtime when available.
    pub const fn default_node_config_path(self) -> Option<&'static str> {
        match self {
            RuntimeMode::Node => Some("config/node.toml"),
            RuntimeMode::Hybrid => Some("config/hybrid.toml"),
            RuntimeMode::Validator => Some("config/validator.toml"),
            RuntimeMode::Wallet => None,
        }
    }

    /// Default configuration path for the wallet runtime when available.
    pub const fn default_wallet_config_path(self) -> Option<&'static str> {
        match self {
            RuntimeMode::Wallet | RuntimeMode::Hybrid | RuntimeMode::Validator => {
                Some("config/wallet.toml")
            }
            RuntimeMode::Node => None,
        }
    }
}

impl Default for RuntimeMode {
    fn default() -> Self {
        RuntimeMode::Node
    }
}

/// Relative weights assigned to priority queues in the mempool.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct QueueWeightsConfig {
    /// Weight assigned to the priority queue.
    pub priority: f64,
    /// Weight assigned to the fee queue.
    pub fee: f64,
}

impl QueueWeightsConfig {
    /// Validates that the weight distribution is sane.
    pub fn validate(&self) -> RuntimeConfigResult<()> {
        if self.priority.is_nan() || self.fee.is_nan() {
            return Err(RuntimeConfigError::InvalidConfig(
                "queue_weights priority and fee must be finite numbers".into(),
            ));
        }
        if self.priority < 0.0 {
            return Err(RuntimeConfigError::InvalidConfig(
                "queue_weights.priority must be greater than or equal to 0.0".into(),
            ));
        }
        if self.fee < 0.0 {
            return Err(RuntimeConfigError::InvalidConfig(
                "queue_weights.fee must be greater than or equal to 0.0".into(),
            ));
        }
        let sum = self.priority + self.fee;
        if (sum - 1.0).abs() > QUEUE_WEIGHT_SUM_TOLERANCE {
            return Err(RuntimeConfigError::InvalidConfig(
                "queue_weights priority and fee must sum to 1.0".into(),
            ));
        }
        Ok(())
    }
}

impl Default for QueueWeightsConfig {
    fn default() -> Self {
        Self {
            priority: 0.7,
            fee: 0.3,
        }
    }
}

/// Aggregated status describing the contents of the runtime mempool.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct MempoolStatus {
    /// Pending transactions observed in the mempool.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub transactions: Vec<Value>,
    /// Pending identities.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub identities: Vec<Value>,
    /// Pending votes.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub votes: Vec<Value>,
    /// Pending uptime proofs.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub uptime_proofs: Vec<Value>,
    /// Queue weight configuration applied to the mempool.
    pub queue_weights: QueueWeightsConfig,
}

/// Static assignment between an identity and the set of roles it should have.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct WalletSecurityBinding {
    /// Identity extracted from RPC requests.
    pub identity: WalletIdentity,
    /// Roles assigned to the identity.
    #[serde(default)]
    pub roles: WalletRoleSet,
}

impl WalletSecurityBinding {
    /// Construct a new binding for the provided identity and roles.
    pub fn new(identity: WalletIdentity, roles: WalletRoleSet) -> Self {
        Self { identity, roles }
    }
}

/// Identity extracted from an RPC request.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind", content = "id")]
pub enum WalletIdentity {
    /// Bearer token presented via the `Authorization` header.
    Token(String),
    /// TLS client certificate fingerprint (SHA-256).
    Certificate(String),
}

impl WalletIdentity {
    /// Construct an identity from a bearer token by hashing it with SHA-256.
    pub fn from_bearer_token(token: &str) -> Self {
        Self::Token(hex_digest(token.as_bytes()))
    }

    /// Construct an identity from a DER-encoded certificate.
    pub fn from_certificate_der(der: &[u8]) -> Self {
        Self::Certificate(hex_digest(der))
    }

    /// Construct an identity from a PEM-encoded certificate.
    pub fn from_certificate_pem(pem: &str) -> WalletIdentityResult<Self> {
        let der = decode_pem(pem)?;
        Ok(Self::from_certificate_der(&der))
    }

    /// Construct an identity from a pre-computed fingerprint.
    pub fn from_certificate_fingerprint(fingerprint: &str) -> WalletIdentityResult<Self> {
        let trimmed = fingerprint.trim();
        if trimmed.is_empty() {
            return Err(WalletIdentityError::EmptyFingerprint);
        }
        if !trimmed.chars().all(|ch| ch.is_ascii_hexdigit()) {
            return Err(WalletIdentityError::NonHexFingerprint);
        }
        Ok(Self::Certificate(trimmed.to_lowercase()))
    }
}

/// Wallet roles recognised by the runtime RBAC layer.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WalletRole {
    /// Full administrative control over the wallet runtime.
    Admin,
    /// Operational control (e.g. rescans, draft creation).
    Operator,
    /// Read-only access to wallet state.
    Viewer,
}

impl WalletRole {
    /// Returns the stable string representation for the role.
    pub const fn as_str(&self) -> &'static str {
        match self {
            WalletRole::Admin => "admin",
            WalletRole::Operator => "operator",
            WalletRole::Viewer => "viewer",
        }
    }
}

/// Collection type tracking the roles associated with a request or identity.
pub type WalletRoleSet = BTreeSet<WalletRole>;

/// Errors surfaced when constructing wallet identities.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum WalletIdentityError {
    /// The provided fingerprint was empty.
    #[error("certificate fingerprint must not be empty")]
    EmptyFingerprint,
    /// The provided fingerprint contained non-hexadecimal characters.
    #[error("certificate fingerprint must be hexadecimal")]
    NonHexFingerprint,
    /// The PEM payload was invalid.
    #[error("invalid certificate pem: {0}")]
    InvalidCertificatePem(String),
}

/// Result alias returned by wallet identity helpers.
pub type WalletIdentityResult<T> = Result<T, WalletIdentityError>;

/// Certificate fingerprint metadata surfaced in the configuration file.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct WalletRpcSecurityCaFingerprint {
    /// Hex-encoded SHA-256 fingerprint.
    pub fingerprint: String,
    /// Optional operator-supplied description.
    #[serde(default)]
    pub description: Option<String>,
}

impl WalletRpcSecurityCaFingerprint {
    /// Validates the fingerprint entry.
    pub fn validate(&self, label: &str) -> RuntimeConfigResult<()> {
        let trimmed = self.fingerprint.trim();
        if trimmed.is_empty() {
            return Err(RuntimeConfigError::InvalidConfig(format!(
                "{label} entries must not contain empty fingerprints"
            )));
        }
        if !trimmed.chars().all(|ch| ch.is_ascii_hexdigit()) {
            return Err(RuntimeConfigError::InvalidConfig(format!(
                "{label} fingerprints must be hexadecimal"
            )));
        }
        Ok(())
    }
}

/// Static bindings associating certificate/token identities with wallet roles.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct WalletRpcSecurityBinding {
    /// Identity matched during request authentication.
    pub identity: WalletIdentity,
    /// Roles assigned to the identity.
    #[serde(default)]
    pub roles: Vec<WalletRole>,
}

impl WalletRpcSecurityBinding {
    /// Validates the binding entry.
    pub fn validate(&self, label: &str) -> RuntimeConfigResult<()> {
        if self.roles.is_empty() {
            return Err(RuntimeConfigError::InvalidConfig(format!(
                "{label} entry for identity {:?} must define at least one role",
                self.identity
            )));
        }
        Ok(())
    }

    /// Converts the binding into a runtime assignment.
    pub fn to_runtime_binding(&self) -> WalletSecurityBinding {
        let roles: WalletRoleSet = self.roles.iter().copied().collect();
        WalletSecurityBinding::new(self.identity.clone(), roles)
    }
}

fn decode_pem(pem: &str) -> WalletIdentityResult<Vec<u8>> {
    let mut body = String::new();
    for line in pem.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("-----BEGIN") || trimmed.starts_with("-----END") {
            continue;
        }
        body.push_str(trimmed);
    }
    Base64::decode_vec(&body)
        .map_err(|err| WalletIdentityError::InvalidCertificatePem(err.to_string()))
}

fn hex_digest(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hex::encode(hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_identity_hashes_secret() {
        let identity = WalletIdentity::from_bearer_token("secret");
        assert!(matches!(identity, WalletIdentity::Token(hash) if hash.len() == 64));
    }

    #[test]
    fn certificate_identity_from_pem() {
        let pem = "-----BEGIN CERTIFICATE-----\nZmFrZWNlcnQ=\n-----END CERTIFICATE-----";
        let identity = WalletIdentity::from_certificate_pem(pem).expect("identity");
        assert!(matches!(identity, WalletIdentity::Certificate(_)));
    }

    #[test]
    fn certificate_parsing_normalises_fingerprint() {
        let der = b"certificate-bytes";
        let fingerprint_from_der = WalletIdentity::from_certificate_der(der);
        let pem = format!(
            "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----",
            Base64::encode_string(der)
        );
        let fingerprint_from_pem =
            WalletIdentity::from_certificate_pem(&pem).expect("fingerprint from pem");
        assert_eq!(fingerprint_from_der, fingerprint_from_pem);
    }

    #[test]
    fn fingerprint_parser_rejects_invalid_input() {
        assert_eq!(
            WalletIdentity::from_certificate_fingerprint(""),
            Err(WalletIdentityError::EmptyFingerprint)
        );
        assert_eq!(
            WalletIdentity::from_certificate_fingerprint("not-hex"),
            Err(WalletIdentityError::NonHexFingerprint)
        );
    }
}

/// Wallet RPC listener configuration.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct WalletRpcConfig {
    /// Socket address to bind for wallet RPC requests.
    #[serde(default = "default_wallet_rpc_listen")]
    pub listen: SocketAddr,
    /// Optional browser origin allowed for GUI requests.
    pub allowed_origin: Option<String>,
    /// Optional request-per-minute limit enforced by the runtime.
    pub requests_per_minute: Option<u64>,
    /// TLS configuration for the RPC server.
    pub security: WalletRpcSecurityConfig,
}

impl WalletRpcConfig {
    /// Validates listener and security configuration.
    pub fn validate(&self, mtls_enabled: bool) -> RuntimeConfigResult<()> {
        if let Some(origin) = &self.allowed_origin {
            if origin.trim().is_empty() {
                return Err(RuntimeConfigError::InvalidConfig(
                    "wallet configuration wallet.rpc.allowed_origin must not be empty".into(),
                ));
            }
        }
        if let Some(limit) = self.requests_per_minute {
            if limit == 0 {
                return Err(RuntimeConfigError::InvalidConfig(
                    "wallet configuration wallet.rpc.requests_per_minute must be greater than 0"
                        .into(),
                ));
            }
        }
        self.security.validate(mtls_enabled)
    }
}

impl Default for WalletRpcConfig {
    fn default() -> Self {
        Self {
            listen: default_wallet_rpc_listen(),
            allowed_origin: None,
            requests_per_minute: None,
            security: WalletRpcSecurityConfig::default(),
        }
    }
}

fn default_wallet_rpc_listen() -> SocketAddr {
    "127.0.0.1:9090".parse().expect("valid socket addr")
}

/// TLS configuration for the wallet RPC server.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct WalletRpcSecurityConfig {
    /// Server certificate presented to clients.
    pub certificate: Option<PathBuf>,
    /// Private key associated with the certificate.
    pub private_key: Option<PathBuf>,
    /// Optional CA certificate used to validate clients.
    pub ca_certificate: Option<PathBuf>,
}

impl WalletRpcSecurityConfig {
    /// Validates TLS configuration consistency.
    pub fn validate(&self, mtls_enabled: bool) -> RuntimeConfigResult<()> {
        if !cfg!(feature = "wallet_rpc_mtls") {
            if self.certificate.is_some()
                || self.private_key.is_some()
                || self.ca_certificate.is_some()
            {
                return Err(wallet_rpc_mtls_disabled_error("wallet.rpc.security"));
            }
            return Ok(());
        }

        if mtls_enabled {
            for (path, field) in [
                (&self.certificate, "wallet.rpc.security.certificate"),
                (&self.private_key, "wallet.rpc.security.private_key"),
                (&self.ca_certificate, "wallet.rpc.security.ca_certificate"),
            ] {
                let path = path.as_ref().ok_or_else(|| {
                    RuntimeConfigError::InvalidConfig(format!(
                        "{field} must be provided when TLS security is enabled"
                    ))
                })?;
                if path.as_os_str().is_empty() {
                    return Err(RuntimeConfigError::InvalidConfig(format!(
                        "{field} must not be empty"
                    )));
                }
                if !path.exists() {
                    return Err(RuntimeConfigError::InvalidConfig(format!(
                        "{field} references {} which does not exist",
                        path.display()
                    )));
                }
            }
        } else if self.certificate.is_some()
            || self.private_key.is_some()
            || self.ca_certificate.is_some()
        {
            return Err(RuntimeConfigError::InvalidConfig(
                "wallet.rpc.security certificate, private_key, and ca_certificate require wallet.security.mtls_enabled"
                    .into(),
            ));
        }
        Ok(())
    }
}

impl Default for WalletRpcSecurityConfig {
    fn default() -> Self {
        Self {
            certificate: None,
            private_key: None,
            ca_certificate: None,
        }
    }
}

/// Wallet audit configuration surfaced by the runtime.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct WalletAuditConfig {
    /// Enable audit logging for wallet operations.
    pub enabled: bool,
    /// Number of days to retain audit logs on disk.
    pub retention_days: u64,
}

impl Default for WalletAuditConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            retention_days: 30,
        }
    }
}

/// Wallet authentication configuration surfaced to operators.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct WalletAuthConfig {
    /// Enable token-based authentication for RPC requests.
    pub enabled: bool,
    /// Token required when authentication is enabled.
    pub token: Option<String>,
    /// Optional TLS requirements for authenticated flows.
    pub tls: Option<WalletAuthTlsConfig>,
}

impl WalletAuthConfig {
    /// Validates the auth configuration.
    pub fn validate(&self, require_tls: bool) -> RuntimeConfigResult<()> {
        if !self.enabled {
            if let Some(tls) = &self.tls {
                if tls.is_configured() {
                    tls.validate("wallet.auth.tls")?;
                }
            }
            return Ok(());
        }

        match self
            .token
            .as_ref()
            .map(|value| value.trim())
            .filter(|v| !v.is_empty())
        {
            Some(_) => {}
            None => {
                return Err(RuntimeConfigError::InvalidConfig(
                    "wallet configuration wallet.auth.token must be provided when authentication is enabled"
                        .into(),
                ));
            }
        }

        if require_tls {
            let tls = self.tls.as_ref().ok_or_else(|| {
                RuntimeConfigError::InvalidConfig(
                    "wallet configuration wallet.auth.tls must be configured when authentication is enabled"
                        .into(),
                )
            })?;
            tls.validate("wallet.auth.tls")?;
        } else if let Some(tls) = &self.tls {
            tls.validate("wallet.auth.tls")?;
        }

        Ok(())
    }
}

impl Default for WalletAuthConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            token: None,
            tls: None,
        }
    }
}

/// TLS requirements enforced for wallet authentication.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct WalletAuthTlsConfig {
    /// Client certificate presented when authenticating against the RPC server.
    pub certificate: Option<PathBuf>,
    /// Private key associated with the certificate.
    pub private_key: Option<PathBuf>,
    /// Optional CA certificate bundle.
    pub ca_certificate: Option<PathBuf>,
}

impl WalletAuthTlsConfig {
    fn is_configured(&self) -> bool {
        self.certificate.is_some() || self.private_key.is_some() || self.ca_certificate.is_some()
    }

    fn validate(&self, label: &str) -> RuntimeConfigResult<()> {
        let certificate = self.certificate.as_ref().ok_or_else(|| {
            RuntimeConfigError::InvalidConfig(format!(
                "wallet configuration {label}.certificate must be provided when TLS is enabled"
            ))
        })?;
        let private_key = self.private_key.as_ref().ok_or_else(|| {
            RuntimeConfigError::InvalidConfig(format!(
                "wallet configuration {label}.private_key must be provided when TLS is enabled"
            ))
        })?;

        for (path, field) in [(certificate, "certificate"), (private_key, "private_key")] {
            if path.as_os_str().is_empty() {
                return Err(RuntimeConfigError::InvalidConfig(format!(
                    "wallet configuration {label}.{field} must not be empty"
                )));
            }
            if !path.exists() {
                return Err(RuntimeConfigError::InvalidConfig(format!(
                    "wallet configuration {label}.{field} references {} which does not exist",
                    path.display()
                )));
            }
        }

        if let Some(ca) = &self.ca_certificate {
            if ca.as_os_str().is_empty() {
                return Err(RuntimeConfigError::InvalidConfig(format!(
                    "wallet configuration {label}.ca_certificate must not be empty"
                )));
            }
            if !ca.exists() {
                return Err(RuntimeConfigError::InvalidConfig(format!(
                    "wallet configuration {label}.ca_certificate references {} which does not exist",
                    ca.display()
                )));
            }
        }

        Ok(())
    }
}

impl Default for WalletAuthTlsConfig {
    fn default() -> Self {
        Self {
            certificate: None,
            private_key: None,
            ca_certificate: None,
        }
    }
}

/// Wallet key management configuration.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct WalletKeysConfig {
    /// Path pointing to the wallet keystore bundle.
    pub key_path: PathBuf,
}

impl WalletKeysConfig {
    /// Validates the key configuration.
    pub fn validate(&self) -> RuntimeConfigResult<()> {
        if self.key_path.as_os_str().is_empty() {
            return Err(RuntimeConfigError::InvalidConfig(
                "wallet configuration wallet.keys.key_path must not be empty".into(),
            ));
        }
        Ok(())
    }
}

impl Default for WalletKeysConfig {
    fn default() -> Self {
        Self {
            key_path: PathBuf::from("./keys/wallet.toml"),
        }
    }
}

/// Wallet rate limiting budgets for RPC flows.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct WalletBudgetsConfig {
    /// Allowed transactions per minute.
    pub submit_transaction_per_minute: u64,
    /// Allowed prover jobs per minute.
    pub proof_generation_per_minute: u64,
    /// Depth of the proof pipeline.
    pub pipeline_depth: usize,
}

impl WalletBudgetsConfig {
    /// Validates budget constraints.
    pub fn validate(&self) -> RuntimeConfigResult<()> {
        if self.submit_transaction_per_minute == 0 {
            return Err(RuntimeConfigError::InvalidConfig(
                "wallet configuration wallet.budgets.submit_transaction_per_minute must be greater than 0"
                    .into(),
            ));
        }
        if self.proof_generation_per_minute == 0 {
            return Err(RuntimeConfigError::InvalidConfig(
                "wallet configuration wallet.budgets.proof_generation_per_minute must be greater than 0"
                    .into(),
            ));
        }
        if self.pipeline_depth == 0 {
            return Err(RuntimeConfigError::InvalidConfig(
                "wallet configuration wallet.budgets.pipeline_depth must be greater than 0".into(),
            ));
        }
        Ok(())
    }
}

impl Default for WalletBudgetsConfig {
    fn default() -> Self {
        Self {
            submit_transaction_per_minute: 120,
            proof_generation_per_minute: 60,
            pipeline_depth: 64,
        }
    }
}

/// Wallet rescan configuration surfaced for operators.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct WalletRescanConfig {
    /// Automatically trigger rescans when drift is detected.
    pub auto_trigger: bool,
    /// Number of blocks to scan backwards when performing a rescan.
    pub lookback_blocks: u64,
    /// Number of blocks to process per batch during rescans.
    pub chunk_size: u64,
}

impl WalletRescanConfig {
    /// Validates rescan configuration limits.
    pub fn validate(&self) -> RuntimeConfigResult<()> {
        if self.lookback_blocks == 0 {
            return Err(RuntimeConfigError::InvalidConfig(
                "wallet configuration wallet.rescan.lookback_blocks must be greater than 0".into(),
            ));
        }
        if self.chunk_size == 0 {
            return Err(RuntimeConfigError::InvalidConfig(
                "wallet configuration wallet.rescan.chunk_size must be greater than 0".into(),
            ));
        }
        Ok(())
    }
}

impl Default for WalletRescanConfig {
    fn default() -> Self {
        Self {
            auto_trigger: false,
            lookback_blocks: 2_880,
            chunk_size: 64,
        }
    }
}

/// Wallet engine configuration surfaced to the runtime.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct WalletEngineSettings {
    /// Directory where the wallet stores state and cache data.
    pub data_dir: PathBuf,
    /// Path to the persisted keystore bundle used by the wallet engine.
    pub keystore_path: PathBuf,
    /// Directory storing encrypted wallet backup archives.
    pub backup_path: PathBuf,
    /// Optional birthday height used when bootstrapping from checkpoints.
    pub birthday_height: Option<u64>,
}

impl Default for WalletEngineSettings {
    fn default() -> Self {
        Self {
            data_dir: PathBuf::from("./data/wallet"),
            keystore_path: PathBuf::from("./data/wallet/keystore.toml"),
            backup_path: PathBuf::from("./data/wallet/backups"),
            birthday_height: None,
        }
    }
}

/// Spending policy constraints enforced by the wallet engine.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct WalletPolicySettings {
    /// Maximum number of unused external addresses tracked by the wallet.
    pub external_gap_limit: u32,
    /// Maximum number of unused change addresses tracked by the wallet.
    pub internal_gap_limit: u32,
    /// Minimum confirmations required before funds become spendable.
    pub min_confirmations: u32,
    /// Threshold below which outputs are considered dust and rejected.
    pub dust_limit: u128,
    /// Cap the number of change outputs emitted by a transaction.
    pub max_change_outputs: u32,
    /// Optional daily spend limit enforced before draft creation succeeds.
    pub spend_limit_daily: Option<u128>,
    /// Timeout (in seconds) after which pending input locks may be released.
    pub pending_lock_timeout: u64,
    /// Hooks coordinating tier-aware policy integrations.
    pub tier: PolicyTierHooks,
}

impl Default for WalletPolicySettings {
    fn default() -> Self {
        Self {
            external_gap_limit: DEFAULT_GAP_LIMIT,
            internal_gap_limit: DEFAULT_GAP_LIMIT,
            min_confirmations: DEFAULT_MIN_CONFIRMATIONS,
            dust_limit: DEFAULT_DUST_LIMIT,
            max_change_outputs: DEFAULT_MAX_CHANGE_OUTPUTS,
            spend_limit_daily: None,
            pending_lock_timeout: DEFAULT_PENDING_LOCK_TIMEOUT_SECS,
            tier: PolicyTierHooks::default(),
        }
    }
}

/// Control tier-aware runtime integrations for wallet policies.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct PolicyTierHooks {
    /// Enable tier integration checks for spending policies.
    pub enabled: bool,
    /// Optional named hook surfaced to clients for bespoke integrations.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hook: Option<String>,
}

impl Default for PolicyTierHooks {
    fn default() -> Self {
        Self {
            enabled: false,
            hook: None,
        }
    }
}

/// Fee rate guidance exposed to RPC consumers.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct WalletFeeSettings {
    /// Default fee rate applied when callers omit an explicit value.
    pub default_sats_per_vbyte: u64,
    /// Lowest allowed fee rate for submitted transactions.
    pub min_sats_per_vbyte: u64,
    /// Highest allowed fee rate for submitted transactions.
    pub max_sats_per_vbyte: u64,
    /// Preferred confirmation target used when sampling node statistics.
    pub target_confirmations: u16,
    /// Lower bound applied to node-derived heuristic estimates.
    pub heuristic_min_sats_per_vbyte: u64,
    /// Upper bound applied to node-derived heuristic estimates.
    pub heuristic_max_sats_per_vbyte: u64,
    /// Duration (in seconds) to cache node-derived estimates before refreshing.
    pub cache_ttl_secs: u64,
}

impl Default for WalletFeeSettings {
    fn default() -> Self {
        Self {
            default_sats_per_vbyte: DEFAULT_FEE_RATE,
            min_sats_per_vbyte: DEFAULT_MIN_FEE_RATE,
            max_sats_per_vbyte: DEFAULT_MAX_FEE_RATE,
            target_confirmations: DEFAULT_FEE_TARGET_CONFIRMATIONS,
            heuristic_min_sats_per_vbyte: DEFAULT_HEURISTIC_MIN_FEE_RATE,
            heuristic_max_sats_per_vbyte: DEFAULT_HEURISTIC_MAX_FEE_RATE,
            cache_ttl_secs: DEFAULT_FEE_CACHE_TTL_SECS,
        }
    }
}

/// Controls prover integration toggles for the wallet runtime.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct WalletProverSettings {
    /// Requested prover backend.
    pub backend: WalletProverBackend,
    /// Require proofs to be produced before drafts can be broadcast.
    pub require_proof: bool,
    /// Allow broadcasting drafts even when proofs are unavailable.
    pub allow_broadcast_without_proof: bool,
    /// Timeout (in seconds) applied to prover jobs before they are aborted.
    pub timeout_secs: u64,
    /// Maximum witness size (in bytes) accepted from prover backends.
    pub max_witness_bytes: u64,
    /// Upper bound on concurrent prover jobs executed by the runtime.
    pub max_concurrency: u32,
}

impl Default for WalletProverSettings {
    fn default() -> Self {
        Self {
            backend: WalletProverBackend::default(),
            require_proof: false,
            allow_broadcast_without_proof: false,
            timeout_secs: DEFAULT_PROVER_TIMEOUT_SECS,
            max_witness_bytes: DEFAULT_PROVER_MAX_WITNESS_BYTES,
            max_concurrency: DEFAULT_PROVER_MAX_CONCURRENCY,
        }
    }
}

/// Supported prover backend selectors for the wallet runtime config.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum WalletProverBackend {
    /// Disable the prover and surface drafts without witnesses.
    Disabled,
    /// Select the lightweight mock prover backend.
    Mock,
    /// Select the STWO prover backend exposed by the runtime.
    Stwo,
}

impl WalletProverBackend {
    /// Returns the canonical string identifier for this backend.
    pub fn as_str(&self) -> &'static str {
        match self {
            WalletProverBackend::Disabled => "disabled",
            WalletProverBackend::Mock => "mock",
            WalletProverBackend::Stwo => "stwo",
        }
    }
}

impl Default for WalletProverBackend {
    fn default() -> Self {
        WalletProverBackend::Mock
    }
}

/// Configure hardware wallet integration toggles.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct WalletHwSettings {
    /// Enable hardware wallet support for signing flows.
    pub enabled: bool,
    /// Transport used to communicate with hardware devices.
    pub transport: WalletHwTransport,
    /// Optional device selector narrowing enumeration results.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device_selector: Option<String>,
    /// Allow falling back to software signing when devices are unavailable.
    pub fallback_to_software: bool,
}

impl WalletHwSettings {
    /// Ensures the configuration matches the compiled feature set.
    pub fn ensure_supported(&self) -> RuntimeConfigResult<()> {
        if self.enabled && !cfg!(feature = "wallet_hw") {
            Err(RuntimeConfigError::InvalidConfig(
                "wallet hardware support requires the `wallet_hw` feature".into(),
            ))
        } else {
            Ok(())
        }
    }
}

impl Default for WalletHwSettings {
    fn default() -> Self {
        Self {
            enabled: false,
            transport: WalletHwTransport::default(),
            device_selector: None,
            fallback_to_software: true,
        }
    }
}

/// Configure wallet telemetry (crash reporting uploads).
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct WalletTelemetrySettings {
    /// Enable anonymized runtime metrics uploads.
    pub metrics: bool,
    /// Enable crash reporting uploads.
    pub crash_reports: bool,
    /// HTTPS endpoint receiving crash payloads.
    pub endpoint: String,
    /// Salt applied when hashing machine identifiers.
    pub machine_id_salt: String,
}

impl WalletTelemetrySettings {
    /// Returns the configured endpoint when present.
    pub fn endpoint(&self) -> Option<&str> {
        if self.endpoint.trim().is_empty() {
            None
        } else {
            Some(self.endpoint.as_str())
        }
    }
}

impl Default for WalletTelemetrySettings {
    fn default() -> Self {
        Self {
            metrics: false,
            crash_reports: false,
            endpoint: String::new(),
            machine_id_salt: String::new(),
        }
    }
}

/// Supported hardware wallet transports.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum WalletHwTransport {
    /// HID transport.
    Hid,
    /// USB transport.
    Usb,
    /// TCP transport.
    Tcp,
}

impl Default for WalletHwTransport {
    fn default() -> Self {
        WalletHwTransport::Hid
    }
}

/// Wallet node runtime configuration.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct WalletNodeRuntimeConfig {
    /// Enable an embedded node alongside the wallet runtime.
    pub embedded: bool,
    /// Gossip peers the wallet should connect to when running in client mode.
    pub gossip_endpoints: Vec<String>,
}

/// GUI-specific configuration surfaced to operators.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct WalletGuiConfig {
    /// Interval (in milliseconds) between sync status polls.
    pub poll_interval_ms: u64,
    /// Maximum number of history entries fetched per page.
    pub max_history_rows: u32,
    /// Preferred visual theme surfaced to the GUI.
    pub theme: WalletGuiTheme,
    /// Require clipboard confirmation before copying sensitive data.
    pub confirm_clipboard: bool,
    /// Opt-in flag for telemetry collection from the GUI.
    pub telemetry_opt_in: bool,
    /// Enable the Security section for managing RPC mTLS + RBAC from the GUI.
    pub security_controls_enabled: bool,
}

impl WalletGuiConfig {
    /// Returns a sanitized copy that clamps out-of-range values.
    pub fn sanitized(mut self) -> Self {
        if self.poll_interval_ms < WALLET_GUI_MIN_POLL_INTERVAL_MS {
            self.poll_interval_ms = WALLET_GUI_MIN_POLL_INTERVAL_MS;
        }
        if self.max_history_rows < WALLET_GUI_MIN_HISTORY_ROWS {
            self.max_history_rows = WALLET_GUI_DEFAULT_MAX_HISTORY_ROWS;
        }
        self
    }
}

impl Default for WalletGuiConfig {
    fn default() -> Self {
        Self {
            poll_interval_ms: WALLET_GUI_DEFAULT_POLL_INTERVAL_MS,
            max_history_rows: WALLET_GUI_DEFAULT_MAX_HISTORY_ROWS,
            theme: WalletGuiTheme::System,
            confirm_clipboard: true,
            telemetry_opt_in: false,
            security_controls_enabled: cfg!(feature = "wallet_rpc_mtls"),
        }
    }
}

/// Appearance theme options exposed to the GUI.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum WalletGuiTheme {
    /// Follow the system theme.
    System,
    /// Force a light theme.
    Light,
    /// Force a dark theme.
    Dark,
}

impl Default for WalletGuiTheme {
    fn default() -> Self {
        WalletGuiTheme::System
    }
}

/// Wallet security configuration encompassing mTLS and RBAC controls.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct WalletSecurityConfig {
    /// Enable mTLS enforcement for wallet RPC requests.
    pub mtls_enabled: bool,
    /// Trusted CA fingerprints recognised by the wallet runtime.
    pub ca_fingerprints: Vec<WalletRpcSecurityCaFingerprint>,
    /// Static RBAC bindings applied on startup.
    pub bindings: Vec<WalletRpcSecurityBinding>,
}

impl WalletSecurityConfig {
    /// Returns true when any security configuration is present.
    pub fn is_configured(&self) -> bool {
        self.mtls_enabled || !self.ca_fingerprints.is_empty() || !self.bindings.is_empty()
    }

    /// Validates the security configuration.
    pub fn validate(&self) -> RuntimeConfigResult<()> {
        if !cfg!(feature = "wallet_rpc_mtls") {
            if self.is_configured() {
                return Err(wallet_rpc_mtls_disabled_error("wallet.security"));
            }
            return Ok(());
        }

        for fingerprint in &self.ca_fingerprints {
            fingerprint.validate("wallet.security.ca_fingerprints")?;
        }
        for binding in &self.bindings {
            binding.validate("wallet.security.bindings")?;
        }
        Ok(())
    }

    /// Converts bindings into runtime assignments.
    pub fn runtime_bindings(&self) -> Vec<WalletSecurityBinding> {
        self.bindings
            .iter()
            .map(WalletRpcSecurityBinding::to_runtime_binding)
            .collect()
    }
}

impl Default for WalletSecurityConfig {
    fn default() -> Self {
        Self {
            mtls_enabled: false,
            ca_fingerprints: Vec::new(),
            bindings: Vec::new(),
        }
    }
}

/// Top-level wallet service configuration exposed by the runtime.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct WalletServiceConfig {
    /// RPC server configuration.
    pub rpc: WalletRpcConfig,
    /// Security configuration for RPC requests.
    pub security: WalletSecurityConfig,
    /// Audit logging controls.
    pub audit: WalletAuditConfig,
    /// Authentication requirements for RPC requests.
    pub auth: WalletAuthConfig,
    /// Key store configuration.
    pub keys: WalletKeysConfig,
    /// Runtime budget configuration for RPC flows.
    pub budgets: WalletBudgetsConfig,
    /// Wallet rescan configuration.
    pub rescan: WalletRescanConfig,
    /// Wallet engine settings.
    pub engine: WalletEngineSettings,
    /// Spending policy settings.
    pub policy: WalletPolicySettings,
    /// Fee configuration exposed to clients.
    pub fees: WalletFeeSettings,
    /// Prover integration settings.
    pub prover: WalletProverSettings,
    /// Hardware wallet integration configuration.
    pub hw: WalletHwSettings,
    /// Telemetry preferences (crash reporting, salts).
    pub telemetry: WalletTelemetrySettings,
}

impl Default for WalletServiceConfig {
    fn default() -> Self {
        Self {
            rpc: WalletRpcConfig::default(),
            security: WalletSecurityConfig::default(),
            audit: WalletAuditConfig::default(),
            auth: WalletAuthConfig::default(),
            keys: WalletKeysConfig::default(),
            budgets: WalletBudgetsConfig::default(),
            rescan: WalletRescanConfig::default(),
            engine: WalletEngineSettings::default(),
            policy: WalletPolicySettings::default(),
            fees: WalletFeeSettings::default(),
            prover: WalletProverSettings::default(),
            hw: WalletHwSettings::default(),
            telemetry: WalletTelemetrySettings::default(),
        }
    }
}

/// High-level wallet configuration surfaced to runtime services.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WalletConfig {
    /// Root directory used for wallet data.
    pub data_dir: PathBuf,
    /// Wallet service configuration.
    #[serde(default)]
    pub wallet: WalletServiceConfig,
    /// Embedded node configuration.
    #[serde(default)]
    pub node: WalletNodeRuntimeConfig,
    /// GUI configuration surfaced to the desktop client.
    #[serde(default)]
    pub gui: WalletGuiConfig,
    /// Optional Electrs vendor configuration.
    #[cfg(feature = "vendor_electrs")]
    #[serde(default)]
    pub electrs: Option<ElectrsConfig>,
}

impl WalletConfig {
    /// Construct a config for the requested runtime mode.
    pub fn for_mode(mode: RuntimeMode) -> Self {
        match mode {
            RuntimeMode::Hybrid => Self::for_hybrid(),
            RuntimeMode::Validator => Self::for_validator(),
            RuntimeMode::Node | RuntimeMode::Wallet => Self::for_wallet(),
        }
    }

    /// Construct a standalone wallet configuration.
    pub fn for_wallet() -> Self {
        Self::default()
    }

    /// Construct a hybrid configuration suitable for wallet + node.
    pub fn for_hybrid() -> Self {
        let mut config = Self::default();
        config.apply_hybrid_defaults();
        config
    }

    /// Construct a validator configuration.
    pub fn for_validator() -> Self {
        let mut config = Self::default();
        config.apply_hybrid_defaults();
        config.apply_validator_defaults();
        config
    }

    fn apply_hybrid_defaults(&mut self) {
        if self.wallet.rpc.requests_per_minute.is_none() {
            self.wallet.rpc.requests_per_minute = Some(600);
        }
        self.node.embedded = false;
        if self.node.gossip_endpoints.is_empty() {
            self.node
                .gossip_endpoints
                .push("/ip4/127.0.0.1/tcp/7600".to_string());
        }

        #[cfg(feature = "vendor_electrs")]
        if let Some(electrs) = self.electrs.as_mut() {
            electrs.features.runtime = true;
            electrs.features.tracker = true;
            electrs.cache.telemetry.enabled = true;
            electrs.tracker.telemetry_endpoint = SocketAddr::from(([127, 0, 0, 1], 9_200));
            electrs.tracker.notifications.p2p = true;
            electrs.p2p.enabled = true;
            electrs.p2p.metrics_endpoint = SocketAddr::from(([127, 0, 0, 1], 9_300));
            electrs.p2p.network_id = "rpp-hybrid".to_string();
            electrs.network = NetworkSelection::Testnet;
        }
    }

    fn apply_validator_defaults(&mut self) {
        #[cfg(feature = "vendor_electrs")]
        if let Some(electrs) = self.electrs.as_mut() {
            electrs.cache.telemetry.enabled = true;
            electrs.tracker.telemetry_endpoint = SocketAddr::from(([127, 0, 0, 1], 9_250));
            electrs.p2p.metrics_endpoint = SocketAddr::from(([127, 0, 0, 1], 9_350));
            electrs.p2p.network_id = "rpp-validator".to_string();
            electrs.tracker.notifications.topic = "/rpp/gossip/finality/1.0.0".to_string();
        }
    }

    /// Validates the wallet configuration.
    pub fn validate(&self) -> RuntimeConfigResult<()> {
        if !cfg!(feature = "wallet_rpc_mtls") && self.wallet.security.is_configured() {
            return Err(wallet_rpc_mtls_disabled_error("wallet.security"));
        }
        self.wallet.security.validate()?;
        self.wallet
            .rpc
            .validate(self.wallet.security.mtls_enabled)?;
        self.wallet.keys.validate()?;
        self.wallet.budgets.validate()?;
        self.wallet.rescan.validate()?;
        validate_wallet_engine(&self.wallet.engine)?;
        validate_wallet_policy(&self.wallet.policy)?;
        validate_wallet_fees(&self.wallet.fees)?;
        validate_wallet_prover(&self.wallet.prover)?;
        self.wallet.hw.ensure_supported()?;
        validate_wallet_telemetry(&self.wallet.telemetry)?;
        self.wallet.auth.validate(false)?;
        if !self.node.embedded && self.node.gossip_endpoints.is_empty() {
            return Err(RuntimeConfigError::InvalidConfig(
                "wallet node runtime requires gossip endpoints when embedded node is disabled"
                    .into(),
            ));
        }
        if self
            .node
            .gossip_endpoints
            .iter()
            .any(|endpoint| endpoint.trim().is_empty())
        {
            return Err(RuntimeConfigError::InvalidConfig(
                "wallet node runtime gossip endpoints must not be empty".into(),
            ));
        }
        Ok(())
    }
}

impl Default for WalletConfig {
    fn default() -> Self {
        Self {
            data_dir: PathBuf::from("./data"),
            wallet: WalletServiceConfig::default(),
            node: WalletNodeRuntimeConfig {
                embedded: false,
                gossip_endpoints: vec!["/ip4/127.0.0.1/tcp/7600".to_string()],
            },
            gui: WalletGuiConfig::default(),
            #[cfg(feature = "vendor_electrs")]
            electrs: Some(ElectrsConfig::default()),
        }
    }
}

fn wallet_rpc_mtls_disabled_error(scope: &str) -> RuntimeConfigError {
    RuntimeConfigError::InvalidConfig(format!(
        "{scope} requires compiling with the `wallet_rpc_mtls` feature; rebuild this binary to configure wallet RPC security"
    ))
}

fn validate_wallet_engine(config: &WalletEngineSettings) -> RuntimeConfigResult<()> {
    if config.data_dir.as_os_str().is_empty() {
        return Err(RuntimeConfigError::InvalidConfig(
            "wallet configuration wallet.engine.data_dir must not be empty".into(),
        ));
    }
    if config.keystore_path.as_os_str().is_empty() {
        return Err(RuntimeConfigError::InvalidConfig(
            "wallet configuration wallet.engine.keystore_path must not be empty".into(),
        ));
    }
    if config.backup_path.as_os_str().is_empty() {
        return Err(RuntimeConfigError::InvalidConfig(
            "wallet configuration wallet.engine.backup_path must not be empty".into(),
        ));
    }
    Ok(())
}

fn validate_wallet_policy(config: &WalletPolicySettings) -> RuntimeConfigResult<()> {
    if config.external_gap_limit == 0 {
        return Err(RuntimeConfigError::InvalidConfig(
            "wallet configuration wallet.policy.external_gap_limit must be greater than 0".into(),
        ));
    }
    if config.internal_gap_limit == 0 {
        return Err(RuntimeConfigError::InvalidConfig(
            "wallet configuration wallet.policy.internal_gap_limit must be greater than 0".into(),
        ));
    }
    if config.min_confirmations == 0 {
        return Err(RuntimeConfigError::InvalidConfig(
            "wallet configuration wallet.policy.min_confirmations must be greater than 0".into(),
        ));
    }
    Ok(())
}

fn validate_wallet_fees(config: &WalletFeeSettings) -> RuntimeConfigResult<()> {
    if config.min_sats_per_vbyte == 0 {
        return Err(RuntimeConfigError::InvalidConfig(
            "wallet configuration wallet.fees.min_sats_per_vbyte must be greater than 0".into(),
        ));
    }
    if config.max_sats_per_vbyte == 0 {
        return Err(RuntimeConfigError::InvalidConfig(
            "wallet configuration wallet.fees.max_sats_per_vbyte must be greater than 0".into(),
        ));
    }
    if config.min_sats_per_vbyte > config.max_sats_per_vbyte {
        return Err(RuntimeConfigError::InvalidConfig(
            "wallet configuration wallet.fees.min_sats_per_vbyte must not exceed max_sats_per_vbyte"
                .into(),
        ));
    }
    if config.default_sats_per_vbyte < config.min_sats_per_vbyte
        || config.default_sats_per_vbyte > config.max_sats_per_vbyte
    {
        return Err(RuntimeConfigError::InvalidConfig(
            "wallet configuration wallet.fees.default_sats_per_vbyte must fall within the configured min/max bounds"
                .into(),
        ));
    }
    Ok(())
}

fn validate_wallet_prover(config: &WalletProverSettings) -> RuntimeConfigResult<()> {
    if config.timeout_secs == 0 {
        return Err(RuntimeConfigError::InvalidConfig(
            "wallet configuration wallet.prover.timeout_secs must be greater than 0".into(),
        ));
    }
    if config.max_witness_bytes == 0 {
        return Err(RuntimeConfigError::InvalidConfig(
            "wallet configuration wallet.prover.max_witness_bytes must be greater than 0".into(),
        ));
    }
    if config.max_witness_bytes > usize::MAX as u64 {
        return Err(RuntimeConfigError::InvalidConfig(
            "wallet configuration wallet.prover.max_witness_bytes must fit into platform usize"
                .into(),
        ));
    }
    if config.max_concurrency == 0 {
        return Err(RuntimeConfigError::InvalidConfig(
            "wallet configuration wallet.prover.max_concurrency must be greater than 0".into(),
        ));
    }
    if config.require_proof && config.allow_broadcast_without_proof {
        return Err(RuntimeConfigError::InvalidConfig(
            "wallet configuration wallet.prover.allow_broadcast_without_proof must be false when proofs are required".into(),
        ));
    }
    if config.require_proof && config.backend == WalletProverBackend::Disabled {
        return Err(RuntimeConfigError::InvalidConfig(
            "wallet configuration wallet.prover.require_proof cannot be true when backend=\"disabled\"".into(),
        ));
    }
    match config.backend {
        WalletProverBackend::Disabled => {}
        WalletProverBackend::Mock => {
            if !cfg!(feature = "prover-mock") {
                return Err(RuntimeConfigError::InvalidConfig(
                    "wallet configuration wallet.prover.backend=\"mock\" requires compiling with the `prover-mock` feature"
                        .into(),
                ));
            }
        }
        WalletProverBackend::Stwo => {
            if !cfg!(feature = "prover-stwo") {
                return Err(RuntimeConfigError::InvalidConfig(
                    "wallet configuration wallet.prover.backend=\"stwo\" requires compiling with the `prover-stwo` feature"
                        .into(),
                ));
            }
        }
    }
    Ok(())
}

fn validate_wallet_telemetry(config: &WalletTelemetrySettings) -> RuntimeConfigResult<()> {
    if config.crash_reports || config.metrics {
        let endpoint = config.endpoint().ok_or_else(|| {
            RuntimeConfigError::InvalidConfig(
                "wallet.telemetry.endpoint must be configured when telemetry uploads are enabled"
                    .into(),
            )
        })?;
        if !endpoint.starts_with("https://") {
            return Err(RuntimeConfigError::InvalidConfig(
                "wallet.telemetry.endpoint must use the https:// scheme".into(),
            ));
        }
    }
    Ok(())
}

#[cfg(feature = "vendor_electrs")]
mod electrs {
    use super::*;

    const DEFAULT_GOSSIP_TOPIC: &str = "/rpp/gossip/blocks/1.0.0";

    /// Configuration options for the Electrs vendor integration.
    #[derive(Clone, Debug, Serialize, Deserialize)]
    #[serde(default)]
    pub struct ElectrsConfig {
        /// Ledger network the wallet should track.
        pub network: NetworkSelection,
        /// Optional feature toggles that enable runtime-backed components.
        pub features: FeatureGates,
        /// Cache configuration for vendor integrations.
        pub cache: CacheConfig,
        /// Tracker-specific configuration options.
        pub tracker: TrackerConfig,
        /// Optional configuration for the P2P bridge used by the daemon.
        pub p2p: P2pConfig,
    }

    impl Default for ElectrsConfig {
        fn default() -> Self {
            Self {
                network: NetworkSelection::Regtest,
                features: FeatureGates::default(),
                cache: CacheConfig::default(),
                tracker: TrackerConfig::default(),
                p2p: P2pConfig::default(),
            }
        }
    }

    /// Supported runtime networks for the Electrs integration.
    #[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
    #[serde(rename_all = "lowercase")]
    pub enum NetworkSelection {
        /// Regtest network.
        Regtest,
        /// Testnet network.
        Testnet,
        /// Signet network.
        Signet,
        /// Mainnet network.
        Mainnet,
    }

    impl Default for NetworkSelection {
        fn default() -> Self {
            NetworkSelection::Regtest
        }
    }

    /// Optional feature toggles for vendor-backed components.
    #[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
    #[serde(default)]
    pub struct FeatureGates {
        /// Attach runtime adapters to the Firewood integration.
        pub runtime: bool,
        /// Bring up the Electrs tracker backed by the runtime daemon.
        pub tracker: bool,
    }

    impl Default for FeatureGates {
        fn default() -> Self {
            Self {
                runtime: false,
                tracker: false,
            }
        }
    }

    /// Cache configuration influencing warmup and telemetry behaviour.
    #[derive(Clone, Debug, Serialize, Deserialize)]
    #[serde(default)]
    pub struct CacheConfig {
        /// Telemetry settings for cache statistics.
        pub telemetry: CacheTelemetryConfig,
    }

    impl Default for CacheConfig {
        fn default() -> Self {
            Self {
                telemetry: CacheTelemetryConfig::default(),
            }
        }
    }

    /// Controls how the cache reports telemetry and where it stores warmup data.
    #[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
    #[serde(default)]
    pub struct CacheTelemetryConfig {
        /// Enable or disable telemetry collection for cache interactions.
        pub enabled: bool,
        /// Optional hex-encoded prefix used when persisting warmup entries.
        pub warmup_prefix: Option<String>,
    }

    impl Default for CacheTelemetryConfig {
        fn default() -> Self {
            Self {
                enabled: false,
                warmup_prefix: None,
            }
        }
    }

    /// Controls tracker-specific behaviour, including telemetry endpoints.
    #[derive(Clone, Debug, Serialize, Deserialize)]
    #[serde(default)]
    pub struct TrackerConfig {
        /// Socket address used when registering tracker telemetry metrics.
        pub telemetry_endpoint: SocketAddr,
        /// Configure optional notification subscriptions for the tracker.
        pub notifications: TrackerNotificationConfig,
    }

    impl Default for TrackerConfig {
        fn default() -> Self {
            Self {
                telemetry_endpoint: SocketAddr::from(([127, 0, 0, 1], 0)),
                notifications: TrackerNotificationConfig::default(),
            }
        }
    }

    /// Controls how the tracker interacts with the daemon's gossip channels.
    #[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
    #[serde(default)]
    pub struct TrackerNotificationConfig {
        /// Enable the broadcast subscription for runtime P2P notifications.
        pub p2p: bool,
        /// Gossip topic used for the block notification subscription.
        pub topic: String,
    }

    impl Default for TrackerNotificationConfig {
        fn default() -> Self {
            Self {
                p2p: false,
                topic: DEFAULT_GOSSIP_TOPIC.into(),
            }
        }
    }

    /// Configure the optional daemon-level P2P connection used for fetching headers and blocks.
    #[derive(Clone, Debug, Serialize, Deserialize)]
    #[serde(default)]
    pub struct P2pConfig {
        /// Enable the P2P bridge and route daemon RPC calls through the network module.
        pub enabled: bool,
        /// Socket address used when registering daemon P2P metrics.
        pub metrics_endpoint: SocketAddr,
        /// Network identifier advertised when joining the swarm.
        pub network_id: String,
        /// Optional authentication token attached to subscription requests.
        pub auth_token: Option<String>,
        /// Gossip topics that the daemon exposes to downstream consumers.
        pub gossip_topics: Vec<String>,
    }

    impl Default for P2pConfig {
        fn default() -> Self {
            Self {
                enabled: false,
                metrics_endpoint: SocketAddr::from(([127, 0, 0, 1], 0)),
                network_id: "rpp-local".into(),
                auth_token: None,
                gossip_topics: vec![DEFAULT_GOSSIP_TOPIC.into()],
            }
        }
    }
}

#[cfg(feature = "vendor_electrs")]
pub use electrs::*;
