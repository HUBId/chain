use std::sync::Arc;

/// Wallet actions instrumented by runtime telemetry.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
#[allow(clippy::enum_variant_names)]
pub enum WalletAction {
    /// Export a wallet backup archive.
    BackupExport,
    /// Validate a wallet backup archive.
    BackupValidate,
    /// Import a wallet backup archive.
    BackupImport,
    /// Query the watch-only status.
    WatchOnlyStatus,
    /// Enable watch-only mode.
    WatchOnlyEnable,
    /// Disable watch-only mode.
    WatchOnlyDisable,
    #[cfg(feature = "wallet_multisig_hooks")]
    /// Fetch the multisig policy scope.
    MultisigGetScope,
    #[cfg(feature = "wallet_multisig_hooks")]
    /// Update the multisig policy scope.
    MultisigSetScope,
    #[cfg(feature = "wallet_multisig_hooks")]
    /// Retrieve the configured multisig cosigners.
    MultisigGetCosigners,
    #[cfg(feature = "wallet_multisig_hooks")]
    /// Update the configured multisig cosigners.
    MultisigSetCosigners,
    #[cfg(feature = "wallet_multisig_hooks")]
    /// Export multisig configuration.
    MultisigExport,
    #[cfg(feature = "wallet_zsi")]
    /// Generate a zero-knowledge proof.
    ZsiProve,
    #[cfg(feature = "wallet_zsi")]
    /// Verify a zero-knowledge proof.
    ZsiVerify,
    #[cfg(feature = "wallet_zsi")]
    /// Bind a wallet to a zero-knowledge account.
    ZsiBindAccount,
    #[cfg(feature = "wallet_zsi")]
    /// List zero-knowledge records.
    ZsiList,
    #[cfg(feature = "wallet_zsi")]
    /// Delete a zero-knowledge record.
    ZsiDelete,
    /// Enumerate connected hardware wallets.
    HwEnumerate,
    /// Sign via a hardware wallet.
    HwSign,
}

/// Result emitted alongside [`WalletAction`].
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum WalletActionResult {
    /// Operation succeeded.
    Success,
    /// Operation failed.
    Error,
}

/// Runtime metrics hooks exposed to wallet-facing RPC handlers.
pub trait RuntimeMetrics: Send + Sync {
    /// Record a wallet action outcome.
    fn record_wallet_action(&self, action: WalletAction, outcome: WalletActionResult);
}

/// No-op telemetry handle used when runtime metrics are unavailable.
#[derive(Clone, Debug, Default)]
pub struct NoopRuntimeMetrics;

impl RuntimeMetrics for NoopRuntimeMetrics {
    fn record_wallet_action(&self, _action: WalletAction, _outcome: WalletActionResult) {}
}

/// Shared handle type used by wallet RPC components.
pub type RuntimeMetricsHandle = Arc<dyn RuntimeMetrics + Send + Sync>;

/// Return a reference counted no-op metrics handle.
pub fn noop_runtime_metrics() -> RuntimeMetricsHandle {
    Arc::new(NoopRuntimeMetrics::default())
}
