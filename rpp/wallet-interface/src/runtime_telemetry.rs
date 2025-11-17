use std::sync::Arc;

/// Wallet actions instrumented by runtime telemetry.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
#[allow(clippy::enum_variant_names)]
pub enum WalletAction {
    BackupExport,
    BackupValidate,
    BackupImport,
    WatchOnlyStatus,
    WatchOnlyEnable,
    WatchOnlyDisable,
    #[cfg(feature = "wallet_multisig_hooks")]
    MultisigGetScope,
    #[cfg(feature = "wallet_multisig_hooks")]
    MultisigSetScope,
    #[cfg(feature = "wallet_multisig_hooks")]
    MultisigGetCosigners,
    #[cfg(feature = "wallet_multisig_hooks")]
    MultisigSetCosigners,
    #[cfg(feature = "wallet_multisig_hooks")]
    MultisigExport,
    #[cfg(feature = "wallet_zsi")]
    ZsiProve,
    #[cfg(feature = "wallet_zsi")]
    ZsiVerify,
    #[cfg(feature = "wallet_zsi")]
    ZsiBindAccount,
    #[cfg(feature = "wallet_zsi")]
    ZsiList,
    #[cfg(feature = "wallet_zsi")]
    ZsiDelete,
    HwEnumerate,
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
