use serde::{Deserialize, Serialize};

/// Wallet actions tracked by telemetry collectors.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
#[allow(clippy::enum_variant_names)]
pub enum WalletTelemetryAction {
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

/// Result of an observed action.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TelemetryOutcome {
    /// Operation succeeded.
    Success,
    /// Operation failed.
    Error,
}

/// Counter entry captured by telemetry snapshots.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TelemetryCounter {
    /// Canonical counter name (e.g. `backup.export.ok`).
    pub name: String,
    /// Total number of observed events.
    pub value: u64,
}

/// Telemetry summary exchanged between components.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TelemetryCounters {
    /// Whether telemetry is enabled at the source.
    pub enabled: bool,
    /// Sorted list of counters emitted by the source.
    #[serde(default)]
    pub counters: Vec<TelemetryCounter>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counters_round_trip() {
        let counters = TelemetryCounters {
            enabled: true,
            counters: vec![TelemetryCounter {
                name: "backup.export.ok".into(),
                value: 3,
            }],
        };
        let encoded = serde_json::to_string(&counters).expect("serialize counters");
        let decoded: TelemetryCounters =
            serde_json::from_str(&encoded).expect("deserialize counters");
        assert_eq!(decoded, counters);
    }
}
