use serde::{Deserialize, Serialize};

/// Wallet actions tracked by telemetry collectors.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
#[allow(clippy::enum_variant_names)]
pub enum WalletTelemetryAction {
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
    use serde_json::json;

    // The telemetry payloads are ingested by monitoring pipelines, so the
    // serialization tests below make sure success/error outcomes keep their shape.

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

    #[test]
    fn counters_snapshot_covers_outcomes() {
        let counters = TelemetryCounters {
            enabled: false,
            counters: vec![
                TelemetryCounter {
                    name: "backup.export.success".into(),
                    value: 7,
                },
                TelemetryCounter {
                    name: "backup.export.error".into(),
                    value: 1,
                },
            ],
        };
        let serialized = serde_json::to_value(&counters).expect("serialize counters");
        assert_eq!(
            serialized,
            json!({
                "enabled": false,
                "counters": [
                    {"name": "backup.export.success", "value": 7},
                    {"name": "backup.export.error", "value": 1}
                ]
            })
        );
    }
}
