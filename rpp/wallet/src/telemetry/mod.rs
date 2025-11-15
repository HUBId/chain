use std::collections::HashMap;
use std::sync::Mutex;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum WalletTelemetryAction {
    BackupExport,
    BackupValidate,
    BackupImport,
    WatchOnlyStatus,
    WatchOnlyEnable,
    WatchOnlyDisable,
    MultisigGetScope,
    MultisigSetScope,
    MultisigGetCosigners,
    MultisigSetCosigners,
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

impl WalletTelemetryAction {
    pub fn label(&self) -> &'static str {
        match self {
            Self::BackupExport => "backup.export",
            Self::BackupValidate => "backup.validate",
            Self::BackupImport => "backup.import",
            Self::WatchOnlyStatus => "watch_only.status",
            Self::WatchOnlyEnable => "watch_only.enable",
            Self::WatchOnlyDisable => "watch_only.disable",
            Self::MultisigGetScope => "multisig.get_scope",
            Self::MultisigSetScope => "multisig.set_scope",
            Self::MultisigGetCosigners => "multisig.get_cosigners",
            Self::MultisigSetCosigners => "multisig.set_cosigners",
            Self::MultisigExport => "multisig.export",
            #[cfg(feature = "wallet_zsi")]
            Self::ZsiProve => "zsi.prove",
            #[cfg(feature = "wallet_zsi")]
            Self::ZsiVerify => "zsi.verify",
            #[cfg(feature = "wallet_zsi")]
            Self::ZsiBindAccount => "zsi.bind_account",
            #[cfg(feature = "wallet_zsi")]
            Self::ZsiList => "zsi.list",
            #[cfg(feature = "wallet_zsi")]
            Self::ZsiDelete => "zsi.delete",
            Self::HwEnumerate => "hw.enumerate",
            Self::HwSign => "hw.sign",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TelemetryOutcome {
    Success,
    Error,
}

impl TelemetryOutcome {
    pub fn label(&self) -> &'static str {
        match self {
            Self::Success => "ok",
            Self::Error => "err",
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TelemetryCounter {
    pub name: String,
    pub value: u64,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TelemetryCounters {
    pub enabled: bool,
    pub counters: Vec<TelemetryCounter>,
}

#[derive(Debug, Default)]
pub struct WalletActionTelemetry {
    enabled: bool,
    counters: Mutex<HashMap<String, u64>>,
}

impl WalletActionTelemetry {
    pub fn new(enabled: bool) -> Self {
        Self {
            enabled,
            counters: Mutex::new(HashMap::new()),
        }
    }

    pub fn enabled(&self) -> bool {
        self.enabled
    }

    pub fn record(&self, action: WalletTelemetryAction, outcome: TelemetryOutcome) {
        if !self.enabled {
            return;
        }
        let key = format!("{}.{}", action.label(), outcome.label());
        let mut counters = match self.counters.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        *counters.entry(key).or_default() += 1;
    }

    pub fn snapshot(&self) -> TelemetryCounters {
        if !self.enabled {
            return TelemetryCounters {
                enabled: false,
                counters: Vec::new(),
            };
        }

        let counters = match self.counters.lock() {
            Ok(guard) => guard.clone(),
            Err(poisoned) => poisoned.into_inner().clone(),
        };
        let mut counters: Vec<_> = counters
            .into_iter()
            .map(|(name, value)| TelemetryCounter { name, value })
            .collect();
        counters.sort_by(|a, b| a.name.cmp(&b.name));
        TelemetryCounters {
            enabled: true,
            counters,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn disabled_telemetry_does_not_record_events() {
        let telemetry = WalletActionTelemetry::new(false);
        assert!(!telemetry.enabled());

        telemetry.record(
            WalletTelemetryAction::BackupExport,
            TelemetryOutcome::Success,
        );
        telemetry.record(
            WalletTelemetryAction::WatchOnlyEnable,
            TelemetryOutcome::Error,
        );

        let snapshot = telemetry.snapshot();
        assert!(!snapshot.enabled);
        assert!(snapshot.counters.is_empty());
    }

    #[test]
    fn enabled_telemetry_accumulates_success_and_errors() {
        let telemetry = WalletActionTelemetry::new(true);
        assert!(telemetry.enabled());

        telemetry.record(
            WalletTelemetryAction::BackupExport,
            TelemetryOutcome::Success,
        );
        telemetry.record(
            WalletTelemetryAction::BackupExport,
            TelemetryOutcome::Success,
        );
        telemetry.record(WalletTelemetryAction::BackupExport, TelemetryOutcome::Error);
        telemetry.record(
            WalletTelemetryAction::WatchOnlyEnable,
            TelemetryOutcome::Error,
        );

        let snapshot = telemetry.snapshot();
        assert!(snapshot.enabled);
        assert_eq!(
            snapshot.counters,
            vec![
                TelemetryCounter {
                    name: "backup.export.err".to_string(),
                    value: 1,
                },
                TelemetryCounter {
                    name: "backup.export.ok".to_string(),
                    value: 2,
                },
                TelemetryCounter {
                    name: "watch_only.enable.err".to_string(),
                    value: 1,
                },
            ]
        );
    }
}
