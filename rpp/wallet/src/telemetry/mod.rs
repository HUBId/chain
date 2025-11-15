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
    ZsiProve,
    ZsiVerify,
    ZsiBindAccount,
    ZsiList,
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
            Self::ZsiProve => "zsi.prove",
            Self::ZsiVerify => "zsi.verify",
            Self::ZsiBindAccount => "zsi.bind_account",
            Self::ZsiList => "zsi.list",
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
