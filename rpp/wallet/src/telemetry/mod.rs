use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Mutex;
use std::time::Duration;

pub use crate::interface_telemetry::{
    TelemetryCounter, TelemetryCounters, TelemetryOutcome, WalletTelemetryAction,
};

mod exporter;

use exporter::{events_per_batch, TelemetryEvent, TelemetryEventKind, TelemetryExporter};

impl WalletTelemetryAction {
    pub fn label(&self) -> &'static str {
        match self {
            Self::BackupExport => "backup.export",
            Self::BackupValidate => "backup.validate",
            Self::BackupImport => "backup.import",
            Self::WatchOnlyStatus => "watch_only.status",
            Self::WatchOnlyEnable => "watch_only.enable",
            Self::WatchOnlyDisable => "watch_only.disable",
            #[cfg(feature = "wallet_multisig_hooks")]
            Self::MultisigGetScope => "multisig.get_scope",
            #[cfg(feature = "wallet_multisig_hooks")]
            Self::MultisigSetScope => "multisig.set_scope",
            #[cfg(feature = "wallet_multisig_hooks")]
            Self::MultisigGetCosigners => "multisig.get_cosigners",
            #[cfg(feature = "wallet_multisig_hooks")]
            Self::MultisigSetCosigners => "multisig.set_cosigners",
            #[cfg(feature = "wallet_multisig_hooks")]
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

impl TelemetryOutcome {
    pub fn label(&self) -> &'static str {
        match self {
            Self::Success => "ok",
            Self::Error => "err",
        }
    }
}

#[derive(Debug)]
pub struct WalletActionTelemetry {
    enabled: bool,
    counters: Mutex<HashMap<String, u64>>,
    events: Mutex<Vec<TelemetryEvent>>,
    exporter: Option<TelemetryExporter>,
}

impl Default for WalletActionTelemetry {
    fn default() -> Self {
        Self::new(false)
    }
}

impl WalletActionTelemetry {
    pub fn new(enabled: bool) -> Self {
        Self {
            enabled,
            counters: Mutex::new(HashMap::new()),
            events: Mutex::new(Vec::new()),
            exporter: None,
        }
    }

    /// Constructs a telemetry handle backed by the runtime exporter.
    pub fn with_exporter(
        enabled: bool,
        endpoint: Option<String>,
        spool_dir: Option<PathBuf>,
        machine_id: Option<String>,
    ) -> std::io::Result<Self> {
        let exporter = if enabled {
            if let (Some(endpoint), Some(spool)) = (endpoint, spool_dir) {
                Some(TelemetryExporter::new(endpoint, spool, machine_id)?)
            } else {
                None
            }
        } else {
            None
        };
        Ok(Self {
            enabled,
            counters: Mutex::new(HashMap::new()),
            events: Mutex::new(Vec::new()),
            exporter,
        })
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

    /// Emits a session lifecycle event tagged with the startup phase.
    pub fn record_session(&self, phase: &'static str) {
        if !self.enabled {
            return;
        }
        self.record_event(TelemetryEventKind::Session { phase });
    }

    /// Emits a RPC latency sample tagged by method name and outcome.
    pub fn record_rpc_event(
        &self,
        method: &str,
        duration: Duration,
        outcome: TelemetryOutcome,
        code: Option<&str>,
    ) {
        if !self.enabled {
            return;
        }
        let latency_ms = duration.as_millis() as u64;
        self.record_event(TelemetryEventKind::Rpc {
            method: method.to_string(),
            latency_ms,
            outcome: outcome.label(),
            code: code.map(|value| value.to_string()),
        });
    }

    /// Emits a send workflow step event.
    pub fn record_send_stage(&self, stage: &'static str, outcome: TelemetryOutcome) {
        if !self.enabled {
            return;
        }
        self.record_event(TelemetryEventKind::SendStage {
            stage,
            outcome: outcome.label(),
        });
    }

    /// Emits a rescan workflow step event, optionally tagging the latency.
    pub fn record_rescan_stage(
        &self,
        stage: &'static str,
        duration: Option<Duration>,
        outcome: TelemetryOutcome,
    ) {
        if !self.enabled {
            return;
        }
        self.record_event(TelemetryEventKind::Rescan {
            stage,
            latency_ms: duration.map(|value| value.as_millis() as u64),
            outcome: outcome.label(),
        });
    }

    /// Emits a telemetry error code sample.
    pub fn record_error_code(&self, code: &str, context: Option<&str>) {
        if !self.enabled {
            return;
        }
        self.record_event(TelemetryEventKind::Error {
            code: code.to_string(),
            context: context.map(|value| value.to_string()),
        });
    }

    /// Flushes pending events to the exporter (if configured).
    pub fn flush(&self) {
        if let Some(exporter) = &self.exporter {
            let drained = {
                let mut guard = match self.events.lock() {
                    Ok(guard) => guard,
                    Err(poisoned) => poisoned.into_inner(),
                };
                guard.drain(..).collect::<Vec<_>>()
            };
            if !drained.is_empty() {
                exporter.publish(drained);
            } else {
                exporter.flush_spool();
            }
        }
    }

    fn record_event(&self, kind: TelemetryEventKind) {
        if let Some(exporter) = &self.exporter {
            let mut guard = match self.events.lock() {
                Ok(guard) => guard,
                Err(poisoned) => poisoned.into_inner(),
            };
            guard.push(TelemetryEvent::now(kind));
            if guard.len() >= events_per_batch(Some(exporter)) {
                let batch = guard.drain(..).collect();
                exporter.publish(batch);
            }
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
