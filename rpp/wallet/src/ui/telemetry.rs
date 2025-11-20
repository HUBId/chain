use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use metrics::{counter, histogram};

use crate::rpc::client::WalletRpcClientError;
use crate::telemetry::TelemetryOutcome;

use super::commands::RpcCallError;

#[derive(Clone, Debug)]
pub struct UiTelemetry {
    inner: Arc<Inner>,
}

#[derive(Debug, Default)]
struct Inner {
    opt_in: AtomicBool,
}

static GLOBAL: OnceLock<UiTelemetry> = OnceLock::new();

pub fn global() -> UiTelemetry {
    GLOBAL.get_or_init(UiTelemetry::default).clone()
}

impl Default for UiTelemetry {
    fn default() -> Self {
        Self {
            inner: Arc::new(Inner {
                opt_in: AtomicBool::new(false),
            }),
        }
    }
}

impl UiTelemetry {
    pub fn set_opt_in(&self, enabled: bool) {
        self.inner.opt_in.store(enabled, Ordering::Relaxed);
    }

    pub fn opted_in(&self) -> bool {
        self.inner.opt_in.load(Ordering::Relaxed)
    }

    pub fn record_rpc_success(&self, method: &'static str, duration: Duration) {
        if !self.opted_in() {
            return;
        }
        let value = duration.as_secs_f64() * 1_000.0;
        histogram!("ui.rpc.latency_ms", "method" => method, "result" => "ok").record(value);
    }

    pub fn record_rpc_timeout(&self, method: &'static str, timeout: Duration) {
        if !self.opted_in() {
            return;
        }
        let value = timeout.as_secs_f64() * 1_000.0;
        histogram!("ui.rpc.latency_ms", "method" => method, "result" => "timeout").record(value);
    }

    pub fn record_rpc_client_error(
        &self,
        method: &'static str,
        duration: Duration,
        error: &WalletRpcClientError,
    ) {
        if !self.opted_in() {
            return;
        }
        let value = duration.as_secs_f64() * 1_000.0;
        let labels = client_error_labels(error);
        if let Some(code) = labels.code.as_deref() {
            histogram!(
                "ui.rpc.latency_ms",
                "method" => method,
                "result" => "error",
                "error_kind" => labels.kind,
                "code" => code
            )
            .record(value);
            counter!("ui.errors.by_code", "code" => code).increment(1);
        } else {
            histogram!(
                "ui.rpc.latency_ms",
                "method" => method,
                "result" => "error",
                "error_kind" => labels.kind
            )
            .record(value);
        }
    }

    pub fn record_send_step_success(&self, stage: &'static str) {
        if !self.opted_in() {
            return;
        }
        counter!("ui.send.steps", "stage" => stage, "outcome" => "success").increment(1);
    }

    pub fn record_send_step_failure(&self, stage: &'static str, error: &RpcCallError) {
        if !self.opted_in() {
            return;
        }
        match rpc_failure_labels(error) {
            RpcFailure::Timeout => {
                counter!("ui.send.steps", "stage" => stage, "outcome" => "timeout").increment(1);
            }
            RpcFailure::Client { kind, code } => {
                if let Some(code) = code.as_deref() {
                    counter!(
                        "ui.send.steps",
                        "stage" => stage,
                        "outcome" => "error",
                        "error_kind" => kind,
                        "code" => code
                    )
                    .increment(1);
                } else {
                    counter!(
                        "ui.send.steps",
                        "stage" => stage,
                        "outcome" => "error",
                        "error_kind" => kind
                    )
                    .increment(1);
                }
            }
        }
    }

    pub fn record_rescan_trigger(&self, origin: &'static str) {
        if !self.opted_in() {
            return;
        }
        counter!("ui.rescan.triggered", "origin" => origin).increment(1);
    }

    pub fn record_lock_outcome(&self, action: LockAction, outcome: TelemetryOutcome) {
        self.record_action(action.label(), outcome);
    }

    pub fn record_backup_outcome(&self, action: BackupAction, outcome: TelemetryOutcome) {
        self.record_action(action.label(), outcome);
    }

    pub fn record_watch_only_outcome(&self, action: WatchOnlyAction, outcome: TelemetryOutcome) {
        self.record_action(action.label(), outcome);
    }

    #[cfg(feature = "wallet_rpc_mtls")]
    pub fn record_security_outcome(&self, action: SecurityAction, outcome: TelemetryOutcome) {
        self.record_action(action.label(), outcome);
    }

    #[cfg(not(feature = "wallet_rpc_mtls"))]
    pub fn record_security_outcome(&self, _action: SecurityAction, _outcome: TelemetryOutcome) {}

    #[cfg(feature = "wallet_zsi")]
    pub fn record_zsi_outcome(&self, action: ZsiAction, outcome: TelemetryOutcome) {
        self.record_action(action.label(), outcome);
    }

    #[cfg(not(feature = "wallet_zsi"))]
    pub fn record_zsi_outcome(&self, _action: ZsiAction, _outcome: TelemetryOutcome) {}

    #[cfg(feature = "wallet_hw")]
    pub fn record_hardware_outcome(&self, action: HardwareAction, outcome: TelemetryOutcome) {
        self.record_action(action.label(), outcome);
    }

    fn record_action(&self, operation: &'static str, outcome: TelemetryOutcome) {
        if !self.opted_in() {
            return;
        }
        counter!(
            "ui.action.events",
            "operation" => operation,
            "outcome" => outcome.label()
        )
        .increment(1);
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BackupAction {
    Export,
    Validate,
    Import,
}

impl BackupAction {
    fn label(self) -> &'static str {
        match self {
            Self::Export => "backup.export",
            Self::Validate => "backup.validate",
            Self::Import => "backup.import",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LockAction {
    RefreshPendingLocks,
    ReleasePendingLocks,
}

impl LockAction {
    fn label(self) -> &'static str {
        match self {
            Self::RefreshPendingLocks => "locks.refresh",
            Self::ReleasePendingLocks => "locks.release",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WatchOnlyAction {
    Status,
    Enable,
    Disable,
}

impl WatchOnlyAction {
    fn label(self) -> &'static str {
        match self {
            Self::Status => "watch_only.status",
            Self::Enable => "watch_only.enable",
            Self::Disable => "watch_only.disable",
        }
    }
}

#[cfg(feature = "wallet_rpc_mtls")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SecurityAction {
    Snapshot,
    Assign,
    Remove,
    MtlsUpdate,
    CertificateUpload,
}

#[cfg(feature = "wallet_rpc_mtls")]
impl SecurityAction {
    fn label(self) -> &'static str {
        match self {
            Self::Snapshot => "security.snapshot",
            Self::Assign => "security.assign",
            Self::Remove => "security.remove",
            Self::MtlsUpdate => "security.mtls_update",
            Self::CertificateUpload => "security.certificate_upload",
        }
    }
}

#[cfg(not(feature = "wallet_rpc_mtls"))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SecurityAction;

#[cfg(feature = "wallet_zsi")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ZsiAction {
    ListArtifacts,
    BindAccount,
    DeleteArtifact,
}

#[cfg(feature = "wallet_zsi")]
impl ZsiAction {
    fn label(self) -> &'static str {
        match self {
            Self::ListArtifacts => "zsi.list",
            Self::BindAccount => "zsi.bind_account",
            Self::DeleteArtifact => "zsi.delete",
        }
    }
}

#[cfg(not(feature = "wallet_zsi"))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ZsiAction;

#[cfg(feature = "wallet_hw")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HardwareAction {
    Enumerate,
    Sign,
}

#[cfg(feature = "wallet_hw")]
impl HardwareAction {
    fn label(self) -> &'static str {
        match self {
            Self::Enumerate => "hardware.enumerate",
            Self::Sign => "hardware.sign",
        }
    }
}

struct ClientErrorLabels {
    kind: &'static str,
    code: Option<String>,
}

enum RpcFailure {
    Timeout,
    Client {
        kind: &'static str,
        code: Option<String>,
    },
}

fn client_error_labels(error: &WalletRpcClientError) -> ClientErrorLabels {
    match error {
        WalletRpcClientError::InvalidEndpoint(_) => ClientErrorLabels {
            kind: "invalid_endpoint",
            code: None,
        },
        WalletRpcClientError::Json(_) => ClientErrorLabels {
            kind: "json",
            code: None,
        },
        WalletRpcClientError::Transport(_) => ClientErrorLabels {
            kind: "transport",
            code: None,
        },
        WalletRpcClientError::HttpStatus(_) => ClientErrorLabels {
            kind: "http_status",
            code: None,
        },
        WalletRpcClientError::EmptyResponse => ClientErrorLabels {
            kind: "empty_response",
            code: None,
        },
        WalletRpcClientError::UnsupportedFeature { feature, .. } => ClientErrorLabels {
            kind: "unsupported_feature",
            code: Some((*feature).to_string()),
        },
        WalletRpcClientError::Rpc { code, .. } => ClientErrorLabels {
            kind: "rpc",
            code: Some(code.as_str().into_owned()),
        },
    }
}

fn rpc_failure_labels(error: &RpcCallError) -> RpcFailure {
    match error {
        RpcCallError::Timeout(_) => RpcFailure::Timeout,
        RpcCallError::Client(inner) => {
            let labels = client_error_labels(inner);
            RpcFailure::Client {
                kind: labels.kind,
                code: labels.code,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use metrics::{
        Counter, CounterFn, Histogram, HistogramFn, Key, Metadata, Recorder, SharedString, Unit,
    };
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};

    #[derive(Default)]
    struct TestRecorderInner {
        counters: Mutex<HashMap<String, u64>>,
        histograms: Mutex<HashMap<String, Vec<f64>>>,
    }

    #[derive(Clone)]
    struct TestRecorder {
        inner: Arc<TestRecorderInner>,
    }

    impl TestRecorder {
        fn new() -> Arc<TestRecorderInner> {
            static RECORDER: OnceLock<Arc<TestRecorderInner>> = OnceLock::new();
            RECORDER
                .get_or_init(|| {
                    let inner = Arc::new(TestRecorderInner::default());
                    let recorder = TestRecorder {
                        inner: Arc::clone(&inner),
                    };
                    metrics::set_boxed_recorder(Box::new(recorder)).expect("set global recorder");
                    inner
                })
                .clone()
        }

        fn reset(inner: &Arc<TestRecorderInner>) {
            inner.counters.lock().unwrap().clear();
            inner.histograms.lock().unwrap().clear();
        }

        fn counter_value(inner: &Arc<TestRecorderInner>, key: &str) -> Option<u64> {
            inner.counters.lock().unwrap().get(key).copied()
        }

        fn histogram_values(inner: &Arc<TestRecorderInner>, key: &str) -> Vec<f64> {
            inner
                .histograms
                .lock()
                .unwrap()
                .get(key)
                .cloned()
                .unwrap_or_default()
        }
    }

    impl Recorder for TestRecorder {
        fn describe_counter(&self, _: Key, _: Option<Unit>, _: SharedString) {}

        fn describe_gauge(&self, _: Key, _: Option<Unit>, _: SharedString) {}

        fn describe_histogram(&self, _: Key, _: Option<Unit>, _: SharedString) {}

        fn register_counter(&self, key: &Key, _: &Metadata<'_>) -> Counter {
            let formatted = format_key(key);
            self.inner
                .counters
                .lock()
                .unwrap()
                .entry(formatted.clone())
                .or_insert(0);
            Counter::from_arc(Arc::new(TestCounterHandle {
                key: formatted,
                inner: Arc::clone(&self.inner),
            }))
        }

        fn register_gauge(&self, _: &Key, _: &Metadata<'_>) -> metrics::Gauge {
            metrics::Gauge::noop()
        }

        fn register_histogram(&self, key: &Key, _: &Metadata<'_>) -> Histogram {
            let formatted = format_key(key);
            Histogram::from_arc(Arc::new(TestHistogramHandle {
                key: formatted,
                inner: Arc::clone(&self.inner),
            }))
        }
    }

    struct TestCounterHandle {
        key: String,
        inner: Arc<TestRecorderInner>,
    }

    impl CounterFn for TestCounterHandle {
        fn increment(&self, value: u64) {
            let mut counters = self.inner.counters.lock().unwrap();
            let entry = counters.entry(self.key.clone()).or_default();
            *entry = entry.saturating_add(value);
        }

        fn absolute(&self, value: u64) {
            let mut counters = self.inner.counters.lock().unwrap();
            let entry = counters.entry(self.key.clone()).or_default();
            *entry = (*entry).max(value);
        }
    }

    struct TestHistogramHandle {
        key: String,
        inner: Arc<TestRecorderInner>,
    }

    impl HistogramFn for TestHistogramHandle {
        fn record(&self, value: f64) {
            let mut histograms = self.inner.histograms.lock().unwrap();
            histograms.entry(self.key.clone()).or_default().push(value);
        }
    }

    fn format_key(key: &Key) -> String {
        let mut labels: Vec<_> = key
            .labels()
            .map(|label| (label.key().to_owned(), label.value().to_owned()))
            .collect();
        labels.sort_by(|a, b| a.0.cmp(&b.0));
        if labels.is_empty() {
            key.name().to_owned()
        } else {
            let joined = labels
                .into_iter()
                .map(|(k, v)| format!("{k}={v}"))
                .collect::<Vec<_>>()
                .join(",");
            format!("{}{{{joined}}}", key.name())
        }
    }

    #[test]
    fn telemetry_suppressed_when_opt_out() {
        let inner = TestRecorder::new();
        TestRecorder::reset(&inner);

        let telemetry = global();
        telemetry.set_opt_in(false);

        telemetry.record_rpc_success("list_utxos", Duration::from_millis(12));
        telemetry.record_send_step_success("policy_preview");
        telemetry.record_rescan_trigger("birthday");

        assert!(TestRecorder::histogram_values(
            &inner,
            "ui.rpc.latency_ms{method=list_utxos,result=ok}"
        )
        .is_empty());
        assert!(TestRecorder::counter_value(
            &inner,
            "ui.send.steps{outcome=success,stage=policy_preview}"
        )
        .is_none());
        assert!(
            TestRecorder::counter_value(&inner, "ui.rescan.triggered{origin=birthday}").is_none()
        );
    }

    #[test]
    fn telemetry_emitted_when_opt_in() {
        let inner = TestRecorder::new();
        TestRecorder::reset(&inner);

        let telemetry = global();
        telemetry.set_opt_in(true);

        telemetry.record_rpc_success("get_balance", Duration::from_millis(25));
        telemetry.record_rpc_timeout("sync_status", Duration::from_secs(5));
        let rpc_error = WalletRpcClientError::Rpc {
            code: crate::rpc::error::WalletRpcErrorCode::RescanInProgress,
            message: "error".to_string(),
            json_code: -32053,
            details: None,
        };
        telemetry.record_rpc_client_error("rescan", Duration::from_millis(70), &rpc_error);

        telemetry.record_send_step_success("draft_sign");
        let call_error = RpcCallError::Client(rpc_error);
        telemetry.record_send_step_failure("draft_sign", &call_error);
        telemetry.record_rescan_trigger("explicit");

        let success = TestRecorder::histogram_values(
            &inner,
            "ui.rpc.latency_ms{method=get_balance,result=ok}",
        );
        assert_eq!(success.len(), 1);
        assert!(success[0] > 0.0);

        let timeout = TestRecorder::histogram_values(
            &inner,
            "ui.rpc.latency_ms{method=sync_status,result=timeout}",
        );
        assert_eq!(timeout.len(), 1);

        let error_hist = TestRecorder::histogram_values(
            &inner,
            "ui.rpc.latency_ms{code=RESCAN_IN_PROGRESS,error_kind=rpc,method=rescan,result=error}",
        );
        assert_eq!(error_hist.len(), 1);

        let error_counter =
            TestRecorder::counter_value(&inner, "ui.errors.by_code{code=RESCAN_IN_PROGRESS}");
        assert_eq!(error_counter, Some(1));

        let send_success =
            TestRecorder::counter_value(&inner, "ui.send.steps{outcome=success,stage=draft_sign}");
        assert_eq!(send_success, Some(1));

        let send_failure = TestRecorder::counter_value(
            &inner,
            "ui.send.steps{code=RESCAN_IN_PROGRESS,error_kind=rpc,outcome=error,stage=draft_sign}",
        );
        assert_eq!(send_failure, Some(1));

        let rescan = TestRecorder::counter_value(&inner, "ui.rescan.triggered{origin=explicit}");
        assert_eq!(rescan, Some(1));
    }

    #[test]
    fn action_helpers_only_emit_when_opted_in() {
        let inner = TestRecorder::new();
        TestRecorder::reset(&inner);

        let telemetry = global();
        telemetry.set_opt_in(false);

        telemetry.record_backup_outcome(BackupAction::Export, TelemetryOutcome::Success);
        telemetry.record_watch_only_outcome(WatchOnlyAction::Enable, TelemetryOutcome::Error);
        #[cfg(feature = "wallet_rpc_mtls")]
        telemetry.record_security_outcome(SecurityAction::Assign, TelemetryOutcome::Success);
        #[cfg(feature = "wallet_zsi")]
        telemetry.record_zsi_outcome(ZsiAction::BindAccount, TelemetryOutcome::Error);
        #[cfg(feature = "wallet_hw")]
        telemetry.record_hardware_outcome(HardwareAction::Enumerate, TelemetryOutcome::Success);
        telemetry.record_lock_outcome(LockAction::RefreshPendingLocks, TelemetryOutcome::Success);
        telemetry.record_lock_outcome(LockAction::ReleasePendingLocks, TelemetryOutcome::Error);

        assert!(TestRecorder::counter_value(
            &inner,
            "ui.action.events{operation=backup.export,outcome=ok}"
        )
        .is_none());
        assert!(TestRecorder::counter_value(
            &inner,
            "ui.action.events{operation=watch_only.enable,outcome=err}"
        )
        .is_none());
        #[cfg(feature = "wallet_rpc_mtls")]
        assert!(TestRecorder::counter_value(
            &inner,
            "ui.action.events{operation=security.assign,outcome=ok}"
        )
        .is_none());
        #[cfg(feature = "wallet_zsi")]
        assert!(TestRecorder::counter_value(
            &inner,
            "ui.action.events{operation=zsi.bind_account,outcome=err}"
        )
        .is_none());
        #[cfg(feature = "wallet_hw")]
        assert!(TestRecorder::counter_value(
            &inner,
            "ui.action.events{operation=hardware.enumerate,outcome=ok}"
        )
        .is_none());
        assert!(TestRecorder::counter_value(
            &inner,
            "ui.action.events{operation=locks.refresh,outcome=ok}"
        )
        .is_none());
        assert!(TestRecorder::counter_value(
            &inner,
            "ui.action.events{operation=locks.release,outcome=err}"
        )
        .is_none());

        TestRecorder::reset(&inner);
        telemetry.set_opt_in(true);

        telemetry.record_backup_outcome(BackupAction::Export, TelemetryOutcome::Success);
        telemetry.record_watch_only_outcome(WatchOnlyAction::Enable, TelemetryOutcome::Error);
        #[cfg(feature = "wallet_rpc_mtls")]
        telemetry.record_security_outcome(SecurityAction::Assign, TelemetryOutcome::Success);
        #[cfg(feature = "wallet_zsi")]
        telemetry.record_zsi_outcome(ZsiAction::BindAccount, TelemetryOutcome::Error);
        #[cfg(feature = "wallet_hw")]
        telemetry.record_hardware_outcome(HardwareAction::Enumerate, TelemetryOutcome::Success);

        assert_eq!(
            TestRecorder::counter_value(
                &inner,
                "ui.action.events{operation=backup.export,outcome=ok}"
            ),
            Some(1)
        );
        assert_eq!(
            TestRecorder::counter_value(
                &inner,
                "ui.action.events{operation=watch_only.enable,outcome=err}"
            ),
            Some(1)
        );
        assert_eq!(
            TestRecorder::counter_value(
                &inner,
                "ui.action.events{operation=locks.refresh,outcome=ok}"
            ),
            Some(1)
        );
        assert_eq!(
            TestRecorder::counter_value(
                &inner,
                "ui.action.events{operation=locks.release,outcome=err}"
            ),
            Some(1)
        );
        #[cfg(feature = "wallet_rpc_mtls")]
        assert_eq!(
            TestRecorder::counter_value(
                &inner,
                "ui.action.events{operation=security.assign,outcome=ok}"
            ),
            Some(1)
        );
        #[cfg(feature = "wallet_zsi")]
        assert_eq!(
            TestRecorder::counter_value(
                &inner,
                "ui.action.events{operation=zsi.bind_account,outcome=err}"
            ),
            Some(1)
        );
        #[cfg(feature = "wallet_hw")]
        assert_eq!(
            TestRecorder::counter_value(
                &inner,
                "ui.action.events{operation=hardware.enumerate,outcome=ok}"
            ),
            Some(1)
        );
    }
}
