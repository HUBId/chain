use std::env;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, OnceLock};

use metrics::counter;
use rpp::runtime::config::WalletConfig as RuntimeWalletConfig;
use rpp::runtime::RuntimeMode;

use crate::telemetry::TelemetryOutcome;

#[derive(Clone, Debug)]
pub struct CliTelemetry {
    inner: Arc<Inner>,
}

#[derive(Debug, Default)]
struct Inner {
    opt_in: AtomicBool,
}

static GLOBAL: OnceLock<CliTelemetry> = OnceLock::new();

pub fn global() -> CliTelemetry {
    GLOBAL.get_or_init(CliTelemetry::default).clone()
}

impl Default for CliTelemetry {
    fn default() -> Self {
        Self {
            inner: Arc::new(Inner {
                opt_in: AtomicBool::new(false),
            }),
        }
    }
}

impl CliTelemetry {
    pub fn set_opt_in(&self, enabled: bool) {
        self.inner.opt_in.store(enabled, Ordering::Relaxed);
    }

    pub fn opted_in(&self) -> bool {
        self.inner.opt_in.load(Ordering::Relaxed)
    }

    pub fn record_backup_outcome(&self, action: BackupAction, outcome: TelemetryOutcome) {
        self.record_action(action.label(), outcome);
    }

    pub fn record_watch_only_outcome(&self, action: WatchOnlyAction, outcome: TelemetryOutcome) {
        self.record_action(action.label(), outcome);
    }

    pub fn record_zsi_outcome(&self, action: ZsiAction, outcome: TelemetryOutcome) {
        self.record_action(action.label(), outcome);
    }

    pub fn record_hardware_outcome(&self, action: HardwareAction, outcome: TelemetryOutcome) {
        self.record_action(action.label(), outcome);
    }

    fn record_action(&self, operation: &'static str, outcome: TelemetryOutcome) {
        if !self.opted_in() {
            return;
        }
        counter!(
            "cli.action.events",
            "operation" => operation,
            "outcome" => outcome.label()
        )
        .increment(1);
    }
}

pub fn configure(opt_in_hint: Option<bool>, config_path: Option<&Path>) {
    let env_opt_in = read_env_opt_in();
    let config_opt_in = if let Some(path) = config_path {
        load_config_opt_in(path)
    } else {
        default_config_path().and_then(|path| load_config_opt_in(&path))
    };

    let enabled = env_opt_in
        .or(opt_in_hint)
        .or(config_opt_in)
        .unwrap_or(false);
    global().set_opt_in(enabled);
}

fn read_env_opt_in() -> Option<bool> {
    env::var("RPP_WALLET_TELEMETRY_OPT_IN")
        .ok()
        .as_deref()
        .and_then(parse_bool)
}

fn parse_bool(value: &str) -> Option<bool> {
    match value.trim().to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "on" => Some(true),
        "0" | "false" | "no" | "off" => Some(false),
        _ => None,
    }
}

fn load_config_opt_in(path: &Path) -> Option<bool> {
    if !path.exists() {
        return None;
    }
    RuntimeWalletConfig::load(path)
        .ok()
        .map(|config| config.wallet.gui.telemetry_opt_in)
}

fn default_config_path() -> Option<PathBuf> {
    RuntimeMode::Wallet
        .default_wallet_config_path()
        .map(PathBuf::from)
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ZsiAction {
    Issue,
    Rotate,
    Revoke,
    Audit,
    Prove,
    Verify,
    BindAccount,
    ListArtifacts,
    DeleteArtifact,
}

impl ZsiAction {
    fn label(self) -> &'static str {
        match self {
            Self::Issue => "zsi.issue",
            Self::Rotate => "zsi.rotate",
            Self::Revoke => "zsi.revoke",
            Self::Audit => "zsi.audit",
            Self::Prove => "zsi.prove",
            Self::Verify => "zsi.verify",
            Self::BindAccount => "zsi.bind_account",
            Self::ListArtifacts => "zsi.list",
            Self::DeleteArtifact => "zsi.delete",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HardwareAction {
    Enumerate,
    Sign,
}

impl HardwareAction {
    fn label(self) -> &'static str {
        match self {
            Self::Enumerate => "hardware.enumerate",
            Self::Sign => "hardware.sign",
        }
    }
}
