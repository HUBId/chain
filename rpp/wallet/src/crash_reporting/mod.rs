use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use hostname::get as get_hostname;
use once_cell::sync::OnceCell;
use regex::Regex;
use reqwest::blocking::Client;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use signal_hook::consts::signal;
use signal_hook::iterator::Signals;
use thiserror::Error;

const MAX_SPOOL_BYTES: u64 = 10 * 1024 * 1024; // 10 MiB
const MAX_UPLOAD_BACKOFF_SECS: u64 = 60;
const INITIAL_UPLOAD_BACKOFF_SECS: u64 = 1;
const SPOOL_LIST_LIMIT: usize = 50;

/// Default spool size (in bytes) retained locally before pruning old crash reports.
pub const DEFAULT_SPOOL_BYTES: u64 = MAX_SPOOL_BYTES;

static GLOBAL_REPORTER: OnceCell<Arc<CrashReporter>> = OnceCell::new();

#[derive(Debug, Clone)]
pub struct CrashReporterConfig {
    pub enabled: bool,
    pub endpoint: Option<String>,
    pub machine_id_salt: String,
    pub spool_dir: PathBuf,
    pub spool_max_bytes: u64,
}

impl CrashReporterConfig {
    pub fn disabled(spool_dir: PathBuf) -> Self {
        Self {
            enabled: false,
            endpoint: None,
            machine_id_salt: String::new(),
            spool_dir,
            spool_max_bytes: MAX_SPOOL_BYTES,
        }
    }
}

#[derive(Debug, Error)]
pub enum CrashReporterError {
    #[error("io error: {0}")]
    Io(#[from] io::Error),
    #[error("signal hook error: {0}")]
    Signal(io::Error),
}

#[derive(Debug)]
pub struct CrashReporterHandle {
    _reporter: Arc<CrashReporter>,
    _signal_thread: Option<thread::JoinHandle<()>>,
    _uploader_thread: Option<thread::JoinHandle<()>>,
}

impl CrashReporterHandle {
    pub fn disabled(spool_dir: PathBuf) -> Self {
        let reporter = Arc::new(
            CrashReporter::new(CrashReporterConfig::disabled(spool_dir))
                .expect("disabled crash reporter"),
        );
        Self {
            _reporter: reporter,
            _signal_thread: None,
            _uploader_thread: None,
        }
    }
}

pub fn install_global(
    config: CrashReporterConfig,
) -> Result<CrashReporterHandle, CrashReporterError> {
    if !config.enabled {
        return Ok(CrashReporterHandle::disabled(config.spool_dir));
    }
    let reporter = Arc::new(CrashReporter::new(config)?);
    reporter.install_panic_hook();
    let signal_thread = reporter.spawn_signal_listener()?;
    let uploader_thread = reporter.spawn_uploader();
    GLOBAL_REPORTER.set(reporter.clone()).ok();
    Ok(CrashReporterHandle {
        _reporter: reporter,
        _signal_thread: Some(signal_thread),
        _uploader_thread: uploader_thread,
    })
}

pub fn list_reports(spool_dir: &Path) -> io::Result<Vec<CrashReportEnvelope>> {
    if !spool_dir.exists() {
        return Ok(Vec::new());
    }
    let mut entries: Vec<_> = fs::read_dir(spool_dir)?
        .filter_map(|entry| entry.ok())
        .collect();
    entries.sort_by_key(|entry| entry.file_name());
    let mut reports = Vec::new();
    for entry in entries.into_iter().rev().take(SPOOL_LIST_LIMIT) {
        if entry.file_type()?.is_file() {
            if let Ok(report) = read_report(entry.path()) {
                reports.push(report);
            }
        }
    }
    Ok(reports)
}

pub fn acknowledge_report(path: &Path) -> io::Result<()> {
    let mut report = read_report(path.to_path_buf())?;
    if report.acknowledged {
        return Ok(());
    }
    report.acknowledged = true;
    write_report(path, &report)
}

fn read_report(path: PathBuf) -> io::Result<CrashReportEnvelope> {
    let contents = fs::read_to_string(&path)?;
    let mut report: CrashReportEnvelope =
        serde_json::from_str(&contents).map_err(|err| io::Error::new(io::ErrorKind::Other, err))?;
    report.path = Some(path);
    Ok(report)
}

fn write_report(path: &Path, report: &CrashReportEnvelope) -> io::Result<()> {
    let serialized = serde_json::to_vec_pretty(report)
        .map_err(|err| io::Error::new(io::ErrorKind::Other, err))?;
    let tmp = path.with_extension("tmp");
    fs::write(&tmp, serialized)?;
    fs::rename(tmp, path)
}

#[derive(Debug)]
struct CrashReporter {
    config: CrashReporterConfig,
    client: Client,
    redact_hex: Regex,
    redact_b64: Regex,
    guard: Mutex<()>,
}

impl CrashReporter {
    fn new(config: CrashReporterConfig) -> io::Result<Self> {
        if !config.spool_dir.exists() {
            fs::create_dir_all(&config.spool_dir)?;
        }
        let client = Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .map_err(|err| io::Error::new(io::ErrorKind::Other, err))?;
        Ok(Self {
            config,
            client,
            redact_hex: Regex::new(r"[0-9a-fA-F]{32,}").unwrap(),
            redact_b64: Regex::new(r"[A-Za-z0-9+/]{32,}={0,2}").unwrap(),
            guard: Mutex::new(()),
        })
    }

    fn install_panic_hook(self: &Arc<Self>) {
        let reporter = Arc::clone(self);
        let previous = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |info| {
            reporter.record_panic(info);
            previous(info);
        }));
    }

    fn spawn_signal_listener(
        self: &Arc<Self>,
    ) -> Result<thread::JoinHandle<()>, CrashReporterError> {
        let mut signals = Signals::new([
            signal::SIGABRT,
            signal::SIGBUS,
            signal::SIGFPE,
            signal::SIGILL,
            signal::SIGSEGV,
        ])
        .map_err(CrashReporterError::Signal)?;
        let reporter = Arc::clone(self);
        Ok(thread::spawn(move || {
            for sig in signals.forever() {
                reporter.record_signal(sig);
                let _ = signal_hook::low_level::emulate_default_handler(sig);
            }
        }))
    }

    fn spawn_uploader(self: &Arc<Self>) -> Option<thread::JoinHandle<()>> {
        if self
            .config
            .endpoint
            .as_deref()
            .map(str::is_empty)
            .unwrap_or(true)
        {
            return None;
        }
        let reporter = Arc::clone(self);
        Some(thread::spawn(move || reporter.upload_loop()))
    }

    fn upload_loop(&self) {
        let mut backoff = INITIAL_UPLOAD_BACKOFF_SECS;
        loop {
            match self.try_upload_once() {
                Ok(true) => backoff = INITIAL_UPLOAD_BACKOFF_SECS,
                Ok(false) => thread::sleep(Duration::from_secs(5)),
                Err(err) => {
                    eprintln!("wallet crash uploader error: {err}");
                    thread::sleep(Duration::from_secs(backoff));
                    backoff = (backoff * 2).min(MAX_UPLOAD_BACKOFF_SECS);
                }
            }
        }
    }

    fn try_upload_once(&self) -> Result<bool, CrashReporterError> {
        let endpoint = match self.config.endpoint.as_ref() {
            Some(endpoint) => endpoint,
            None => return Ok(false),
        };
        let mut entries = collect_spool_entries(&self.config.spool_dir)?;
        if entries.is_empty() {
            return Ok(false);
        }
        let entry = match entries.into_iter().find(|report| report.acknowledged) {
            Some(entry) => entry,
            None => return Ok(false),
        };
        let payload = serde_json::to_value(&entry)
            .map_err(|err| io::Error::new(io::ErrorKind::Other, err))?;
        let response = self
            .client
            .post(endpoint)
            .json(&payload)
            .send()
            .map_err(|err| io::Error::new(io::ErrorKind::Other, err))?;
        if !response.status().is_success() {
            return Err(CrashReporterError::Io(io::Error::new(
                io::ErrorKind::Other,
                format!("upload failed: {}", response.status()),
            )));
        }
        if let Some(path) = entry.path.as_ref() {
            let _ = fs::remove_file(path);
        }
        Ok(true)
    }

    fn record_signal(&self, signal: i32) {
        let stacktrace = format!("signal {signal} triggered crash");
        self.persist_report(CrashEventKind::Signal, Some(signal), stacktrace);
    }

    fn record_panic(&self, info: &std::panic::PanicInfo<'_>) {
        let backtrace = std::backtrace::Backtrace::force_capture().to_string();
        let mut summary = format!("panic: {}\n", info);
        summary.push_str(&backtrace);
        let sanitized = self.redact(&summary);
        self.persist_report(CrashEventKind::Panic, None, sanitized);
    }

    fn persist_report(&self, kind: CrashEventKind, signal: Option<i32>, stacktrace: String) {
        let _guard = self.guard.lock().unwrap();
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;
        let id = format!("{}-{}", timestamp, std::process::id());
        let path = self.config.spool_dir.join(format!("{id}.json"));
        let report = CrashReportEnvelope {
            id,
            created_at: timestamp,
            kind,
            signal,
            os: std::env::consts::OS.to_string(),
            arch: std::env::consts::ARCH.to_string(),
            build_id: env!("CARGO_PKG_VERSION").to_string(),
            commit: option_env!("GIT_COMMIT_SHA").map(|value| value.to_string()),
            features: compiled_features(),
            stacktrace,
            acknowledged: false,
            machine_id: machine_id(&self.config.machine_id_salt),
            path: Some(path.clone()),
        };
        if let Err(err) = write_report(&path, &report) {
            eprintln!("wallet crash reporter failed to persist crash report: {err}");
            return;
        }
        if let Err(err) = enforce_spool_limit(&self.config.spool_dir, self.config.spool_max_bytes) {
            eprintln!("wallet crash reporter failed to enforce spool limit: {err}");
        }
    }

    fn redact(&self, input: &str) -> String {
        let no_null = input.replace('\0', "");
        let trimmed = self
            .redact_hex
            .replace_all(&no_null, "<redacted>")
            .into_owned();
        self.redact_b64
            .replace_all(&trimmed, "<redacted>")
            .into_owned()
    }
}

fn collect_spool_entries(spool_dir: &Path) -> io::Result<Vec<CrashReportEnvelope>> {
    if !spool_dir.exists() {
        return Ok(Vec::new());
    }
    let mut entries = Vec::new();
    for entry in fs::read_dir(spool_dir)? {
        let entry = entry?;
        if entry.file_type()?.is_file() {
            if let Ok(report) = read_report(entry.path()) {
                entries.push(report);
            }
        }
    }
    entries.sort_by_key(|entry| entry.created_at);
    Ok(entries)
}

fn enforce_spool_limit(spool_dir: &Path, limit: u64) -> io::Result<()> {
    if !spool_dir.exists() {
        return Ok(());
    }
    let mut entries: Vec<_> = fs::read_dir(spool_dir)?
        .filter_map(|entry| entry.ok())
        .collect();
    entries.sort_by_key(|entry| entry.metadata().and_then(|m| m.modified()).ok());
    let mut total = 0u64;
    for entry in &entries {
        total += entry.metadata()?.len();
    }
    if total <= limit {
        return Ok(());
    }
    for entry in entries {
        if total <= limit {
            break;
        }
        let size = entry.metadata()?.len();
        total = total.saturating_sub(size);
        let _ = fs::remove_file(entry.path());
    }
    Ok(())
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CrashEventKind {
    Panic,
    Signal,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrashReportEnvelope {
    pub id: String,
    pub created_at: u64,
    pub kind: CrashEventKind,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signal: Option<i32>,
    pub os: String,
    pub arch: String,
    pub build_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub commit: Option<String>,
    pub features: Vec<String>,
    pub stacktrace: String,
    pub acknowledged: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub machine_id: Option<String>,
    #[serde(skip)]
    pub path: Option<PathBuf>,
}

fn compiled_features() -> Vec<String> {
    let mut features = Vec::new();
    if cfg!(feature = "wallet_gui") {
        features.push("wallet_gui".to_string());
    }
    if cfg!(feature = "wallet_hw") {
        features.push("wallet_hw".to_string());
    }
    if cfg!(feature = "wallet_zsi") {
        features.push("wallet_zsi".to_string());
    }
    if cfg!(feature = "wallet_multisig_hooks") {
        features.push("wallet_multisig_hooks".to_string());
    }
    features.sort();
    features
}

pub fn machine_id(salt: &str) -> Option<String> {
    if salt.trim().is_empty() {
        return None;
    }
    let hostname = get_hostname().ok()?.to_string_lossy().into_owned();
    let mut input = salt.as_bytes().to_vec();
    input.extend_from_slice(hostname.as_bytes());
    let digest = Sha256::digest(&input);
    Some(format!("{:x}", digest))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redact_replaces_hex_sequences() {
        let config = CrashReporterConfig {
            enabled: true,
            endpoint: None,
            machine_id_salt: String::new(),
            spool_dir: tempfile::tempdir().unwrap().into_path(),
            spool_max_bytes: MAX_SPOOL_BYTES,
        };
        let reporter = CrashReporter::new(config).unwrap();
        let sample = "frame 0x1234567890abcdef1234567890abcdef";
        assert!(!reporter
            .redact(sample)
            .contains("1234567890abcdef1234567890abcdef"));
    }

    #[test]
    fn machine_id_uses_salt() {
        let first = machine_id("salt-a").unwrap();
        let second = machine_id("salt-b").unwrap();
        assert_ne!(first, second);
    }

    #[test]
    fn signal_report_is_persisted() {
        let dir = tempfile::tempdir().unwrap();
        let config = CrashReporterConfig {
            enabled: true,
            endpoint: None,
            machine_id_salt: String::new(),
            spool_dir: dir.path().to_path_buf(),
            spool_max_bytes: DEFAULT_SPOOL_BYTES,
        };
        let reporter = CrashReporter::new(config).unwrap();
        reporter.record_signal(11);
        let reports = list_reports(dir.path()).unwrap();
        assert_eq!(reports.len(), 1);
        assert_eq!(reports[0].kind, CrashEventKind::Signal);
        assert_eq!(reports[0].signal, Some(11));
    }
}
