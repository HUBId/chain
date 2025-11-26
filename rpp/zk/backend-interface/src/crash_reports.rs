use std::cell::RefCell;
use std::env;
use std::fs::{self, File};
use std::io::Write;
use std::panic::{self, PanicHookInfo};
use std::path::{Path, PathBuf};
use std::process;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

const DEFAULT_REPORT_DIR: &str = "logs/zk-crash-reports";
const OPT_IN_ENV: &str = "RPP_ZK_CRASH_REPORTS";
const REPORT_DIR_ENV: &str = "RPP_ZK_CRASH_REPORT_DIR";

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct CrashContext {
    pub backend: Option<String>,
    pub circuit: Option<String>,
}

thread_local! {
    static CRASH_CONTEXT: RefCell<CrashContext> = RefCell::new(CrashContext::default());
}

#[derive(Debug)]
pub struct CrashContextGuard {
    previous: CrashContext,
}

impl CrashContextGuard {
    pub fn enter(backend: impl Into<String>, circuit: impl Into<String>) -> Self {
        let next = CrashContext {
            backend: Some(backend.into()),
            circuit: Some(circuit.into()),
        };
        let previous = CRASH_CONTEXT.with(|ctx| ctx.replace(next));
        Self { previous }
    }
}

impl Drop for CrashContextGuard {
    fn drop(&mut self) {
        CRASH_CONTEXT.with(|ctx| ctx.replace(self.previous.clone()));
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CrashReport {
    pub process: String,
    pub backend: Option<String>,
    pub circuit: Option<String>,
    pub message: String,
    pub location: Option<String>,
    pub thread: Option<String>,
    pub pid: u32,
    pub timestamp_ms: u128,
    pub backtrace: String,
}

impl CrashReport {
    fn file_stem(&self, sequence: usize) -> String {
        format!(
            "{}-{}-{}-{}",
            self.process, self.timestamp_ms, self.pid, sequence
        )
    }
}

pub struct CrashReportHook {
    previous: Option<Arc<dyn Fn(&PanicHookInfo<'_>) + Send + Sync + 'static>>,
    _report_dir: Arc<PathBuf>,
    _process: String,
}

impl CrashReportHook {
    pub fn install(report_dir: impl Into<PathBuf>, process: impl Into<String>) -> Self {
        let previous = Arc::new(panic::take_hook());
        let process = process.into();
        let report_dir = Arc::new(report_dir.into());
        let hook_dir = Arc::clone(&report_dir);
        let hook_process = process.clone();
        let previous_for_hook = Arc::clone(&previous);
        panic::set_hook(Box::new(move |info| {
            emit_report(&hook_dir, &hook_process, info);
            previous_for_hook(info);
        }));

        Self {
            previous: Some(previous),
            _report_dir: report_dir,
            _process: process,
        }
    }

    pub fn install_from_env(process: impl Into<String>) -> Option<Self> {
        match env::var(OPT_IN_ENV) {
            Ok(value) if is_enabled(&value) => {
                let report_dir =
                    env::var(REPORT_DIR_ENV).unwrap_or_else(|_| DEFAULT_REPORT_DIR.into());
                Some(Self::install(report_dir, process))
            }
            _ => None,
        }
    }
}

impl Drop for CrashReportHook {
    fn drop(&mut self) {
        if thread::panicking() {
            return;
        }

        if let Some(previous) = self.previous.take() {
            let previous = Arc::clone(&previous);
            let _ = panic::take_hook();
            panic::set_hook(Box::new(move |info| previous(info)));
        }
    }
}

fn emit_report(report_dir: &Path, process: &str, info: &PanicHookInfo<'_>) {
    let timestamp_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis();
    let location = info
        .location()
        .map(|loc| format!("{}:{}:{}", loc.file(), loc.line(), loc.column()));
    let thread = std::thread::current().name().map(ToString::to_string);
    let message = if let Some(s) = info.payload().downcast_ref::<&str>() {
        s.to_string()
    } else if let Some(s) = info.payload().downcast_ref::<String>() {
        s.clone()
    } else {
        "unknown panic payload".to_string()
    };

    let context = CRASH_CONTEXT.with(|ctx| ctx.borrow().clone());
    let backtrace = std::backtrace::Backtrace::force_capture().to_string();

    let report = CrashReport {
        process: process.to_string(),
        backend: context.backend,
        circuit: context.circuit,
        message,
        location,
        thread,
        pid: process::id(),
        timestamp_ms,
        backtrace,
    };

    if let Err(err) = persist_report(report_dir, &report) {
        eprintln!("failed to persist zk crash report: {err}");
    }
}

fn persist_report(report_dir: &Path, report: &CrashReport) -> std::io::Result<()> {
    fs::create_dir_all(report_dir)?;
    static SEQUENCE: AtomicUsize = AtomicUsize::new(0);
    let sequence = SEQUENCE.fetch_add(1, Ordering::SeqCst);
    let file_path = report_dir.join(format!("{}.json", report.file_stem(sequence)));
    let mut file = File::create(&file_path)?;
    let json = serde_json::to_vec_pretty(report)?;
    file.write_all(&json)?;
    Ok(())
}

fn is_enabled(value: &str) -> bool {
    matches!(
        value.to_ascii_lowercase().as_str(),
        "1" | "true" | "yes" | "on" | "enabled"
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Mutex, OnceLock};
    use tempfile::TempDir;

    static SERIAL_HOOK: OnceLock<Mutex<()>> = OnceLock::new();

    #[test]
    fn panic_hook_writes_contextual_report() {
        let _guard = SERIAL_HOOK.get_or_init(|| Mutex::new(())).lock().unwrap();

        let temp = TempDir::new().expect("tempdir");
        let _hook = CrashReportHook::install(temp.path(), "prover-process");

        let _ctx = CrashContextGuard::enter("rpp-stark", "consensus");
        let _ = std::panic::catch_unwind(|| panic!("simulated crash"));

        let entries: Vec<_> = fs::read_dir(temp.path())
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .collect();
        assert_eq!(
            entries.len(),
            1,
            "crash report should be written exactly once"
        );

        let contents = fs::read(&entries[0]).unwrap();
        let report: CrashReport = serde_json::from_slice(&contents).unwrap();
        assert_eq!(report.process, "prover-process");
        assert_eq!(report.backend.as_deref(), Some("rpp-stark"));
        assert_eq!(report.circuit.as_deref(), Some("consensus"));
        assert!(!report.backtrace.trim().is_empty());
        assert!(report.message.contains("simulated crash"));
    }

    #[test]
    fn opt_in_respects_env_toggle() {
        let _guard = SERIAL_HOOK.get_or_init(|| Mutex::new(())).lock().unwrap();

        env::remove_var(OPT_IN_ENV);
        assert!(CrashReportHook::install_from_env("verifier").is_none());

        env::set_var(OPT_IN_ENV, "true");
        env::set_var(REPORT_DIR_ENV, DEFAULT_REPORT_DIR);
        let hook = CrashReportHook::install_from_env("verifier");
        assert!(hook.is_some());
    }
}
