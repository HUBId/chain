use std::sync::atomic::{AtomicBool, Ordering};

use once_cell::sync::OnceCell;
use tracing::warn;

use crate::errors::{ChainError, ChainResult};

/// Environment variable that acknowledges the experimental Plonky3 backend.
pub const ACK_ENV: &str = "CHAIN_PLONKY3_EXPERIMENTAL";

static CLI_ACK: AtomicBool = AtomicBool::new(false);
static WARNED: AtomicBool = AtomicBool::new(false);
static ENV_ACK: OnceCell<bool> = OnceCell::new();

fn parse_env_ack() -> bool {
    let value = match std::env::var(ACK_ENV) {
        Ok(value) => value,
        Err(_) => return false,
    };
    matches!(
        value.trim().to_ascii_lowercase().as_str(),
        "1" | "true" | "yes" | "allow"
    )
}

fn env_acknowledged() -> bool {
    *ENV_ACK.get_or_init(parse_env_ack)
}

fn acked() -> bool {
    CLI_ACK.load(Ordering::SeqCst) || env_acknowledged()
}

fn emit_warning_once() {
    if WARNED.swap(true, Ordering::SeqCst) {
        return;
    }
    warn!(
        "plonky3 backend enabled in experimental mode; proofs offer no cryptographic soundness"
    );
}

/// Marks the experimental backend as acknowledged through the CLI flag.
pub fn acknowledge_via_cli() {
    CLI_ACK.store(true, Ordering::SeqCst);
    emit_warning_once();
}

/// Provides the canonical warning string presented to operators.
pub fn warning_banner() -> String {
    "Plonky3 backend is experimental and provides no cryptographic soundness.".into()
}

/// Returns any warnings that should be exposed via APIs or telemetry.
pub fn warnings() -> Vec<String> {
    if acked() {
        vec![warning_banner()]
    } else {
        Vec::new()
    }
}

/// Ensures the experimental backend has been acknowledged.
pub fn require_acknowledgement() -> ChainResult<()> {
    if acked() {
        emit_warning_once();
        Ok(())
    } else {
        Err(ChainError::Config(format!(
            "plonky3 backend is experimental and provides no cryptographic soundness. \
             Re-run with --experimental-plonky3 or set {ACK_ENV}=1 to acknowledge the risk."
        )))
    }
}

/// Test helper enabling the experimental backend for deterministic fixtures.
#[allow(dead_code)]
pub fn force_enable_for_tests() {
    CLI_ACK.store(true, Ordering::SeqCst);
    emit_warning_once();
}
