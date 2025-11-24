use blake2::{Blake2s256, Digest};
use std::env;
use std::sync::OnceLock;

/// Environment flag enabling deterministic prover behavior across backends.
pub const DETERMINISTIC_ENV: &str = "RPP_PROVER_DETERMINISTIC";

fn compute_seed(value: &str) -> [u8; 32] {
    let mut hasher = Blake2s256::new();
    hasher.update(value.as_bytes());
    hasher.update(b"RPP-PROVER");
    hasher.finalize().into()
}

fn seeded_value(raw: String) -> [u8; 32] {
    if raw.is_empty() {
        compute_seed("rpp-prover-deterministic")
    } else {
        compute_seed(&raw)
    }
}

fn cached_seed() -> Option<[u8; 32]> {
    static SEED: OnceLock<Option<[u8; 32]>> = OnceLock::new();
    SEED.get_or_init(|| env::var(DETERMINISTIC_ENV).ok().map(seeded_value))
        .as_ref()
        .copied()
}

/// Returns true when deterministic mode is requested via [`DETERMINISTIC_ENV`].
pub fn deterministic_mode() -> bool {
    cached_seed().is_some()
}

/// Supplies a deterministic 32-byte seed derived from [`DETERMINISTIC_ENV`].
pub fn deterministic_seed() -> Option<[u8; 32]> {
    cached_seed()
}
