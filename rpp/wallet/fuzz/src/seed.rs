use std::{
    env,
    num::ParseIntError,
    sync::{Mutex, Once},
};

use getrandom::register_custom_getrandom;
use rand_chacha::ChaCha20Rng;
use rand_core::{RngCore, SeedableRng};

const DEFAULT_SEED: u64 = 0x5A17_F00D;
const ENV_VAR: &str = "RPP_FUZZ_SEED";

fn parse_seed(raw: Option<String>) -> Result<u64, ParseIntError> {
    let Some(value) = raw else {
        return Ok(DEFAULT_SEED);
    };

    if let Some(hex) = value.strip_prefix("0x").or_else(|| value.strip_prefix("0X")) {
        u64::from_str_radix(hex, 16)
    } else {
        value.parse()
    }
}

fn seed_from_env() -> u64 {
    parse_seed(env::var(ENV_VAR).ok()).unwrap_or(DEFAULT_SEED)
}

fn seed_to_bytes(seed: u64) -> [u8; 32] {
    let mut bytes = [0u8; 32];
    bytes[..8].copy_from_slice(&seed.to_le_bytes());
    bytes
}

fn seeded_rng(seed: u64) -> ChaCha20Rng {
    ChaCha20Rng::from_seed(seed_to_bytes(seed))
}

fn global_rng() -> &'static Mutex<ChaCha20Rng> {
    static RNG: once_cell::sync::OnceCell<Mutex<ChaCha20Rng>> = once_cell::sync::OnceCell::new();
    RNG.get_or_init(|| Mutex::new(seeded_rng(seed_from_env())))
}

/// Installs a deterministic RNG that sources randomness from the configured seed.
///
/// The seed is read from `RPP_FUZZ_SEED` (decimal or `0x`-prefixed hexadecimal) and
/// falls back to `DEFAULT_SEED` when unspecified or malformed.
pub fn install_deterministic_rng() {
    static REGISTER: Once = Once::new();
    REGISTER.call_once(|| {
        register_custom_getrandom(|dest| {
            let mut guard = global_rng()
                .lock()
                .expect("fuzz seed RNG should not be poisoned");
            guard.fill_bytes(dest);
            Ok(())
        })
        .expect("fuzz seed RNG registration must succeed");
    });
}

#[cfg(test)]
mod tests {
    use super::{parse_seed, seeded_rng, seed_to_bytes, DEFAULT_SEED, ENV_VAR};
    use rand_core::RngCore;
    use std::env;

    fn stream(seed: u64) -> Vec<u8> {
        let mut rng = seeded_rng(seed);
        let mut buf = vec![0u8; 64];
        rng.fill_bytes(&mut buf);
        buf
    }

    #[test]
    fn identical_seeds_produce_identical_streams() {
        let reference = stream(0xABCDEF);
        assert_eq!(reference, stream(0xABCDEF));
    }

    #[test]
    fn distinct_seeds_change_stream() {
        assert_ne!(stream(1), stream(2));
    }

    #[test]
    fn env_seed_accepts_hex_and_decimal() {
        assert_eq!(parse_seed(Some("0x2A".into())).unwrap(), 42);
        assert_eq!(parse_seed(Some("42".into())).unwrap(), 42);
    }

    #[test]
    fn malformed_env_seed_falls_back_to_default() {
        let _guard = env::var_os(ENV_VAR);
        assert_eq!(parse_seed(Some("not-a-number".into())).unwrap(), DEFAULT_SEED);
    }

    #[test]
    fn seed_serialization_round_trips() {
        let seed = 0xDEADBEEF;
        let bytes = seed_to_bytes(seed);
        let mut rng = rand_chacha::ChaCha20Rng::from_seed(bytes);
        let mut other = seeded_rng(seed);

        let mut lhs = [0u8; 32];
        let mut rhs = [0u8; 32];
        rng.fill_bytes(&mut lhs);
        other.fill_bytes(&mut rhs);

        assert_eq!(lhs, rhs);
    }
}
