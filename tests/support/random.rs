//! Utilities for deterministic randomness in integration tests.
//!
//! Tests that rely on randomness should call [`seeded_rng`] before generating
//! random values. This ensures runs can be reproduced by setting
//! `RPP_TEST_SEED` to the seed emitted in the test logs.

use rand::rngs::{OsRng, StdRng};
use rand::{RngCore, SeedableRng};
use std::env;

const ENV_VAR: &str = "RPP_TEST_SEED";

/// Returns a [`StdRng`] seeded using a process-wide deterministic seed.
///
/// If the seed is already present in the `RPP_TEST_SEED` environment variable,
/// it will be reused. Otherwise, a new seed is generated from [`OsRng`], stored
/// in the environment for subsequent calls, and logged for debugging.
pub fn seeded_rng(test_name: &str) -> StdRng {
    let seed = match env::var(ENV_VAR) {
        Ok(value) => value.parse::<u64>().expect("RPP_TEST_SEED must be a valid u64"),
        Err(_) => {
            let mut os_rng = OsRng;
            let seed = os_rng.next_u64();
            env::set_var(ENV_VAR, seed.to_string());
            println!(
                "[support::random] generated seed {seed} for test `{test_name}`; set {ENV_VAR} to reuse"
            );
            seed
        }
    };

    StdRng::seed_from_u64(seed)
}
