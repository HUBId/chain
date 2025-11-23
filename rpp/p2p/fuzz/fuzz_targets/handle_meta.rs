#![no_main]

use libfuzzer_sys::fuzz_target;
use rpp_p2p::sanitize_meta_payload;

#[cfg(feature = "backend-rpp-stark")]
#[path = "../src/seed.rs"]
mod seed;

fuzz_target!(|data: &[u8]| {
    #[cfg(feature = "backend-rpp-stark")]
    seed::install_deterministic_rng();

    let _ = sanitize_meta_payload(data);
});
