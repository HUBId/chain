#![no_main]

use libfuzzer_sys::fuzz_target;
use rpp_p2p::sanitize_meta_payload;

fuzz_target!(|data: &[u8]| {
    let _ = sanitize_meta_payload(data);
});
