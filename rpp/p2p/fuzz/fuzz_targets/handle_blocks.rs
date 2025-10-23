#![no_main]

use libfuzzer_sys::fuzz_target;
use rpp_chain::types::Block;
use rpp_p2p::sanitize_block_payload;

fuzz_target!(|data: &[u8]| {
    let _ = sanitize_block_payload::<Block>(data);
});
