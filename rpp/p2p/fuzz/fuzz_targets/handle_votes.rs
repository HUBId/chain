#![no_main]

use libfuzzer_sys::fuzz_target;
use rpp_chain::consensus::SignedBftVote;
use rpp_p2p::sanitize_vote_payload;

fuzz_target!(|data: &[u8]| {
    let _ = sanitize_vote_payload::<SignedBftVote>(data);
});
