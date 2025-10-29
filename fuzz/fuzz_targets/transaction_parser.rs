#![no_main]

use libfuzzer_sys::fuzz_target;
use rpp_chain::sync::RuntimeTransactionProofVerifier;
use rpp_p2p::pipeline::TransactionProofVerifier;

fuzz_target!(|data: &[u8]| {
    let verifier = RuntimeTransactionProofVerifier::default();
    let _ = verifier.verify(data);
});
