#![cfg(feature = "wallet_zsi")]
#![no_main]

//! This fuzz target requires the `wallet_zsi` feature. Enable with `--features wallet_zsi`.

use libfuzzer_sys::fuzz_target;
use prover_mock_backend::MockBackend;
use rpp_wallet::rpc::zsi::{self, AuditParams, IssueParams, RevokeParams, RotateParams};

fuzz_target!(|data: &[u8]| {
    if let Ok(params) = serde_json::from_slice::<IssueParams>(data) {
        let _ = zsi::issue(MockBackend::new(), params);
    }

    if let Ok(params) = serde_json::from_slice::<RotateParams>(data) {
        let _ = zsi::rotate(MockBackend::new(), params);
    }

    if let Ok(params) = serde_json::from_slice::<RevokeParams>(data) {
        let _ = zsi::revoke(MockBackend::new(), params);
    }

    if let Ok(params) = serde_json::from_slice::<AuditParams>(data) {
        let _ = zsi::audit(MockBackend::new(), params);
    }
});
