use std::num::NonZeroU64;
use std::sync::Arc;

use rpp_chain::errors::ChainResult;
use rpp_chain::runtime::telemetry::metrics::RuntimeMetrics;
use rpp_chain::runtime::wallet::rpc::AuthToken;
use rpp_chain::runtime::wallet::runtime::{
    GenericWalletRuntimeHandle, NodeConnector, WalletRuntime, WalletRuntimeConfig, WalletService,
};
use rpp_chain::runtime::wallet::sync::DeterministicSync;

#[derive(Clone)]
struct TestWallet {
    address: String,
}

impl WalletService for TestWallet {
    fn address(&self) -> String {
        self.address.clone()
    }
}

struct NoopConnector;

impl NodeConnector<TestWallet> for NoopConnector {
    fn attach(&self, _wallet: &TestWallet) -> ChainResult<()> {
        Ok(())
    }
}

#[tokio::test(flavor = "current_thread")]
async fn wallet_runtime_propagates_limits() {
    let wallet = Arc::new(TestWallet {
        address: "wallet-limits".into(),
    });
    let metrics = RuntimeMetrics::noop();
    let mut config = WalletRuntimeConfig::new("127.0.0.1:0".parse().unwrap());
    config.allowed_origin = Some("https://wallet.example".into());
    config.auth_token = Some(AuthToken::new("limits-token"));
    config.requests_per_minute = NonZeroU64::new(60);

    let handle: GenericWalletRuntimeHandle<TestWallet> = WalletRuntime::start(
        Arc::clone(&wallet),
        config.clone(),
        Arc::clone(&metrics),
        Box::new(DeterministicSync::new("limits")),
        Some(Box::new(NoopConnector)),
    )
    .expect("runtime start");

    assert_eq!(handle.requests_per_minute(), config.requests_per_minute);
    assert_eq!(handle.allowed_origin(), config.allowed_origin.as_ref());
    assert!(handle.attached_to_node());

    handle.shutdown().await.expect("shutdown");
}
