use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use rpp_chain::errors::ChainResult;
use rpp_chain::runtime::telemetry::metrics::RuntimeMetrics;
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

struct RecordingConnector {
    attached: Arc<AtomicBool>,
}

impl NodeConnector<TestWallet> for RecordingConnector {
    fn attach(&self, _wallet: &TestWallet) -> ChainResult<()> {
        self.attached.store(true, Ordering::SeqCst);
        Ok(())
    }
}

#[tokio::test(flavor = "current_thread")]
async fn hybrid_mode_attaches_connector() {
    let attached = Arc::new(AtomicBool::new(false));
    let wallet = Arc::new(TestWallet {
        address: "hybrid-wallet".into(),
    });
    let metrics = RuntimeMetrics::noop();
    let connector = RecordingConnector {
        attached: Arc::clone(&attached),
    };
    let config = WalletRuntimeConfig::new("127.0.0.1:0".parse().unwrap());

    let handle: GenericWalletRuntimeHandle<TestWallet> = WalletRuntime::start(
        Arc::clone(&wallet),
        config,
        Arc::clone(&metrics),
        Box::new(DeterministicSync::new("hybrid")),
        Some(Box::new(connector)),
    )
    .expect("runtime start");

    assert!(handle.attached_to_node());
    assert!(attached.load(Ordering::SeqCst));

    handle.shutdown().await.expect("shutdown");
}
