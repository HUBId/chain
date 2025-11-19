#![cfg(feature = "wallet-integration")]

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use rpp_chain::errors::ChainResult;
use rpp_chain::runtime::telemetry::metrics::RuntimeMetrics;
use rpp_chain::runtime::wallet::runtime::{
    GenericWalletRuntimeHandle, NodeAttachment, NodeConnector, SyncDriver, WalletRuntime,
    WalletRuntimeConfig, WalletService,
};
use rpp_chain::runtime::wallet::sync::DeterministicSync;
use rpp_wallet::runtime::lifecycle::{
    EmbeddedNodeCommand, EmbeddedNodeLifecycle, EmbeddedNodeStatus,
};
use rpp_wallet::node_client::{NodeClient, StubNodeClient};
use rpp_wallet_interface::WalletServiceResult;
use tokio::sync::watch;

#[derive(Clone)]
struct TestWallet {
    address: String,
    node_client_attached: Arc<AtomicBool>,
}

impl WalletService for TestWallet {
    fn address(&self) -> String {
        self.address.clone()
    }

    fn attach_node_client(&self, _client: Arc<dyn NodeClient>) -> WalletServiceResult<()> {
        self.node_client_attached.store(true, Ordering::SeqCst);
        Ok(())
    }
}

struct RecordingConnector {
    attached: Arc<AtomicBool>,
    node_client: Arc<dyn NodeClient>,
}

impl NodeConnector<TestWallet> for RecordingConnector {
    fn attach(&self, _wallet: &TestWallet) -> ChainResult<NodeAttachment> {
        self.attached.store(true, Ordering::SeqCst);
        Ok(NodeAttachment::new(Some(Arc::clone(&self.node_client))))
    }
}

struct RecordingSyncDriver {
    started: Arc<AtomicBool>,
    shutdown_observed: Arc<AtomicBool>,
}

impl SyncDriver for RecordingSyncDriver {
    fn spawn(
        self: Box<Self>,
        _metrics: Arc<RuntimeMetrics>,
        mut shutdown_rx: watch::Receiver<bool>,
    ) -> ChainResult<tokio::task::JoinHandle<()>> {
        let RecordingSyncDriver {
            started,
            shutdown_observed,
        } = *self;
        started.store(true, Ordering::SeqCst);
        Ok(tokio::spawn(async move {
            loop {
                if *shutdown_rx.borrow() {
                    break;
                }
                if shutdown_rx.changed().await.is_err() {
                    break;
                }
            }
            shutdown_observed.store(true, Ordering::SeqCst);
        }))
    }
}

#[tokio::test(flavor = "current_thread")]
async fn hybrid_mode_attaches_connector() {
    let attached = Arc::new(AtomicBool::new(false));
    let node_client_attached = Arc::new(AtomicBool::new(false));
    let sync_started = Arc::new(AtomicBool::new(false));
    let sync_shutdown = Arc::new(AtomicBool::new(false));
    let wallet = Arc::new(TestWallet {
        address: "hybrid-wallet".into(),
        node_client_attached: Arc::clone(&node_client_attached),
    });
    let metrics = RuntimeMetrics::noop();
    let connector = RecordingConnector {
        attached: Arc::clone(&attached),
        node_client: Arc::new(StubNodeClient::default()),
    };
    let sync_driver = RecordingSyncDriver {
        started: Arc::clone(&sync_started),
        shutdown_observed: Arc::clone(&sync_shutdown),
    };
    let mut config = WalletRuntimeConfig::new("127.0.0.1:0".parse().unwrap());
    let mut node_command = EmbeddedNodeCommand::new("sh");
    node_command.args = vec!["-c".into(), "sleep 5".into()];
    let lifecycle = EmbeddedNodeLifecycle::new(
        rpp_wallet_interface::runtime_config::WalletNodeRuntimeConfig {
            embedded: true,
            gossip_endpoints: Vec::new(),
        },
        node_command,
        Vec::new(),
        Vec::new(),
    );
    config.set_embedded_node(lifecycle.clone());

    let handle: GenericWalletRuntimeHandle<TestWallet> = WalletRuntime::start(
        Arc::clone(&wallet),
        config,
        Arc::clone(&metrics),
        Box::new(DeterministicSync::new("hybrid")),
        Some(Box::new(sync_driver)),
        Some(Box::new(connector)),
        None,
    )
    .expect("runtime start");

    assert!(handle.attached_to_node());
    assert!(attached.load(Ordering::SeqCst));
    assert!(node_client_attached.load(Ordering::SeqCst));
    assert!(sync_started.load(Ordering::SeqCst));
    assert!(matches!(
        handle.embedded_node_status(),
        Some(EmbeddedNodeStatus::Running { .. })
    ));

    handle.shutdown().await.expect("shutdown");

    assert!(sync_shutdown.load(Ordering::SeqCst));
    assert!(matches!(
        handle.embedded_node_status(),
        Some(EmbeddedNodeStatus::Stopped)
    ));
}
