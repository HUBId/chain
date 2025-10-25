#![cfg(feature = "vendor_electrs")]

use std::fs;
use std::path::Path;
use std::sync::Arc;

use anyhow::Result;
use tempfile::TempDir;

use rpp::errors::{ChainError, ChainResult};
use rpp::runtime::config::NodeConfig;
use rpp::runtime::node::Node;
use rpp::runtime::orchestration::PipelineOrchestrator;
use rpp::runtime::sync::{PayloadProvider, ReconstructionRequest, RuntimeRecursiveProofVerifier};
use rpp::runtime::types::BlockPayload;
use rpp::runtime::RuntimeMetrics;

use rpp_wallet::config::{
    CacheConfig, ElectrsConfig, FeatureGates, NetworkSelection, P2pConfig, TrackerConfig,
};
use rpp_wallet::vendor::electrs::firewood_adapter::RuntimeAdapters;
use rpp_wallet::vendor::electrs::init::initialize;
use rpp_wallet::vendor::electrs::rpp_ledger::bitcoin::blockdata::constants;
use rpp_wallet::vendor::electrs::Tracker;

#[test]
fn initialize_with_runtime_and_tracker() -> Result<()> {
    let temp = TempDir::new()?;
    let firewood_dir = temp.path().join("firewood");
    let index_dir = temp.path().join("index");
    fs::create_dir_all(&firewood_dir)?;
    fs::create_dir_all(&index_dir)?;

    let runtime = build_runtime_adapters(temp.path());

    let config = ElectrsConfig {
        network: NetworkSelection::Signet,
        features: FeatureGates {
            runtime: true,
            tracker: true,
        },
        cache: CacheConfig::default(),
        tracker: TrackerConfig::default(),
        p2p: P2pConfig::default(),
    };

    let handles = initialize(&config, &firewood_dir, &index_dir, Some(runtime.clone()))?;

    assert!(
        handles.firewood.runtime().is_some(),
        "runtime adapters attached"
    );
    assert!(handles.daemon.is_some(), "daemon instantiated");
    assert!(handles.tracker.is_some(), "tracker instantiated");

    let tracker = handles.tracker.as_ref().unwrap();
    assert_network(tracker, config.network);

    Ok(())
}

#[test]
fn initialize_without_runtime_skips_optional_handles() -> Result<()> {
    let temp = TempDir::new()?;
    let firewood_dir = temp.path().join("firewood");
    let index_dir = temp.path().join("index");
    fs::create_dir_all(&firewood_dir)?;
    fs::create_dir_all(&index_dir)?;

    let config = ElectrsConfig {
        network: NetworkSelection::Regtest,
        features: FeatureGates {
            runtime: false,
            tracker: false,
        },
        cache: CacheConfig::default(),
        tracker: TrackerConfig::default(),
        p2p: P2pConfig::default(),
    };

    let handles = initialize(&config, &firewood_dir, &index_dir, None)?;

    assert!(
        handles.firewood.runtime().is_none(),
        "runtime adapters disabled"
    );
    assert!(handles.daemon.is_none(), "daemon disabled");
    assert!(handles.tracker.is_none(), "tracker disabled");

    Ok(())
}

#[test]
fn tracker_requires_runtime() {
    let temp = TempDir::new().expect("tempdir");
    let firewood_dir = temp.path().join("firewood");
    let index_dir = temp.path().join("index");
    fs::create_dir_all(&firewood_dir).expect("firewood dir");
    fs::create_dir_all(&index_dir).expect("index dir");

    let config = ElectrsConfig {
        network: NetworkSelection::Testnet,
        features: FeatureGates {
            runtime: false,
            tracker: true,
        },
        cache: CacheConfig::default(),
        tracker: TrackerConfig::default(),
        p2p: P2pConfig::default(),
    };

    let error =
        initialize(&config, &firewood_dir, &index_dir, None).expect_err("tracker needs runtime");
    assert!(
        error
            .to_string()
            .contains("tracker feature requires the runtime feature"),
        "error message should reference runtime dependency"
    );
}

#[test]
fn config_parses_from_json_and_drives_features() -> Result<()> {
    let payload = r#"{
        "network": "mainnet",
        "features": {
            "runtime": true,
            "tracker": false
        }
    }"#;

    let config: ElectrsConfig = serde_json::from_str(payload)?;
    assert_eq!(config.network, NetworkSelection::Mainnet);
    assert!(config.features.runtime);
    assert!(!config.features.tracker);

    let temp = TempDir::new()?;
    let firewood_dir = temp.path().join("firewood");
    let index_dir = temp.path().join("index");
    fs::create_dir_all(&firewood_dir)?;
    fs::create_dir_all(&index_dir)?;

    let runtime = build_runtime_adapters(temp.path());
    let handles = initialize(&config, &firewood_dir, &index_dir, Some(runtime))?;

    assert!(
        handles.firewood.runtime().is_some(),
        "runtime enabled in config"
    );
    assert!(
        handles.daemon.is_some(),
        "daemon expected when runtime enabled"
    );
    assert!(handles.tracker.is_none(), "tracker disabled in config");

    Ok(())
}

fn assert_network(tracker: &Tracker, network: NetworkSelection) {
    let expected = constants::genesis_block(network.into());
    assert_eq!(tracker.chain().height(), 0, "fresh index height");
    assert_eq!(
        tracker.chain().tip(),
        expected.header.block_hash(),
        "genesis hash"
    );
}

fn build_runtime_adapters(base: &Path) -> RuntimeAdapters {
    let mut config = NodeConfig::default();
    config.data_dir = base.join("node/data");
    config.key_path = base.join("node/keys/node.toml");
    config.p2p_key_path = base.join("node/keys/p2p.toml");
    config.vrf_key_path = base.join("node/keys/vrf.toml");
    config.snapshot_dir = base.join("node/snapshots");
    config.proof_cache_dir = base.join("node/proofs");

    let node = Node::new(config, RuntimeMetrics::noop()).expect("node");
    let node_handle = node.handle();
    let storage = node_handle.storage();

    let (orchestrator, _shutdown) = PipelineOrchestrator::new(node_handle.clone(), None);
    let provider = Arc::new(DummyPayloadProvider::default());
    let proof_verifier = Arc::new(RuntimeRecursiveProofVerifier::default());

    RuntimeAdapters::new(
        Arc::new(storage.clone()),
        node_handle,
        orchestrator,
        provider,
        proof_verifier,
    )
}

#[derive(Default)]
struct DummyPayloadProvider;

impl PayloadProvider for DummyPayloadProvider {
    fn fetch_payload(&self, request: &ReconstructionRequest) -> ChainResult<BlockPayload> {
        Err(ChainError::Config(format!(
            "no payload available for height {}",
            request.height
        )))
    }
}
