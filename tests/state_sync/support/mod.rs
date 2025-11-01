//! Shared harness for state-sync regression coverage.
//!
//! This module mirrors the light-client integration fixture from
//! [`tests/light_client_sync.rs`](../light_client_sync.rs) and powers the
//! [`proof_error_io`](../proof_error_io.rs) regression test.

#![allow(dead_code)]

use std::sync::Arc;

use blake3::Hash;
use firewood_storage::{
    FileIoError, LinearAddress, MaybePersistedNode, NodeReader, RootReader, SharedNode,
};
use parking_lot::RwLock;
use rpp_chain::config::NodeConfig;
use rpp_chain::node::{Node, NodeHandle, DEFAULT_STATE_SYNC_CHUNK};
use rpp_chain::runtime::metrics::RuntimeMetrics;
use rpp_chain::runtime::node::StateSyncSessionCache;
use rpp_chain::runtime::sync::{ReconstructionEngine, StateSyncPlan};
use rpp_chain::storage::Storage;
use rpp_p2p::{PipelineError, SnapshotStore};
use tempfile::TempDir;

#[path = "../../support/mod.rs"]
mod shared_support;

use shared_support::collect_state_sync_artifacts;

#[derive(Debug)]
struct FailingRootReader {
    root: MaybePersistedNode,
}

impl FailingRootReader {
    fn new() -> Self {
        Self {
            root: MaybePersistedNode::from(
                LinearAddress::new(1).expect("failing reader requires non-zero address"),
            ),
        }
    }

    fn io_error(&self) -> FileIoError {
        FileIoError::from_generic_no_file(
            std::io::Error::new(std::io::ErrorKind::Other, "failing root read"),
            "failing root read",
        )
    }
}

impl NodeReader for FailingRootReader {
    fn read_node(&self, _address: LinearAddress) -> Result<SharedNode, FileIoError> {
        Err(self.io_error())
    }
}

impl RootReader for FailingRootReader {
    fn root_node(&self) -> Result<Option<SharedNode>, FileIoError> {
        Err(self.io_error())
    }

    fn root_as_maybe_persisted_node(&self) -> Option<MaybePersistedNode> {
        Some(self.root.clone())
    }
}

/// Integration harness that provisions an in-process node with snapshot artefacts.
pub struct StateSyncFixture {
    #[allow(dead_code)]
    temp_dir: TempDir,
    node: Node,
    handle: NodeHandle,
    _storage: Storage,
    plan: StateSyncPlan,
    chunk_size: usize,
}

impl StateSyncFixture {
    /// Bootstraps a node, captures state-sync artefacts, and prunes the genesis payload.
    pub fn new() -> Self {
        let chunk_size = DEFAULT_STATE_SYNC_CHUNK;
        let (config, temp_dir) = prepare_config();
        let node = Node::new(config, RuntimeMetrics::noop()).expect("node");
        let handle = node.handle();
        let storage = handle.storage();
        let pruned = storage
            .prune_block_payload(0)
            .expect("prune genesis payload");
        assert!(pruned, "expected genesis payload to be pruned");
        let engine = ReconstructionEngine::new(storage.clone());
        let artifacts =
            collect_state_sync_artifacts(&engine, chunk_size).expect("state sync artifacts");
        assert!(
            !artifacts.plan.chunks.is_empty(),
            "state sync plan should contain at least one chunk"
        );
        Self {
            temp_dir,
            node,
            handle,
            _storage: storage,
            plan: artifacts.plan,
            chunk_size,
        }
    }

    /// Returns a clone of the runtime handle for the bootstrapped node.
    pub fn handle(&self) -> NodeHandle {
        self.handle.clone()
    }

    /// Constructs a state-sync cache whose chunk retrievals always surface a proof IO error.
    pub fn failing_session_cache(&self) -> StateSyncSessionCache {
        let reader = FailingRootReader::new();
        let proof_error = format!("ProofError::IO({})", reader.io_error());

        let chunk_size = self.chunk_size;
        let total_chunks = self.plan.chunks.len();
        let store = SnapshotStore::with_chunk_override(chunk_size, move |_, _| {
            Err(PipelineError::SnapshotVerification(proof_error.clone()))
        });
        let root = Hash::from_bytes(self.plan.snapshot.commitments.global_state_root);
        StateSyncSessionCache::verified_for_tests(
            root,
            chunk_size,
            total_chunks,
            Arc::new(RwLock::new(store)),
        )
    }
}

fn prepare_config() -> (NodeConfig, TempDir) {
    let temp_dir = TempDir::new().expect("temp dir");
    let mut config = NodeConfig::default();
    let data_dir = temp_dir.path().join("data");
    let keys_dir = temp_dir.path().join("keys");
    std::fs::create_dir_all(&data_dir).expect("data dir");
    std::fs::create_dir_all(&keys_dir).expect("keys dir");
    config.data_dir = data_dir.clone();
    config.snapshot_dir = data_dir.join("snapshots");
    config.proof_cache_dir = data_dir.join("proofs");
    config.network.p2p.peerstore_path = data_dir.join("p2p/peerstore.json");
    config.network.p2p.gossip_path = Some(data_dir.join("p2p/gossip.json"));
    config.key_path = keys_dir.join("node.toml");
    config.p2p_key_path = keys_dir.join("p2p.toml");
    config.vrf_key_path = keys_dir.join("vrf.toml");
    config.network.rpc.listen = "127.0.0.1:0".parse().expect("rpc listen");
    (config, temp_dir)
}
