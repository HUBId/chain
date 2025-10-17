use std::fmt;
use std::path::Path;
use std::sync::Arc;

use anyhow::{anyhow, Context, Result};
use rpp::runtime::node::{MempoolStatus, NodeHandle};
use rpp::runtime::orchestration::{PipelineDashboardSnapshot, PipelineOrchestrator};
use rpp::runtime::sync::{
    PayloadProvider, ReconstructionPlan, RuntimeRecursiveProofVerifier,
};
use rpp::runtime::types::{Block, BlockHeader, BlockMetadata};
use rpp_p2p::GossipTopic;
use storage_firewood::kv::{FirewoodKv, Hash, KvError};
use storage_firewood::Storage;
use tokio::sync::{broadcast, watch};

/// Thin wrapper around the Firewood key-value engine that exposes a simplified
/// API tailored to the Electrs integration.
pub struct FirewoodAdapter {
    inner: FirewoodKv,
    runtime: Option<RuntimeAdapters>,
}

impl FirewoodAdapter {
    /// Open (or create) a Firewood instance rooted at `path`.
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let inner = FirewoodKv::open(path).context("open firewood store")?;
        Ok(Self {
            inner,
            runtime: None,
        })
    }

    /// Open (or create) a Firewood instance and attach runtime adapters.
    pub fn open_with_runtime(
        path: impl AsRef<Path>,
        runtime: RuntimeAdapters,
    ) -> Result<Self> {
        let inner = FirewoodKv::open(path).context("open firewood store")?;
        Ok(Self {
            inner,
            runtime: Some(runtime),
        })
    }

    /// Wrap an existing Firewood handle together with runtime adapters.
    pub fn from_parts(inner: FirewoodKv, runtime: RuntimeAdapters) -> Self {
        Self {
            inner,
            runtime: Some(runtime),
        }
    }

    /// Attach runtime adapters to an already-open handle.
    pub fn attach_runtime(&mut self, runtime: RuntimeAdapters) {
        self.runtime = Some(runtime);
    }

    /// Expose the attached runtime adapters, if available.
    pub fn runtime(&self) -> Option<&RuntimeAdapters> {
        self.runtime.as_ref()
    }

    fn require_runtime(&self) -> Result<&RuntimeAdapters> {
        self.runtime
            .as_ref()
            .ok_or_else(|| anyhow!("firewood runtime adapters not attached"))
    }

    fn collect_blocks_from(&self, start_height: u64) -> Result<Vec<Block>> {
        let runtime = self.require_runtime()?;
        let node = runtime.node();
        let status = node
            .node_status()
            .map_err(|err| anyhow!("query node status: {err}"))?;
        let tip_height = status
            .tip
            .as_ref()
            .map(|metadata| metadata.height)
            .unwrap_or(status.height);
        if start_height > tip_height {
            return Ok(Vec::new());
        }
        let mut blocks = Vec::new();
        for height in start_height..=tip_height {
            if let Some(block) = node
                .get_block(height)
                .map_err(|err| anyhow!("load block {height}: {err}"))?
            {
                blocks.push(block);
            }
        }
        Ok(blocks)
    }

    /// Stream block headers from the runtime starting at the supplied height.
    pub fn stream_headers_from(&self, start_height: u64) -> Result<Vec<BlockHeader>> {
        let blocks = self.collect_blocks_from(start_height)?;
        Ok(blocks.into_iter().map(|block| block.header).collect())
    }

    /// Stream block metadata from the runtime starting at the supplied height.
    pub fn stream_metadata_from(&self, start_height: u64) -> Result<Vec<BlockMetadata>> {
        let blocks = self.collect_blocks_from(start_height)?;
        Ok(blocks.iter().map(BlockMetadata::from).collect())
    }

    /// Fetch a snapshot of the current mempool state from the runtime node.
    pub fn mempool_snapshot(&self) -> Result<MempoolStatus> {
        let runtime = self.require_runtime()?;
        runtime
            .node()
            .mempool_status()
            .map_err(|err| anyhow!("fetch mempool snapshot: {err}"))
    }

    /// Reconstruct a block payload at the requested height using the configured provider.
    pub fn reconstruct_block(&self, height: u64) -> Result<Block> {
        let runtime = self.require_runtime()?;
        let provider = Arc::clone(runtime.payload_provider());
        runtime
            .node()
            .reconstruct_block(height, provider.as_ref())
            .map_err(|err| anyhow!("reconstruct block {height}: {err}"))
    }

    /// Reconstruct a range of blocks using the configured payload provider.
    pub fn reconstruct_range(&self, start_height: u64, end_height: u64) -> Result<Vec<Block>> {
        let runtime = self.require_runtime()?;
        let provider = Arc::clone(runtime.payload_provider());
        runtime
            .node()
            .reconstruct_range(start_height, end_height, provider.as_ref())
            .map_err(|err| anyhow!(
                "reconstruct blocks {start_height}..={end_height}: {err}"
            ))
    }

    /// Execute a precomputed reconstruction plan using the configured payload provider.
    pub fn execute_reconstruction_plan(
        &self,
        plan: &ReconstructionPlan,
    ) -> Result<Vec<Block>> {
        let runtime = self.require_runtime()?;
        let provider = Arc::clone(runtime.payload_provider());
        runtime
            .node()
            .execute_reconstruction_plan(plan, provider.as_ref())
            .map_err(|err| anyhow!("execute reconstruction plan: {err}"))
    }

    /// Verify a recursive proof payload using the runtime verifier registry.
    pub fn verify_recursive_proof(
        &self,
        proof: &[u8],
        expected_commitment: &str,
        previous_commitment: Option<&str>,
    ) -> Result<()> {
        let runtime = self.require_runtime()?;
        runtime
            .proof_verifier()
            .verify_recursive(proof, expected_commitment, previous_commitment)
            .map_err(|err| anyhow!("verify recursive proof: {err}"))
    }

    /// Subscribe to runtime gossip for the requested topic.
    pub fn subscribe_gossip(
        &self,
        topic: GossipTopic,
    ) -> Result<broadcast::Receiver<Vec<u8>>> {
        let runtime = self.require_runtime()?;
        Ok(runtime.node().subscribe_witness_gossip(topic))
    }

    /// Publish payloads onto the runtime gossip channels.
    pub fn publish_gossip(&self, topic: GossipTopic, payload: &[u8]) -> Result<()> {
        let runtime = self.require_runtime()?;
        runtime.node().fanout_witness_gossip(topic, payload);
        Ok(())
    }

    /// Subscribe to orchestrated pipeline dashboard snapshots.
    pub fn subscribe_pipeline_dashboard(
        &self,
    ) -> Result<watch::Receiver<PipelineDashboardSnapshot>> {
        let runtime = self.require_runtime()?;
        Ok(runtime.orchestrator().subscribe_dashboard())
    }

    /// Stage a put mutation.
    pub fn put(&mut self, key: Vec<u8>, value: Vec<u8>) {
        self.inner.put(key, value);
    }

    /// Stage a delete mutation.
    pub fn delete(&mut self, key: &[u8]) {
        self.inner.delete(key);
    }

    /// Fetch a value without mutating the staged batch.
    pub fn get(&self, key: &[u8]) -> Option<Vec<u8>> {
        self.inner.get(key)
    }

    /// Iterate over the state using a prefix filter.
    pub fn scan_prefix(&self, prefix: &[u8]) -> Vec<(Vec<u8>, Vec<u8>)> {
        self.inner.scan_prefix(prefix).collect()
    }

    /// Commit all staged mutations and persist them to disk.
    pub fn commit(&mut self) -> Result<Hash> {
        self.inner.commit().map_err(|err| match err {
            KvError::EmptyCommit => anyhow::anyhow!("firewood commit without mutations"),
            other => anyhow::Error::new(other).context("commit firewood state"),
        })
    }
}

impl fmt::Debug for FirewoodAdapter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FirewoodAdapter")
            .field("has_runtime", &self.runtime.is_some())
            .finish()
    }
}

/// Runtime-backed clients that Electrs components depend on when the tracker is
/// driven by the Firewood runtime.
#[derive(Clone)]
pub struct RuntimeAdapters {
    storage: Arc<Storage>,
    node: NodeHandle,
    orchestrator: PipelineOrchestrator,
    payload_provider: Arc<dyn PayloadProvider + Send + Sync>,
    proof_verifier: Arc<RuntimeRecursiveProofVerifier>,
}

impl RuntimeAdapters {
    /// Construct a new bundle of runtime adapters required by the tracker.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        storage: Arc<Storage>,
        node: NodeHandle,
        orchestrator: PipelineOrchestrator,
        payload_provider: Arc<dyn PayloadProvider + Send + Sync>,
        proof_verifier: Arc<RuntimeRecursiveProofVerifier>,
    ) -> Self {
        Self {
            storage,
            node,
            orchestrator,
            payload_provider,
            proof_verifier,
        }
    }

    /// Storage handle backed by the Firewood runtime.
    pub fn storage(&self) -> &Arc<Storage> {
        &self.storage
    }

    /// Handle to the running node instance.
    pub fn node(&self) -> &NodeHandle {
        &self.node
    }

    /// Pipeline orchestrator driving the runtime workflows.
    pub fn orchestrator(&self) -> &PipelineOrchestrator {
        &self.orchestrator
    }

    /// Payload provider used by the reconstruction engine.
    pub fn payload_provider(&self) -> &Arc<dyn PayloadProvider + Send + Sync> {
        &self.payload_provider
    }

    /// Recursive proof verifier backed by the runtime registry.
    pub fn proof_verifier(&self) -> &Arc<RuntimeRecursiveProofVerifier> {
        &self.proof_verifier
    }
}
