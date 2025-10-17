use std::fmt;
use std::path::Path;
use std::sync::Arc;

use anyhow::{Context, Result};
use rpp::runtime::node::NodeHandle;
use rpp::runtime::orchestration::PipelineOrchestrator;
use rpp::runtime::sync::{PayloadProvider, RuntimeRecursiveProofVerifier};
use storage_firewood::kv::{FirewoodKv, Hash, KvError};
use storage_firewood::Storage;

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
