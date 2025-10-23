pub mod proofs;
pub mod tabs;
pub mod wallet;
pub mod workflows;

use tokio::runtime::Handle;
use tokio::sync::oneshot;
use tokio::task::{self, JoinHandle};

use crate::config::NodeConfig;
use crate::errors::{ChainError, ChainResult};
use crate::node::NodeInner;
use crate::node::{
    ConsensusStatus, MempoolStatus, NodeHandle, NodeStatus, NodeTelemetrySnapshot, RolloutStatus,
};

pub use crate::types::{ChainProof, UptimeProof};
pub use proofs::{ProofGenerator, TxProof};
pub use tabs::{
    HistoryEntry, HistoryStatus, NodeTabMetrics, PipelineHistoryStatus, ReceiveTabAddress,
    SendPreview,
};
pub use wallet::{
    ConsensusReceipt, PipelineFeedState, Wallet, WalletAccountSummary, WalletNodeRuntimeStatus,
};
#[cfg(feature = "vendor_electrs")]
pub use wallet::{
    ScriptStatusMetadata, TrackedScriptSnapshot, TrackerSnapshot, TrackerState, WalletTrackerHandle,
};
pub use workflows::{
    IdentityFinalizationPhase, IdentityGenesisPhase, IdentityQuorumPhase, IdentityWorkflow,
    IdentityWorkflowState, ReputationStatus, TransactionPolicy, TransactionWorkflow,
    UptimeWorkflow, WalletWorkflows,
};

/// Handle returned by [`start_node`] encapsulating the running node task and configuration.
pub struct WalletNodeRuntime {
    config: NodeConfig,
    handle: NodeHandle,
    join: JoinHandle<()>,
}

impl WalletNodeRuntime {
    async fn blocking_call<F, T>(&self, func: F) -> ChainResult<T>
    where
        F: FnOnce(NodeHandle) -> ChainResult<T> + Send + 'static,
        T: Send + 'static,
    {
        let handle = self.handle.clone();
        let (tx, rx) = oneshot::channel();
        std::thread::spawn(move || {
            let result = func(handle);
            let _ = tx.send(result);
        });
        rx.await.map_err(|err| {
            ChainError::Config(format!("node runtime blocking task cancelled: {err}"))
        })?
    }

    /// Returns the node configuration that produced this runtime.
    pub fn config(&self) -> &NodeConfig {
        &self.config
    }

    /// Returns the address of the running node instance.
    pub fn address(&self) -> &str {
        self.handle.address()
    }

    /// Fetches the latest node status snapshot.
    pub fn node_status(&self) -> ChainResult<NodeStatus> {
        if Handle::try_current().is_ok() {
            task::block_in_place(|| self.handle.node_status())
        } else {
            self.handle.node_status()
        }
    }

    /// Fetches the latest node status snapshot without blocking the async runtime.
    pub async fn node_status_async(&self) -> ChainResult<NodeStatus> {
        self.blocking_call(|handle| handle.node_status()).await
    }

    /// Fetches the latest mempool status snapshot.
    pub fn mempool_status(&self) -> ChainResult<MempoolStatus> {
        if Handle::try_current().is_ok() {
            task::block_in_place(|| self.handle.mempool_status())
        } else {
            self.handle.mempool_status()
        }
    }

    /// Fetches the latest mempool status snapshot without blocking the async runtime.
    pub async fn mempool_status_async(&self) -> ChainResult<MempoolStatus> {
        self.blocking_call(|handle| handle.mempool_status()).await
    }

    /// Fetches the latest consensus status snapshot.
    pub fn consensus_status(&self) -> ChainResult<ConsensusStatus> {
        if Handle::try_current().is_ok() {
            task::block_in_place(|| self.handle.consensus_status())
        } else {
            self.handle.consensus_status()
        }
    }

    /// Fetches the latest consensus status snapshot without blocking the async runtime.
    pub async fn consensus_status_async(&self) -> ChainResult<ConsensusStatus> {
        self.blocking_call(|handle| handle.consensus_status()).await
    }

    /// Fetches rollout status information for the runtime.
    pub fn rollout_status(&self) -> RolloutStatus {
        if Handle::try_current().is_ok() {
            task::block_in_place(|| self.handle.rollout_status())
        } else {
            self.handle.rollout_status()
        }
    }

    /// Fetches rollout status information without blocking the async runtime.
    pub async fn rollout_status_async(&self) -> ChainResult<RolloutStatus> {
        self.blocking_call(|handle| Ok(handle.rollout_status()))
            .await
    }

    /// Fetches the latest telemetry snapshot from the node runtime.
    pub fn telemetry_snapshot(&self) -> ChainResult<NodeTelemetrySnapshot> {
        if Handle::try_current().is_ok() {
            task::block_in_place(|| self.handle.telemetry_snapshot())
        } else {
            self.handle.telemetry_snapshot()
        }
    }

    /// Fetches the latest telemetry snapshot without blocking the async runtime.
    pub async fn telemetry_snapshot_async(&self) -> ChainResult<NodeTelemetrySnapshot> {
        self.blocking_call(|handle| handle.telemetry_snapshot())
            .await
    }

    /// Returns a cloned [`NodeHandle`] for internal consumers.
    pub(crate) fn node_handle(&self) -> NodeHandle {
        self.handle.clone()
    }

    /// Stops the runtime, awaiting task completion.
    pub async fn shutdown(self) -> ChainResult<()> {
        self.handle.stop().await?;
        self.join
            .await
            .map_err(|err| ChainError::Config(format!("node runtime join error: {err}")))
    }
}

/// Start a node runtime using the wallet configuration surface.
pub async fn start_node(config: NodeConfig) -> ChainResult<WalletNodeRuntime> {
    let (handle, join) = NodeInner::start(config.clone()).await?;
    Ok(WalletNodeRuntime {
        config,
        handle,
        join,
    })
}

/// Stop a running node runtime previously started via [`start_node`].
pub async fn stop_node(runtime: WalletNodeRuntime) -> ChainResult<()> {
    runtime.shutdown().await
}
