pub mod proofs;
pub mod tabs;
pub mod wallet;
pub mod workflows;

use tokio::task::JoinHandle;

use crate::config::NodeConfig;
use crate::errors::{ChainError, ChainResult};
use crate::node::{NodeHandle, NodeInner};

pub use crate::types::UptimeProof;
pub use proofs::{ProofGenerator, TxProof};
pub use tabs::{HistoryEntry, HistoryStatus, NodeTabMetrics, ReceiveTabAddress, SendPreview};
pub use wallet::{ConsensusReceipt, Wallet, WalletAccountSummary};
pub use workflows::{
    IdentityFinalizationPhase, IdentityGenesisPhase, IdentityQuorumPhase, IdentityWorkflow,
    IdentityWorkflowState, ReputationStatus, TransactionPolicy, TransactionWorkflow,
    UptimeWorkflow, WalletWorkflows,
};

/// Handle returned by [`start_node`] encapsulating the running node task.
pub struct WalletNodeRuntime {
    handle: NodeHandle,
    join: JoinHandle<()>,
}

impl WalletNodeRuntime {
    pub fn handle(&self) -> &NodeHandle {
        &self.handle
    }
}

/// Start a node runtime using the wallet configuration surface.
pub async fn start_node(config: NodeConfig) -> ChainResult<WalletNodeRuntime> {
    let (handle, join) = NodeInner::start(config).await?;
    Ok(WalletNodeRuntime { handle, join })
}

/// Stop a running node runtime previously started via [`start_node`].
pub async fn stop_node(runtime: WalletNodeRuntime) -> ChainResult<()> {
    runtime.handle.stop().await?;
    runtime
        .join
        .await
        .map_err(|err| ChainError::Config(format!("node runtime join error: {err}")))
}
