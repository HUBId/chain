use std::fmt;
use std::sync::Arc;

use anyhow::Error as AnyError;
use hex;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::runtime_config::MempoolStatus;

/// Lightweight summary describing the current chain head.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChainHead {
    /// Height of the chain head.
    pub height: u64,
    /// Hash of the chain head block.
    pub hash: [u8; 32],
}

impl ChainHead {
    /// Construct a new chain head summary.
    pub fn new(height: u64, hash: [u8; 32]) -> Self {
        Self { height, hash }
    }
}

impl fmt::Display for ChainHead {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "height={}, hash=0x{}",
            self.height,
            hex::encode(self.hash)
        )
    }
}

/// Unified error surfaced when communicating with the execution node.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NodeRejectionHint {
    /// The submitted fee rate was too low for the current mempool state.
    FeeRateTooLow {
        /// Minimum fee rate (sats/vB) the node would accept, if provided.
        required: Option<u64>,
    },
    /// The transaction already exists in the mempool.
    AlreadyKnown,
    /// The transaction conflicted with existing mempool contents.
    Conflicting,
    /// The mempool rejected the transaction because it was full.
    MempoolFull,
    /// Other rejection reason supplied by the node.
    Other(String),
}

impl fmt::Display for NodeRejectionHint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::FeeRateTooLow {
                required: Some(rate),
            } => write!(f, "fee rate too low (required {rate} sats/vB)"),
            Self::FeeRateTooLow { required: None } => write!(f, "fee rate too low"),
            Self::AlreadyKnown => write!(f, "transaction already in mempool"),
            Self::Conflicting => write!(f, "conflicts with existing mempool transaction"),
            Self::MempoolFull => write!(f, "mempool full"),
            Self::Other(reason) => write!(f, "{reason}"),
        }
    }
}

/// Local policy hint explaining a rejection reason before it reaches the node.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NodePolicyHint {
    /// The submission fee rate was below the minimum policy threshold.
    FeeRateTooLow {
        /// Minimum fee rate (sats/vB) enforced by local policy.
        minimum: u64,
    },
    /// A referenced input could not be found.
    MissingInputs,
    /// The transaction would create a dust output.
    DustOutput,
    /// The node rejected the transaction because it violated replacement policy.
    ReplacementRejected,
    /// Other policy rejection reason.
    Other(String),
}

impl fmt::Display for NodePolicyHint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::FeeRateTooLow { minimum } => {
                write!(f, "fee rate below minimum policy ({minimum} sats/vB)")
            }
            Self::MissingInputs => write!(f, "missing transaction inputs"),
            Self::DustOutput => write!(f, "would create dust output"),
            Self::ReplacementRejected => {
                write!(f, "replacement policy rejected transaction")
            }
            Self::Other(reason) => write!(f, "{reason}"),
        }
    }
}

/// Node statistics request that failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NodeStatsKind {
    /// Aggregate mempool status.
    MempoolInfo,
    /// Recent block fee information.
    RecentBlocks,
    /// Fee estimates for the confirmation targets.
    FeeEstimate,
}

impl fmt::Display for NodeStatsKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            NodeStatsKind::MempoolInfo => write!(f, "mempool info"),
            NodeStatsKind::RecentBlocks => write!(f, "recent blocks"),
            NodeStatsKind::FeeEstimate => write!(f, "fee estimates"),
        }
    }
}

/// Convenient result alias used across node client helpers.
pub type NodeClientResult<T> = Result<T, NodeClientError>;

/// Unified error surfaced when communicating with the execution node.
#[derive(Debug, Error, Clone)]
pub enum NodeClientError {
    /// Transport-level failures such as networking errors or RPC timeouts.
    #[error("node unavailable: {message}")]
    Network {
        /// User-facing message explaining the failure.
        message: String,
        /// Optional underlying error.
        #[source]
        source: Option<Arc<AnyError>>,
    },
    /// The node rejected the transaction for application-level reasons.
    #[error("transaction rejected by node")]
    Rejected {
        /// Reason supplied by the node.
        reason: String,
        /// Optional hint describing the rejection reason.
        hint: Option<NodeRejectionHint>,
    },
    /// Local policy prevented the request from being accepted.
    #[error("transaction rejected by node policy")]
    Policy {
        /// Reason describing the local policy failure.
        reason: String,
        /// Optional hint providing more context.
        hint: Option<NodePolicyHint>,
    },
    /// Aggregated statistics (fee estimates, mempool info) were unavailable.
    #[error("node statistics unavailable: {message}")]
    StatsUnavailable {
        /// Kind of statistics that could not be retrieved.
        kind: NodeStatsKind,
        /// Context message describing the failure.
        message: String,
    },
}

impl NodeClientError {
    /// Construct a network error with the default message.
    pub fn network(error: impl Into<AnyError>) -> Self {
        Self::Network {
            message: "execution node unreachable".to_string(),
            source: Some(Arc::new(error.into())),
        }
    }

    /// Construct a network error with a custom message and optional source.
    pub fn network_with_message(message: impl Into<String>, source: Option<AnyError>) -> Self {
        Self::Network {
            message: message.into(),
            source: source.map(Arc::new),
        }
    }

    /// Construct a rejection error with no hint.
    pub fn rejected(reason: impl Into<String>) -> Self {
        Self::Rejected {
            reason: reason.into(),
            hint: None,
        }
    }

    /// Construct a rejection error with a hint.
    pub fn rejected_with_hint(reason: impl Into<String>, hint: NodeRejectionHint) -> Self {
        Self::Rejected {
            reason: reason.into(),
            hint: Some(hint),
        }
    }

    /// Construct a policy error with no hint.
    pub fn policy(reason: impl Into<String>) -> Self {
        Self::Policy {
            reason: reason.into(),
            hint: None,
        }
    }

    /// Construct a policy error with a hint.
    pub fn policy_with_hint(reason: impl Into<String>, hint: NodePolicyHint) -> Self {
        Self::Policy {
            reason: reason.into(),
            hint: Some(hint),
        }
    }

    /// Construct a stats error for the provided kind.
    pub fn stats_unavailable(kind: NodeStatsKind) -> Self {
        Self::StatsUnavailable {
            kind,
            message: format!("node {kind} statistics unavailable"),
        }
    }

    /// Construct a stats error with a custom message.
    pub fn stats_unavailable_with_message(kind: NodeStatsKind, message: impl Into<String>) -> Self {
        Self::StatsUnavailable {
            kind,
            message: message.into(),
        }
    }

    /// Phase 2 telemetry code describing the error category.
    pub fn phase2_code(&self) -> &'static str {
        match self {
            NodeClientError::Network { .. } => "NODE_UNAVAILABLE",
            NodeClientError::Rejected { hint, .. } => {
                if Self::is_fee_too_low_rejection(hint.as_ref()) {
                    "FEE_TOO_LOW"
                } else {
                    "NODE_REJECTED"
                }
            }
            NodeClientError::Policy { hint, .. } => {
                if Self::is_fee_too_low_policy(hint.as_ref()) {
                    "FEE_TOO_LOW"
                } else {
                    "NODE_POLICY"
                }
            }
            NodeClientError::StatsUnavailable { .. } => "NODE_STATS_UNAVAILABLE",
        }
    }

    /// User-facing message for the error.
    pub fn user_message(&self) -> String {
        match self {
            NodeClientError::Network { message, .. } => message.clone(),
            NodeClientError::Rejected { hint, .. } => {
                if let Some(hint) = hint {
                    format!("node rejected transaction ({hint})")
                } else {
                    "node rejected transaction".to_string()
                }
            }
            NodeClientError::Policy { hint, .. } => {
                if let Some(hint) = hint {
                    format!("node policy rejected transaction ({hint})")
                } else {
                    "node policy rejected transaction".to_string()
                }
            }
            NodeClientError::StatsUnavailable { message, .. } => message.clone(),
        }
    }

    /// Suggested remediation hints for the user.
    pub fn hints(&self) -> Vec<String> {
        match self {
            NodeClientError::Network { .. } => {
                vec!["Verify the node connection and retry the request.".to_string()]
            }
            NodeClientError::Rejected { hint, .. } => {
                if let Some(NodeRejectionHint::FeeRateTooLow {
                    required: Some(rate),
                }) = hint
                {
                    vec![format!(
                        "Increase the fee rate to at least {rate} sats/vB and retry."
                    )]
                } else if let Some(NodeRejectionHint::FeeRateTooLow { required: None }) = hint {
                    vec!["Increase the fee rate before retrying.".to_string()]
                } else {
                    vec![
                        "Inspect node policy and retry after addressing the rejection reason."
                            .to_string(),
                    ]
                }
            }
            NodeClientError::Policy { hint, .. } => {
                if let Some(NodePolicyHint::FeeRateTooLow { minimum }) = hint {
                    vec![format!(
                        "Increase the fee rate above the node minimum of {minimum} sats/vB."
                    )]
                } else {
                    vec!["Adjust the draft to satisfy node policy and retry.".to_string()]
                }
            }
            NodeClientError::StatsUnavailable { kind, .. } => {
                vec![format!(
                    "Retry once the node has refreshed {kind} statistics."
                )]
            }
        }
    }

    fn is_fee_too_low_rejection(hint: Option<&NodeRejectionHint>) -> bool {
        match hint {
            Some(NodeRejectionHint::FeeRateTooLow { .. }) => true,
            Some(NodeRejectionHint::Other(reason)) => reason.to_lowercase().contains("fee"),
            _ => false,
        }
    }

    fn is_fee_too_low_policy(hint: Option<&NodePolicyHint>) -> bool {
        matches!(hint, Some(NodePolicyHint::FeeRateTooLow { .. }))
    }
}

/// Pending mempool statistics shared with wallet clients.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct MempoolInfo {
    /// Number of transactions currently tracked.
    pub tx_count: u64,
    /// Aggregate vsize limit for the mempool.
    pub vsize_limit: u64,
    /// Currently used virtual size.
    pub vsize_in_use: u64,
    /// Minimum observed fee rate.
    pub min_fee_rate: Option<u64>,
    /// Maximum observed fee rate.
    pub max_fee_rate: Option<u64>,
}

impl MempoolInfo {
    /// Ratio describing how full the mempool is.
    pub fn utilization(&self) -> f64 {
        if self.vsize_limit == 0 {
            return 0.0;
        }
        (self.vsize_in_use as f64 / self.vsize_limit as f64).min(1.0)
    }
}

/// Summary of recent block fee rates.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct BlockFeeSummary {
    /// Block height.
    pub height: u64,
    /// Median fee rate observed in the block.
    pub median_fee_rate: Option<u64>,
    /// Maximum fee rate observed in the block.
    pub max_fee_rate: Option<u64>,
}

/// Transaction submission payload shared with node clients.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TransactionSubmission {
    /// Inputs included in the transaction.
    pub inputs: Vec<SubmissionInput>,
    /// Outputs created by the transaction.
    pub outputs: Vec<SubmissionOutput>,
    /// Target fee rate in sats/vB.
    pub fee_rate: u64,
    /// Absolute fee paid by the transaction.
    pub fee: u128,
    /// Spend model used to create the draft.
    pub spend_model: SubmissionSpendModel,
}

impl TransactionSubmission {
    /// Compute the total value locked in the inputs.
    pub fn total_input_value(&self) -> u128 {
        self.inputs.iter().map(|input| input.value).sum()
    }

    /// Compute the total value assigned to the outputs.
    pub fn total_output_value(&self) -> u128 {
        self.outputs.iter().map(|output| output.value).sum()
    }
}

/// Draft input referencing a wallet-controlled outpoint.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SubmissionInput {
    /// Hash of the previous transaction.
    pub txid: [u8; 32],
    /// Output index inside the transaction.
    pub index: u32,
    /// Spendable value.
    pub value: u128,
    /// Confirmations observed for the input.
    pub confirmations: u32,
}

/// Draft output emitted by the transaction builder.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SubmissionOutput {
    /// Address that will receive the value.
    pub address: String,
    /// Output value.
    pub value: u128,
    /// Whether this is a change output.
    pub change: bool,
}

impl SubmissionOutput {
    /// Construct a new output helper.
    pub fn new(address: impl Into<String>, value: u128, change: bool) -> Self {
        Self {
            address: address.into(),
            value,
            change,
        }
    }
}

/// Model describing how much value should be spent in a draft transaction.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SubmissionSpendModel {
    /// Spend an exact amount.
    Exact {
        /// Amount to spend from available funds.
        amount: u128,
    },
    /// Sweep all available funds.
    Sweep,
    /// Spend a specific account debit.
    Account {
        /// Amount debited from the account balance.
        debit: u128,
    },
}

impl SubmissionSpendModel {
    /// Amount debited by the spend model if it is explicit.
    pub fn amount(&self) -> Option<u128> {
        match self {
            SubmissionSpendModel::Exact { amount } => Some(*amount),
            SubmissionSpendModel::Sweep => None,
            SubmissionSpendModel::Account { debit } => Some(*debit),
        }
    }
}

/// Abstraction over the node RPC surface consumed by the wallet.
pub trait NodeClient: Send + Sync {
    /// Submit a drafted transaction to the node for execution.
    fn submit_tx(&self, submission: &TransactionSubmission) -> NodeClientResult<()>;
    /// Submit raw transaction bytes directly to the node.
    fn submit_raw_tx(&self, tx: &[u8]) -> NodeClientResult<()>;
    /// Estimate the fee rate required for the requested confirmation target.
    fn estimate_fee(&self, confirmation_target: u16) -> NodeClientResult<u64>;
    /// Retrieve the current chain head summary.
    fn chain_head(&self) -> NodeClientResult<ChainHead>;
    /// Retrieve the current mempool status snapshot.
    fn mempool_status(&self) -> NodeClientResult<MempoolStatus>;
    /// Retrieve aggregated mempool fee statistics.
    fn mempool_info(&self) -> NodeClientResult<MempoolInfo>;
    /// Retrieve fee summaries for the most recent blocks.
    fn recent_blocks(&self, limit: usize) -> NodeClientResult<Vec<BlockFeeSummary>>;
}

/// Simple in-memory client used in tests and local development harnesses.
#[derive(Clone, Debug)]
pub struct StubNodeClient {
    fee_rate: u64,
    head: ChainHead,
    mempool: MempoolStatus,
    mempool_info: MempoolInfo,
    recent_blocks: Vec<BlockFeeSummary>,
}

impl StubNodeClient {
    /// Construct a new stub client with the provided parameters.
    pub fn new(fee_rate: u64, head: ChainHead, mempool: MempoolStatus) -> Self {
        Self {
            fee_rate,
            head,
            mempool,
            mempool_info: MempoolInfo::default(),
            recent_blocks: Vec::new(),
        }
    }

    /// Override the stub fee rate.
    pub fn with_fee_rate(mut self, fee_rate: u64) -> Self {
        self.fee_rate = fee_rate;
        self
    }

    /// Override the stub chain head.
    pub fn with_chain_head(mut self, head: ChainHead) -> Self {
        self.head = head;
        self
    }

    /// Override the stub mempool snapshot.
    pub fn with_mempool(mut self, mempool: MempoolStatus) -> Self {
        self.mempool = mempool;
        self
    }

    /// Override the stub mempool info snapshot.
    pub fn with_mempool_info(mut self, mempool_info: MempoolInfo) -> Self {
        self.mempool_info = mempool_info;
        self
    }

    /// Override the stub recent block summaries.
    pub fn with_recent_blocks(mut self, blocks: Vec<BlockFeeSummary>) -> Self {
        self.recent_blocks = blocks;
        self
    }
}

impl Default for StubNodeClient {
    fn default() -> Self {
        Self {
            fee_rate: 1,
            head: ChainHead::new(0, [0u8; 32]),
            mempool: MempoolStatus::default(),
            mempool_info: MempoolInfo {
                tx_count: 0,
                vsize_limit: 1_000_000,
                vsize_in_use: 0,
                min_fee_rate: Some(1),
                max_fee_rate: Some(5),
            },
            recent_blocks: Vec::new(),
        }
    }
}

impl NodeClient for StubNodeClient {
    fn submit_tx(&self, submission: &TransactionSubmission) -> NodeClientResult<()> {
        if submission.inputs.is_empty() {
            return Err(NodeClientError::policy("draft missing inputs"));
        }
        if submission.outputs.is_empty() {
            return Err(NodeClientError::policy("draft missing outputs"));
        }
        Ok(())
    }

    fn submit_raw_tx(&self, tx: &[u8]) -> NodeClientResult<()> {
        if tx.is_empty() {
            return Err(NodeClientError::policy("raw transaction payload empty"));
        }
        Ok(())
    }

    fn estimate_fee(&self, confirmation_target: u16) -> NodeClientResult<u64> {
        if confirmation_target == 0 {
            return Err(NodeClientError::policy(
                "confirmation target must be greater than zero",
            ));
        }
        Ok(self.fee_rate)
    }

    fn chain_head(&self) -> NodeClientResult<ChainHead> {
        Ok(self.head)
    }

    fn mempool_status(&self) -> NodeClientResult<MempoolStatus> {
        Ok(self.mempool.clone())
    }

    fn mempool_info(&self) -> NodeClientResult<MempoolInfo> {
        Ok(self.mempool_info.clone())
    }

    fn recent_blocks(&self, limit: usize) -> NodeClientResult<Vec<BlockFeeSummary>> {
        Ok(self.recent_blocks.iter().take(limit).cloned().collect())
    }
}

/// Result alias used by [`WalletService`].
pub type WalletServiceResult<T> = Result<T, WalletServiceError>;

/// Errors surfaced by wallet service adapters.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum WalletServiceError {
    /// The wallet rejected the node client attachment.
    #[error("wallet rejected node client attachment: {0}")]
    Attach(String),
}

impl WalletServiceError {
    /// Convenience helper to create an attachment error.
    pub fn attach(reason: impl Into<String>) -> Self {
        Self::Attach(reason.into())
    }
}

/// Trait implemented by wallet services exposed to the runtime.
pub trait WalletService: Send + Sync {
    /// Return the wallet address string used for logging and identification.
    fn address(&self) -> String;

    /// Attach a node client implementation to the wallet.
    fn attach_node_client(&self, _client: Arc<dyn NodeClient>) -> WalletServiceResult<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime_config::QueueWeightsConfig;

    fn make_submission() -> TransactionSubmission {
        TransactionSubmission {
            inputs: vec![SubmissionInput {
                txid: [1u8; 32],
                index: 0,
                value: 1,
                confirmations: 1,
            }],
            outputs: vec![SubmissionOutput::new("addr", 1, false)],
            fee_rate: 1,
            fee: 0,
            spend_model: SubmissionSpendModel::Exact { amount: 1 },
        }
    }

    #[test]
    fn network_error_reports_phase2_code() {
        let err = NodeClientError::network(anyhow::anyhow!("boom"));
        assert!(matches!(err, NodeClientError::Network { .. }));
        assert_eq!(err.phase2_code(), "NODE_UNAVAILABLE");
        assert_eq!(err.user_message(), "execution node unreachable");
        assert_eq!(
            err.hints(),
            vec!["Verify the node connection and retry the request.".to_string()]
        );
    }

    #[test]
    fn stub_submit_tx_rejects_missing_inputs() {
        let client = StubNodeClient::default();
        let mut submission = make_submission();
        submission.inputs.clear();
        let err = client
            .submit_tx(&submission)
            .expect_err("missing input should fail");
        assert!(matches!(err, NodeClientError::Policy { .. }));
    }

    #[test]
    fn stub_reports_chain_head_and_fee() {
        let client = StubNodeClient::default().with_fee_rate(42);
        let submission = make_submission();
        assert!(client.submit_tx(&submission).is_ok());
        assert_eq!(client.estimate_fee(1).unwrap(), 42);
        let head = client.chain_head().unwrap();
        assert_eq!(head.height, 0);
        let mempool = client.mempool_status().unwrap();
        assert!(mempool.transactions.is_empty());
        assert_eq!(mempool.queue_weights, QueueWeightsConfig::default());
        let mempool_info = client.mempool_info().unwrap();
        assert_eq!(mempool_info.vsize_limit, 1_000_000);
        assert_eq!(client.recent_blocks(4).unwrap().len(), 0);
    }

    #[test]
    fn stub_rejects_zero_confirmation_target() {
        let client = StubNodeClient::default();
        let err = client
            .estimate_fee(0)
            .expect_err("zero confirmation target must fail");
        assert!(matches!(err, NodeClientError::Policy { .. }));
    }

    #[test]
    fn rejection_hints_render_context() {
        let err = NodeClientError::rejected_with_hint(
            "replacement failed",
            NodeRejectionHint::FeeRateTooLow { required: Some(12) },
        );
        assert_eq!(err.phase2_code(), "FEE_TOO_LOW");
        assert_eq!(
            err.user_message(),
            "node rejected transaction (fee rate too low (required 12 sats/vB))"
        );
        assert_eq!(
            err.hints(),
            vec!["Increase the fee rate to at least 12 sats/vB and retry.".to_string()]
        );
    }

    #[test]
    fn policy_hints_render_context() {
        let err = NodeClientError::policy_with_hint(
            "policy limits",
            NodePolicyHint::FeeRateTooLow { minimum: 5 },
        );
        assert_eq!(err.phase2_code(), "FEE_TOO_LOW");
        assert_eq!(
            err.user_message(),
            "node policy rejected transaction (fee rate below minimum policy (5 sats/vB))"
        );
        assert_eq!(
            err.hints(),
            vec!["Increase the fee rate above the node minimum of 5 sats/vB.".to_string()]
        );
    }
}
