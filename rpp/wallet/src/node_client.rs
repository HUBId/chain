use std::fmt;

use anyhow::Error as AnyError;
use rpp::runtime::config::QueueWeightsConfig;
use rpp::runtime::node::MempoolStatus;
use thiserror::Error;

use crate::engine::DraftTransaction;

/// Lightweight summary describing the current chain head.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ChainHead {
    pub height: u64,
    pub hash: [u8; 32],
}

impl ChainHead {
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
#[derive(Debug, Error)]
pub enum NodeClientError {
    /// Transport-level failures such as networking errors or RPC timeouts.
    #[error("transport error: {0}")]
    Transport(#[from] AnyError),
    /// The node rejected the transaction for application-level reasons.
    #[error("transaction rejected: {reason}")]
    Rejected { reason: String },
    /// Local policy prevented the request from being accepted.
    #[error("policy violation: {reason}")]
    Policy { reason: String },
}

impl NodeClientError {
    pub fn transport(error: impl Into<AnyError>) -> Self {
        Self::Transport(error.into())
    }

    pub fn rejected(reason: impl Into<String>) -> Self {
        Self::Rejected {
            reason: reason.into(),
        }
    }

    pub fn policy(reason: impl Into<String>) -> Self {
        Self::Policy {
            reason: reason.into(),
        }
    }
}

pub type NodeClientResult<T> = Result<T, NodeClientError>;

/// Abstraction over the node RPC surface consumed by the wallet.
pub trait NodeClient: Send + Sync {
    fn submit_tx(&self, draft: &DraftTransaction) -> NodeClientResult<()>;
    fn estimate_fee(&self, confirmation_target: u16) -> NodeClientResult<u64>;
    fn chain_head(&self) -> NodeClientResult<ChainHead>;
    fn mempool_status(&self) -> NodeClientResult<MempoolStatus>;
}

/// Simple in-memory client used in tests and local development harnesses.
#[derive(Clone, Debug)]
pub struct StubNodeClient {
    fee_rate: u64,
    head: ChainHead,
    mempool: MempoolStatus,
}

impl StubNodeClient {
    pub fn new(fee_rate: u64, head: ChainHead, mempool: MempoolStatus) -> Self {
        Self {
            fee_rate,
            head,
            mempool,
        }
    }

    pub fn with_fee_rate(mut self, fee_rate: u64) -> Self {
        self.fee_rate = fee_rate;
        self
    }

    pub fn with_chain_head(mut self, head: ChainHead) -> Self {
        self.head = head;
        self
    }

    pub fn with_mempool(mut self, mempool: MempoolStatus) -> Self {
        self.mempool = mempool;
        self
    }
}

impl Default for StubNodeClient {
    fn default() -> Self {
        Self {
            fee_rate: 1,
            head: default_chain_head(),
            mempool: default_mempool_status(),
        }
    }
}

impl NodeClient for StubNodeClient {
    fn submit_tx(&self, draft: &DraftTransaction) -> NodeClientResult<()> {
        if draft.inputs.is_empty() {
            return Err(NodeClientError::policy("draft missing inputs"));
        }
        if draft.outputs.is_empty() {
            return Err(NodeClientError::policy("draft missing outputs"));
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
}

fn default_chain_head() -> ChainHead {
    #[cfg(feature = "vendor_electrs")]
    {
        use crate::vendor::electrs::rpp_ledger::bitcoin::{blockdata::constants, Network};
        let genesis = constants::genesis_block(Network::Regtest);
        let hash = genesis.header.block_hash();
        return ChainHead::new(0, *hash.as_bytes());
    }

    ChainHead::new(0, [0u8; 32])
}

fn default_mempool_status() -> MempoolStatus {
    MempoolStatus {
        transactions: Vec::new(),
        identities: Vec::new(),
        votes: Vec::new(),
        uptime_proofs: Vec::new(),
        queue_weights: QueueWeightsConfig::default(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::anyhow;

    use crate::db::UtxoOutpoint;
    use crate::engine::{DraftInput, DraftOutput, SpendModel};

    fn make_draft() -> DraftTransaction {
        DraftTransaction {
            inputs: vec![DraftInput {
                outpoint: UtxoOutpoint::new([1u8; 32], 0),
                value: 1,
                confirmations: 1,
            }],
            outputs: vec![DraftOutput::new("addr", 1, false)],
            fee_rate: 1,
            fee: 0,
            spend_model: SpendModel::Exact { amount: 1 },
        }
    }

    #[test]
    fn transport_error_display() {
        let err = NodeClientError::transport(anyhow!("boom"));
        assert!(matches!(err, NodeClientError::Transport(_)));
        assert_eq!(format!("{err}"), "transport error: boom");
    }

    #[test]
    fn stub_submit_tx_rejects_missing_inputs() {
        let client = StubNodeClient::default();
        let mut draft = make_draft();
        draft.inputs.clear();
        let err = client
            .submit_tx(&draft)
            .expect_err("missing input should fail");
        assert!(matches!(err, NodeClientError::Policy { .. }));
    }

    #[test]
    fn stub_reports_chain_head_and_fee() {
        let client = StubNodeClient::default().with_fee_rate(42);
        let draft = make_draft();
        assert!(client.submit_tx(&draft).is_ok());
        assert_eq!(client.estimate_fee(1).unwrap(), 42);
        let head = client.chain_head().unwrap();
        assert_eq!(head.height, 0);
        #[cfg(feature = "vendor_electrs")]
        {
            use crate::vendor::electrs::rpp_ledger::bitcoin::{blockdata::constants, Network};
            let genesis = constants::genesis_block(Network::Regtest);
            assert_eq!(&head.hash, genesis.header.block_hash().as_bytes());
        }
        let mempool = client.mempool_status().unwrap();
        assert!(mempool.transactions.is_empty());
        assert_eq!(mempool.queue_weights, QueueWeightsConfig::default());
    }

    #[test]
    fn stub_rejects_zero_confirmation_target() {
        let client = StubNodeClient::default();
        let err = client
            .estimate_fee(0)
            .expect_err("zero confirmation target must fail");
        assert!(matches!(err, NodeClientError::Policy { .. }));
    }
}
