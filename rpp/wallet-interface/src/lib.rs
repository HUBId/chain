//! Wallet/runtime interface contracts.
//!
//! This crate contains the serialization friendly payloads that are exchanged
//! between the wallet and the runtime (or supporting tooling).  By isolating
//! the types in a stand-alone crate we can ensure the interface keeps
//! compiling without depending on the full wallet implementation.

#![deny(missing_docs)]
#![deny(unsafe_code)]
#![allow(ambiguous_glob_reexports)]

/// Lightweight client for interacting with wallet-adjacent node APIs.
pub mod node_client;
pub mod rpc;
/// Runtime configuration schemas exposed to wallets.
pub mod runtime_config;
/// Runtime telemetry hooks and helpers.
pub mod runtime_telemetry;
/// Wallet RBAC store, context, and helper utilities shared between the runtime and CLI/tests.
pub mod runtime_wallet;
/// Telemetry payloads reported by wallet components.
pub mod telemetry;
/// Workflow definitions shared between the wallet and runtime.
pub mod workflows;

pub use node_client::*;
pub use rpc::*;
pub use runtime_config::*;
pub use runtime_telemetry::*;
pub use runtime_wallet::*;
pub use telemetry::*;
pub use workflows::*;

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Convenient result alias used throughout the crate.
pub type Result<T> = std::result::Result<T, WalletInterfaceError>;

/// Common error type returned by helpers in this crate.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum WalletInterfaceError {
    /// A workflow failed validation.
    #[error("invalid workflow: {0}")]
    InvalidWorkflow(String),
}

/// Address newtype used by the interface.
pub type Address = String;

/// Asset types the wallet can transfer.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum AssetType {
    /// The native RPP asset.
    Native,
    /// A custom asset identified by a ticker or id.
    Custom(String),
}

/// Unique identifier for a UTXO.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct UtxoOutpoint {
    /// Hash of the transaction that created the UTXO.
    pub tx_id: String,
    /// Output index inside the transaction.
    pub output_index: u32,
}

/// A record describing a single UTXO.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct UtxoRecord {
    /// Identifier of the UTXO.
    pub outpoint: UtxoOutpoint,
    /// Address allowed to spend the UTXO.
    pub owner: Address,
    /// Asset stored in the UTXO.
    pub asset: AssetType,
    /// Amount contained in the UTXO.
    pub value: u128,
    /// Optional memo preserved for UI consumption.
    pub memo: Option<String>,
}

/// Send tab preview shared with clients.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SendPreview {
    /// Address the funds are debited from.
    pub from: Address,
    /// Address receiving the funds.
    pub to: Address,
    /// Amount to transfer.
    pub amount: u128,
    /// Fee charged for the transfer.
    pub fee: u64,
    /// Optional memo text.
    pub memo: Option<String>,
    /// Account nonce used for replay protection.
    pub nonce: u64,
    /// Balance before the transfer.
    pub balance_before: u128,
    /// Balance after the transfer.
    pub balance_after: u128,
}

impl SendPreview {
    /// Total value debited from the sender (amount + fee).
    pub fn total(&self) -> u128 {
        self.amount + u128::from(self.fee)
    }
}

/// Bundle tying an opaque transaction payload with its proof.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct TransactionProofBundle {
    /// Transaction identifier used for logging and deduplication.
    pub transaction_id: String,
    /// Proof bytes associated with the transaction.
    pub proof: Vec<u8>,
}

/// Reputation tier of a validator.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum Tier {
    /// Tier level 0.
    Tl0,
    /// Tier level 1.
    Tl1,
    /// Tier level 2.
    Tl2,
    /// Tier level 3.
    Tl3,
    /// Tier level 4.
    Tl4,
    /// Tier level 5.
    Tl5,
}

impl TransactionWorkflow {
    /// Perform basic validation of the workflow.
    pub fn validate(&self) -> Result<()> {
        let expected_total = self
            .total_output_value
            .checked_add(u128::from(self.fee))
            .ok_or_else(|| WalletInterfaceError::InvalidWorkflow("value overflow".into()))?;
        if self.total_input_value < expected_total {
            return Err(WalletInterfaceError::InvalidWorkflow(
                "inputs must cover outputs and fees".into(),
            ));
        }
        Ok(())
    }
}
