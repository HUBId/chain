//! Wallet/runtime interface contracts.
//!
//! This crate contains the serialization friendly payloads that are exchanged
//! between the wallet and the runtime (or supporting tooling).  By isolating
//! the types in a stand-alone crate we can ensure the interface keeps
//! compiling without depending on the full wallet implementation.

#![deny(missing_docs)]
#![deny(unsafe_code)]

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

/// Cached reputation status associated with a wallet.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct ReputationStatus {
    /// Current tier assigned by the reputation system.
    pub tier: Tier,
    /// Raw score contributing to the tier.
    pub score: f64,
    /// Hours until the next token emission.
    pub timetoke_hours: u64,
    /// Whether the ZSI attestation has been validated.
    pub zsi_validated: bool,
}

/// Policy constraints derived from the wallet's reputation.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct TransactionPolicy {
    /// Minimum tier required for the transfer.
    pub required_tier: Tier,
    /// Current reputation snapshot.
    pub status: ReputationStatus,
    /// Constraints derived from UTXO selection.
    pub utxo: UtxoPolicyStatus,
}

/// Snapshot of UTXO policy enforcement.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct UtxoPolicyStatus {
    /// Tier associated with the constraint.
    pub tier: Tier,
    /// Number of inputs selected for the transaction.
    pub input_count: usize,
    /// Maximum number of inputs allowed.
    pub max_inputs: usize,
    /// Total debit value being consumed.
    pub debit_value: u128,
    /// Maximum debit value allowed.
    pub max_debit_value: u128,
    /// Change returned to the sender.
    pub change_value: u128,
    /// Maximum allowable change value.
    pub max_change_value: u128,
}

/// Transaction workflow returned by the wallet and consumed by the runtime.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct TransactionWorkflow {
    /// UI preview of the transfer.
    pub preview: SendPreview,
    /// Proof bundle for the transaction.
    pub bundle: TransactionProofBundle,
    /// Inputs selected for the transaction.
    pub utxo_inputs: Vec<UtxoRecord>,
    /// Planned outputs before submitting to the runtime.
    pub planned_outputs: Vec<UtxoRecord>,
    /// Sender state after the transfer.
    pub sender_post_utxos: Vec<UtxoRecord>,
    /// Recipient state before the transfer.
    pub recipient_pre_utxos: Vec<UtxoRecord>,
    /// Recipient state after the transfer.
    pub recipient_post_utxos: Vec<UtxoRecord>,
    /// Total input value consumed.
    pub total_input_value: u128,
    /// Total output value produced.
    pub total_output_value: u128,
    /// Fee paid for the transaction.
    pub fee: u64,
    /// Policy summary for the transfer.
    pub policy: TransactionPolicy,
    /// State root used when building the workflow.
    pub state_root: String,
    /// UTXO commitment used for proofs.
    pub utxo_commitment: String,
    /// Hash of the transaction payload.
    pub tx_hash: String,
    /// Nonce included in the transaction payload.
    pub nonce: u64,
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transaction_workflow_round_trip() {
        let workflow = TransactionWorkflow {
            preview: SendPreview {
                from: "sender".into(),
                to: "recipient".into(),
                amount: 1_000,
                fee: 10,
                memo: Some("test".into()),
                nonce: 42,
                balance_before: 10_000,
                balance_after: 8_990,
            },
            bundle: TransactionProofBundle {
                transaction_id: "txid".into(),
                proof: vec![0, 1, 2, 3],
            },
            utxo_inputs: vec![UtxoRecord {
                outpoint: UtxoOutpoint {
                    tx_id: "prev".into(),
                    output_index: 0,
                },
                owner: "sender".into(),
                asset: AssetType::Native,
                value: 1_010,
                memo: None,
            }],
            planned_outputs: vec![],
            sender_post_utxos: vec![],
            recipient_pre_utxos: vec![],
            recipient_post_utxos: vec![],
            total_input_value: 1_010,
            total_output_value: 1_000,
            fee: 10,
            policy: TransactionPolicy {
                required_tier: Tier::Tl1,
                status: ReputationStatus {
                    tier: Tier::Tl1,
                    score: 0.75,
                    timetoke_hours: 24,
                    zsi_validated: true,
                },
                utxo: UtxoPolicyStatus {
                    tier: Tier::Tl1,
                    input_count: 1,
                    max_inputs: 4,
                    debit_value: 1_010,
                    max_debit_value: 10_000,
                    change_value: 0,
                    max_change_value: 10_000,
                },
            },
            state_root: "state".into(),
            utxo_commitment: "utxo".into(),
            tx_hash: "hash".into(),
            nonce: 42,
        };

        workflow.validate().expect("workflow should be valid");

        let encoded = serde_json::to_string(&workflow).expect("serialize workflow");
        let decoded: TransactionWorkflow =
            serde_json::from_str(&encoded).expect("deserialize workflow");
        assert_eq!(decoded, workflow);
    }
}
