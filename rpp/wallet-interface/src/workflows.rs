use serde::{Deserialize, Serialize};

use crate::{SendPreview, Tier, TransactionProofBundle, UtxoRecord};

/// Reputation status shared with runtime consumers.
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{AssetType, TransactionProofBundle, UtxoOutpoint, UtxoRecord};

    fn sample_workflow() -> TransactionWorkflow {
        TransactionWorkflow {
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
        }
    }

    #[test]
    fn transaction_workflow_round_trip() {
        let workflow = sample_workflow();
        let encoded = serde_json::to_string(&workflow).expect("serialize workflow");
        let decoded: TransactionWorkflow =
            serde_json::from_str(&encoded).expect("deserialize workflow");
        assert_eq!(decoded, workflow);
    }

    #[test]
    fn reputation_status_round_trip() {
        let status = ReputationStatus {
            tier: Tier::Tl2,
            score: 1.5,
            timetoke_hours: 12,
            zsi_validated: false,
        };
        let encoded = serde_json::to_string(&status).expect("serialize status");
        let decoded: ReputationStatus = serde_json::from_str(&encoded).expect("deserialize status");
        assert_eq!(decoded, status);
    }
}
