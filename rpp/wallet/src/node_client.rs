pub use crate::interface_node_client::*;

use crate::engine::{DraftInput, DraftOutput, DraftTransaction, SpendModel};

/// Build a [`TransactionSubmission`] from an engine [`DraftTransaction`].
pub fn submission_from_draft(draft: &DraftTransaction) -> TransactionSubmission {
    TransactionSubmission {
        inputs: draft
            .inputs
            .iter()
            .map(|input| SubmissionInput {
                txid: input.outpoint.txid,
                index: input.outpoint.index,
                value: input.value,
                confirmations: input.confirmations,
            })
            .collect(),
        outputs: draft
            .outputs
            .iter()
            .map(|output| SubmissionOutput {
                address: output.address.clone(),
                value: output.value,
                change: output.change,
            })
            .collect(),
        fee_rate: draft.fee_rate,
        fee: draft.fee,
        spend_model: spend_model_from_engine(&draft.spend_model),
    }
}

fn spend_model_from_engine(model: &SpendModel) -> SubmissionSpendModel {
    match model {
        SpendModel::Exact { amount } => SubmissionSpendModel::Exact { amount: *amount },
        SpendModel::Sweep => SubmissionSpendModel::Sweep,
        SpendModel::Account { debit } => SubmissionSpendModel::Account { debit: *debit },
    }
}

impl From<&TransactionSubmission> for DraftTransaction {
    fn from(submission: &TransactionSubmission) -> Self {
        DraftTransaction {
            inputs: submission
                .inputs
                .iter()
                .map(|input| DraftInput {
                    outpoint: crate::db::UtxoOutpoint::new(input.txid, input.index),
                    value: input.value,
                    confirmations: input.confirmations,
                })
                .collect(),
            outputs: submission
                .outputs
                .iter()
                .map(|output| DraftOutput {
                    address: output.address.clone(),
                    value: output.value,
                    change: output.change,
                })
                .collect(),
            fee_rate: submission.fee_rate,
            fee: submission.fee,
            spend_model: match &submission.spend_model {
                SubmissionSpendModel::Exact { amount } => SpendModel::Exact { amount: *amount },
                SubmissionSpendModel::Sweep => SpendModel::Sweep,
                SubmissionSpendModel::Account { debit } => SpendModel::Account { debit: *debit },
            },
        }
    }
}
