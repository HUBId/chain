use std::cmp::Ordering;

use crate::db::UtxoOutpoint;

use super::{CandidateUtxo, DraftInput, DraftOutput, DraftTransaction, SpendModel};

#[derive(Clone, Debug)]
pub struct TransactionBuilder {
    dust_limit: u128,
}

impl TransactionBuilder {
    pub fn new(dust_limit: u128) -> Self {
        Self { dust_limit }
    }

    pub fn dust_limit(&self) -> u128 {
        self.dust_limit
    }

    pub fn estimate_fee(&self, inputs: usize, outputs: usize, fee_rate: u64) -> u128 {
        let vbytes = self.estimate_vbytes(inputs, outputs);
        (fee_rate as u128) * (vbytes as u128)
    }

    pub fn assemble(
        &self,
        mut selection: Vec<CandidateUtxo>,
        mut outputs: Vec<DraftOutput>,
        fee_rate: u64,
        fee: u128,
        spend_model: SpendModel,
    ) -> DraftTransaction {
        selection.sort_by(|a, b| compare_outpoints(&a.record.outpoint, &b.record.outpoint));
        outputs.sort_by(|a, b| match (a.change, b.change) {
            (false, false) => a.address.cmp(&b.address),
            (true, true) => a.address.cmp(&b.address),
            (false, true) => Ordering::Less,
            (true, false) => Ordering::Greater,
        });
        let inputs = selection
            .into_iter()
            .map(|candidate| DraftInput {
                outpoint: candidate.record.outpoint,
                value: candidate.record.value,
                confirmations: candidate.confirmations,
            })
            .collect();
        DraftTransaction {
            inputs,
            outputs,
            fee_rate,
            fee,
            spend_model,
        }
    }

    fn estimate_vbytes(&self, inputs: usize, outputs: usize) -> u64 {
        let base: u64 = 10;
        base + (inputs as u64) * 148 + (outputs as u64) * 34
    }
}

#[derive(Debug, thiserror::Error)]
pub enum BuilderError {
    #[error("insufficient funds: required {required}, available {available}")]
    InsufficientFunds { required: u128, available: u128 },
    #[error("fee calculation overflowed")]
    FeeOverflow,
}

fn compare_outpoints(a: &UtxoOutpoint, b: &UtxoOutpoint) -> Ordering {
    a.txid
        .cmp(&b.txid)
        .then_with(|| a.index.cmp(&b.index))
}

