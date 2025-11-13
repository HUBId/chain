use std::cmp::Ordering;

use super::{
    utxo_sel::{SelectionMetadata, SelectionResult},
    DraftInput, DraftOutput, DraftTransaction, SpendModel,
};

#[derive(Clone, Debug)]
pub struct TransactionBuilder {
    dust_limit: u128,
    max_change_outputs: u32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BuildPlan {
    pub fee: u128,
    pub change_values: Vec<u128>,
    pub metadata: BuildMetadata,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BuildMetadata {
    pub selection: Option<SelectionMetadata>,
    pub change_outputs: usize,
    pub change_folded_into_fee: bool,
    pub estimated_vbytes: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BuiltTransaction {
    pub transaction: DraftTransaction,
    pub metadata: BuildMetadata,
}

impl TransactionBuilder {
    pub fn new(dust_limit: u128, max_change_outputs: u32) -> Self {
        Self {
            dust_limit,
            max_change_outputs,
        }
    }

    pub fn dust_limit(&self) -> u128 {
        self.dust_limit
    }

    pub fn max_change_outputs(&self) -> u32 {
        self.max_change_outputs
    }

    pub fn estimate_fee(&self, inputs: usize, outputs: usize, fee_rate: u64) -> u128 {
        let vbytes = self.estimate_vbytes(inputs, outputs);
        (fee_rate as u128) * (vbytes as u128)
    }

    pub fn plan(
        &self,
        selection: Option<&SelectionResult>,
        outputs: &[DraftOutput],
        fee_rate: u64,
        spend_model: &SpendModel,
    ) -> Result<BuildPlan, BuilderError> {
        match spend_model {
            SpendModel::Exact { .. } | SpendModel::Sweep => {
                let selection = selection.ok_or(BuilderError::MissingSelection)?;
                self.plan_utxo(selection, outputs, fee_rate)
            }
            SpendModel::Account { .. } => self.plan_account(outputs),
        }
    }

    pub fn finalize(
        &self,
        selection: Option<SelectionResult>,
        mut outputs: Vec<DraftOutput>,
        fee_rate: u64,
        fee: u128,
        spend_model: SpendModel,
        metadata: BuildMetadata,
    ) -> Result<BuiltTransaction, BuilderError> {
        outputs.sort_by(|a, b| match (a.change, b.change) {
            (false, false) => a.address.cmp(&b.address),
            (true, true) => a.address.cmp(&b.address),
            (false, true) => Ordering::Less,
            (true, false) => Ordering::Greater,
        });

        let transaction = match spend_model {
            SpendModel::Exact { .. } | SpendModel::Sweep => {
                let selection = selection.ok_or(BuilderError::MissingSelection)?;
                let mut inputs = selection
                    .inputs
                    .into_iter()
                    .map(|candidate| DraftInput {
                        outpoint: candidate.record.outpoint,
                        value: candidate.record.value,
                        confirmations: candidate.confirmations,
                    })
                    .collect::<Vec<_>>();
                inputs.sort_by(|a, b| compare_outpoints(&a.outpoint, &b.outpoint));
                DraftTransaction {
                    inputs,
                    outputs,
                    fee_rate,
                    fee,
                    spend_model,
                }
            }
            SpendModel::Account { .. } => DraftTransaction {
                inputs: Vec::new(),
                outputs,
                fee_rate,
                fee,
                spend_model,
            },
        };

        Ok(BuiltTransaction {
            transaction,
            metadata,
        })
    }

    fn plan_utxo(
        &self,
        selection: &SelectionResult,
        outputs: &[DraftOutput],
        fee_rate: u64,
    ) -> Result<BuildPlan, BuilderError> {
        let total_in = selection.total_value();
        let outputs_value: u128 = outputs.iter().map(|output| output.value).sum();
        let mut change_values = Vec::new();
        let mut change_folded_into_fee = false;

        let base_fee = self.estimate_fee(selection.len(), outputs.len(), fee_rate);
        let mut required = outputs_value
            .checked_add(base_fee)
            .ok_or(BuilderError::FeeOverflow)?;
        if total_in < required {
            return Err(BuilderError::InsufficientFunds {
                required,
                available: total_in,
            });
        }

        let mut fee = base_fee;
        let mut estimated_outputs = outputs.len();
        let available_after_base = total_in - outputs_value - base_fee;
        if available_after_base > 0 {
            if self.max_change_outputs == 0 {
                fee = base_fee
                    .checked_add(available_after_base)
                    .ok_or(BuilderError::FeeOverflow)?;
                change_folded_into_fee = true;
            } else {
                let fee_with_change =
                    self.estimate_fee(selection.len(), outputs.len() + 1, fee_rate);
                required = outputs_value
                    .checked_add(fee_with_change)
                    .ok_or(BuilderError::FeeOverflow)?;
                if total_in < required {
                    return Err(BuilderError::InsufficientFunds {
                        required,
                        available: total_in,
                    });
                }
                let change_value = total_in - outputs_value - fee_with_change;
                if change_value < self.dust_limit {
                    fee = fee_with_change
                        .checked_add(change_value)
                        .ok_or(BuilderError::FeeOverflow)?;
                    change_folded_into_fee = true;
                } else {
                    change_values.push(change_value);
                    fee = fee_with_change;
                    estimated_outputs += 1;
                }
            }
        }

        let estimated_vbytes = self.estimate_vbytes(selection.len(), estimated_outputs);
        let metadata = BuildMetadata {
            selection: Some(selection.metadata.clone()),
            change_outputs: change_values.len(),
            change_folded_into_fee,
            estimated_vbytes,
        };

        Ok(BuildPlan {
            fee,
            change_values,
            metadata,
        })
    }

    fn plan_account(&self, outputs: &[DraftOutput]) -> Result<BuildPlan, BuilderError> {
        let metadata = BuildMetadata {
            selection: None,
            change_outputs: 0,
            change_folded_into_fee: false,
            estimated_vbytes: self.estimate_vbytes(0, outputs.len()),
        };
        Ok(BuildPlan {
            fee: 0,
            change_values: Vec::new(),
            metadata,
        })
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
    #[error("selection required for utxo spend")]
    MissingSelection,
}

fn compare_outpoints(a: &crate::db::UtxoOutpoint, b: &crate::db::UtxoOutpoint) -> Ordering {
    a.txid.cmp(&b.txid).then_with(|| a.index.cmp(&b.index))
}
