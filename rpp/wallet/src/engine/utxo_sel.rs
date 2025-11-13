use crate::db::UtxoRecord;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CandidateUtxo {
    pub record: UtxoRecord<'static>,
    pub confirmations: u32,
    pub pending: bool,
}

impl CandidateUtxo {
    pub fn new(record: UtxoRecord<'static>, confirmations: u32, pending: bool) -> Self {
        Self {
            record,
            confirmations,
            pending,
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum SelectionError {
    #[error("insufficient confirmed funds: required {required}, available {available}")]
    InsufficientFunds { required: u128, available: u128 },
}

pub fn select_coins(
    candidates: &[CandidateUtxo],
    amount: u128,
    min_confirmations: u32,
) -> Result<Vec<CandidateUtxo>, SelectionError> {
    let mut eligible: Vec<CandidateUtxo> = candidates
        .iter()
        .filter(|candidate| {
            !candidate.pending && candidate.confirmations >= min_confirmations
        })
        .cloned()
        .collect();
    eligible.sort_by(|a, b| {
        b.confirmations
            .cmp(&a.confirmations)
            .then_with(|| a.record.value.cmp(&b.record.value))
            .then_with(|| a.record.outpoint.txid.cmp(&b.record.outpoint.txid))
            .then_with(|| a.record.outpoint.index.cmp(&b.record.outpoint.index))
    });
    let mut selected = Vec::new();
    let mut total = 0u128;
    for candidate in eligible.into_iter() {
        total = total.saturating_add(candidate.record.value);
        selected.push(candidate);
        if total >= amount {
            return Ok(selected);
        }
    }
    let available = total;
    Err(SelectionError::InsufficientFunds {
        required: amount,
        available,
    })
}

