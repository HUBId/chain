use std::cmp::Ordering;

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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SelectionStrategy {
    LargestFirst,
    BranchAndBoundLight,
    PreferConfirmed,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SelectionMetadata {
    pub strategy: SelectionStrategy,
    pub min_confirmations: u32,
    pub confirmed_inputs: usize,
    pub unconfirmed_inputs: usize,
    pub confirmed_value: u128,
    pub total_value: u128,
    pub used_unconfirmed: bool,
}

impl SelectionMetadata {
    fn new(
        strategy: SelectionStrategy,
        min_confirmations: u32,
        confirmed_inputs: usize,
        unconfirmed_inputs: usize,
        confirmed_value: u128,
        total_value: u128,
        used_unconfirmed: bool,
    ) -> Self {
        Self {
            strategy,
            min_confirmations,
            confirmed_inputs,
            unconfirmed_inputs,
            confirmed_value,
            total_value,
            used_unconfirmed,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SelectionResult {
    pub inputs: Vec<CandidateUtxo>,
    pub metadata: SelectionMetadata,
}

impl SelectionResult {
    pub fn total_value(&self) -> u128 {
        self.metadata.total_value
    }

    pub fn len(&self) -> usize {
        self.inputs.len()
    }
}

#[derive(Debug, thiserror::Error)]
pub enum SelectionError {
    #[error(
        "insufficient funds: required {required}, confirmed {confirmed_available}, total {total_available}"
    )]
    InsufficientFunds {
        required: u128,
        confirmed_available: u128,
        total_available: u128,
    },
}

#[derive(Clone, Debug)]
pub struct SelectionRequest<'a> {
    pub candidates: &'a [CandidateUtxo],
    pub amount: u128,
    pub min_confirmations: u32,
    pub strategy: SelectionStrategy,
}

pub fn select_coins(request: SelectionRequest<'_>) -> Result<SelectionResult, SelectionError> {
    let SelectionRequest {
        candidates,
        amount,
        min_confirmations,
        strategy,
    } = request;

    let mut available: Vec<CandidateUtxo> = candidates
        .iter()
        .filter(|candidate| !candidate.pending)
        .cloned()
        .collect();
    let mut confirmed: Vec<CandidateUtxo> = available
        .iter()
        .filter(|candidate| candidate.confirmations >= min_confirmations)
        .cloned()
        .collect();

    let confirmed_total: u128 = confirmed
        .iter()
        .map(|candidate| candidate.record.value)
        .sum();
    let total_available: u128 = available
        .iter()
        .map(|candidate| candidate.record.value)
        .sum();

    let mut used_unconfirmed = false;
    let result = match strategy {
        SelectionStrategy::PreferConfirmed => try_strategy(&mut confirmed, amount, strategy)
            .or_else(|_| {
                used_unconfirmed = true;
                try_strategy(&mut available, amount, strategy)
            }),
        _ => {
            let confirmed_result = try_strategy(&mut confirmed, amount, strategy);
            match confirmed_result {
                Ok(result) => Ok(result),
                Err(_) if confirmed_total >= amount => confirmed_result,
                Err(_) => {
                    used_unconfirmed = true;
                    try_strategy(&mut available, amount, strategy)
                }
            }
        }
    };

    match result {
        Ok(mut inputs) => {
            let confirmed_inputs = inputs
                .iter()
                .filter(|candidate| candidate.confirmations >= min_confirmations)
                .count();
            let total_value: u128 = inputs.iter().map(|candidate| candidate.record.value).sum();
            let confirmed_value: u128 = inputs
                .iter()
                .filter(|candidate| candidate.confirmations >= min_confirmations)
                .map(|candidate| candidate.record.value)
                .sum();
            inputs.sort_by(|a, b| compare_utxo(a, b));
            let metadata = SelectionMetadata::new(
                strategy,
                min_confirmations,
                confirmed_inputs,
                inputs.len().saturating_sub(confirmed_inputs),
                confirmed_value,
                total_value,
                used_unconfirmed,
            );
            Ok(SelectionResult { inputs, metadata })
        }
        Err(_) => Err(SelectionError::InsufficientFunds {
            required: amount,
            confirmed_available: confirmed_total,
            total_available,
        }),
    }
}

fn try_strategy(
    candidates: &mut Vec<CandidateUtxo>,
    amount: u128,
    strategy: SelectionStrategy,
) -> Result<Vec<CandidateUtxo>, ()> {
    match strategy {
        SelectionStrategy::LargestFirst | SelectionStrategy::PreferConfirmed => {
            candidates.sort_by(|a, b| compare_by_value(b, a));
            greedy_select(candidates.iter(), amount)
        }
        SelectionStrategy::BranchAndBoundLight => branch_and_bound_light(candidates, amount),
    }
}

fn greedy_select<'a>(
    iter: impl Iterator<Item = &'a CandidateUtxo>,
    amount: u128,
) -> Result<Vec<CandidateUtxo>, ()> {
    let mut total = 0u128;
    let mut selected = Vec::new();
    for candidate in iter {
        total = total.saturating_add(candidate.record.value);
        selected.push(candidate.clone());
        if total >= amount {
            return Ok(selected);
        }
    }
    Err(())
}

fn branch_and_bound_light(
    candidates: &mut Vec<CandidateUtxo>,
    amount: u128,
) -> Result<Vec<CandidateUtxo>, ()> {
    candidates.sort_by(|a, b| compare_by_value(b, a));
    if candidates.is_empty() {
        return Err(());
    }
    let mut best: Option<(u128, Vec<usize>)> = None;
    let mut prefix_sums = Vec::with_capacity(candidates.len());
    let mut running = 0u128;
    for candidate in candidates.iter() {
        running = running.saturating_add(candidate.record.value);
        prefix_sums.push(running);
    }
    dfs_branch_and_bound(
        0,
        0,
        amount,
        candidates,
        &prefix_sums,
        &mut Vec::new(),
        &mut best,
    );
    best.map(|(_, indices)| {
        indices
            .into_iter()
            .map(|idx| candidates[idx].clone())
            .collect()
    })
    .ok_or(())
}

fn dfs_branch_and_bound(
    index: usize,
    current: u128,
    target: u128,
    candidates: &[CandidateUtxo],
    prefix_sums: &[u128],
    stack: &mut Vec<usize>,
    best: &mut Option<(u128, Vec<usize>)>,
) {
    if current >= target {
        let should_replace = best
            .as_ref()
            .map(|(value, best_indices)| {
                current < *value || (current == *value && stack.len() < best_indices.len())
            })
            .unwrap_or(true);
        if should_replace {
            *best = Some((current, stack.clone()));
        }
        return;
    }
    if index >= candidates.len() {
        return;
    }
    if let Some((best_value, _)) = best {
        if current >= *best_value {
            return;
        }
    }
    let remaining = prefix_sums
        .last()
        .copied()
        .unwrap_or_default()
        .saturating_sub(if index == 0 {
            0
        } else {
            prefix_sums[index - 1]
        });
    if current + remaining < target {
        return;
    }
    // Explore including the current candidate.
    stack.push(index);
    dfs_branch_and_bound(
        index + 1,
        current.saturating_add(candidates[index].record.value),
        target,
        candidates,
        prefix_sums,
        stack,
        best,
    );
    stack.pop();
    // Explore excluding the current candidate.
    dfs_branch_and_bound(
        index + 1,
        current,
        target,
        candidates,
        prefix_sums,
        stack,
        best,
    );
}

fn compare_by_value(a: &CandidateUtxo, b: &CandidateUtxo) -> Ordering {
    a.record
        .value
        .cmp(&b.record.value)
        .then_with(|| compare_utxo(a, b))
}

fn compare_utxo(a: &CandidateUtxo, b: &CandidateUtxo) -> Ordering {
    a.confirmations
        .cmp(&b.confirmations)
        .reverse()
        .then_with(|| a.record.value.cmp(&b.record.value).reverse())
        .then_with(|| {
            a.record
                .outpoint
                .txid
                .cmp(&b.record.outpoint.txid)
                .then_with(|| a.record.outpoint.index.cmp(&b.record.outpoint.index))
        })
}
