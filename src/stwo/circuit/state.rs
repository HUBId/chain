//! State transition STARK constraints blueprint implementation.

use std::collections::HashMap;

use crate::ledger::compute_merkle_root;
use crate::reputation::{ReputationWeights, Tier, current_timestamp};
use crate::stwo::air::{AirColumn, AirConstraint, AirDefinition, AirExpression, ConstraintDomain};
use crate::stwo::params::StarkParameters;
use crate::types::{Account, SignedTransaction, Stake};
use serde_json::to_vec;

use super::{
    CircuitError, ExecutionTrace, StarkCircuit, TraceSegment, string_to_field,
    transaction::TransactionCircuit, transaction::TransactionWitness,
};

/// Witness for the state transition circuit.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct StateWitness {
    pub prev_state_root: String,
    pub new_state_root: String,
    pub transactions: Vec<SignedTransaction>,
    pub accounts_before: Vec<Account>,
    pub accounts_after: Vec<Account>,
    pub required_tier: Tier,
    pub reputation_weights: ReputationWeights,
}

/// Circuit verifying batched state transitions.
#[derive(Debug)]
pub struct StateCircuit {
    pub witness: StateWitness,
}

impl StateCircuit {
    pub fn new(witness: StateWitness) -> Self {
        Self { witness }
    }

    fn sort_accounts(accounts: &mut Vec<Account>) {
        accounts.sort_by(|a, b| a.address.cmp(&b.address));
    }

    fn compute_root(accounts: &mut Vec<Account>) -> String {
        Self::sort_accounts(accounts);
        let mut leaves = accounts
            .iter()
            .map(|account| {
                let bytes = serde_json::to_vec(account).expect("serialize account");
                <[u8; 32]>::from(stwo::core::vcs::blake2_hash::Blake2sHasher::hash(
                    bytes.as_slice(),
                ))
            })
            .collect::<Vec<_>>();
        hex::encode(compute_merkle_root(&mut leaves))
    }

    fn check_roots(&self) -> Result<(), CircuitError> {
        let mut before = self.witness.accounts_before.clone();
        let mut after = self.witness.accounts_after.clone();
        let prev_root = Self::compute_root(&mut before);
        if prev_root != self.witness.prev_state_root {
            return Err(CircuitError::ConstraintViolation(
                "previous state root mismatch".into(),
            ));
        }
        let new_root = Self::compute_root(&mut after);
        if new_root != self.witness.new_state_root {
            return Err(CircuitError::ConstraintViolation(
                "new state root mismatch".into(),
            ));
        }
        Ok(())
    }

    fn replay_transactions(&self) -> Result<Vec<Account>, CircuitError> {
        let mut state: HashMap<_, _> = self
            .witness
            .accounts_before
            .iter()
            .cloned()
            .map(|account| (account.address.clone(), account))
            .collect();

        for tx in &self.witness.transactions {
            let sender = state.get(&tx.payload.from).cloned().ok_or_else(|| {
                CircuitError::ConstraintViolation("sender account missing".into())
            })?;
            let receiver = state.get(&tx.payload.to).cloned();
            let witness = TransactionWitness {
                signed_tx: tx.clone(),
                sender_account: sender.clone(),
                receiver_account: receiver.clone(),
                required_tier: self.witness.required_tier.clone(),
                reputation_weights: self.witness.reputation_weights.clone(),
            };
            TransactionCircuit::new(witness).evaluate_constraints()?;

            let total = tx
                .payload
                .amount
                .checked_add(tx.payload.fee as u128)
                .ok_or_else(|| CircuitError::ConstraintViolation("amount overflow".into()))?;
            let sender_mut = state
                .get_mut(&tx.payload.from)
                .ok_or_else(|| CircuitError::ConstraintViolation("sender missing".into()))?;
            if sender_mut.balance < total {
                return Err(CircuitError::ConstraintViolation(
                    "insufficient balance during state replay".into(),
                ));
            }
            sender_mut.balance -= total;
            sender_mut.nonce += 1;

            let recipient = state
                .entry(tx.payload.to.clone())
                .or_insert_with(|| Account::new(tx.payload.to.clone(), 0, Stake::default()));
            recipient.balance = recipient.balance.saturating_add(tx.payload.amount);
            recipient
                .reputation
                .recompute_score(&self.witness.reputation_weights, current_timestamp());
        }

        let mut accounts: Vec<Account> = state.into_values().collect();
        Self::sort_accounts(&mut accounts);
        Ok(accounts)
    }

    fn check_resulting_accounts(&self) -> Result<(), CircuitError> {
        let expected = self.replay_transactions()?;
        let mut provided = self.witness.accounts_after.clone();
        Self::sort_accounts(&mut provided);
        let expected_serialized = expected
            .iter()
            .map(|account| {
                to_vec(account).map_err(|err| {
                    CircuitError::InvalidWitness(format!(
                        "failed to serialize expected account: {err}"
                    ))
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        let provided_serialized = provided
            .iter()
            .map(|account| {
                to_vec(account).map_err(|err| {
                    CircuitError::InvalidWitness(format!(
                        "failed to serialize provided account: {err}"
                    ))
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        if expected_serialized != provided_serialized {
            return Err(CircuitError::ConstraintViolation(
                "resulting account set does not match provided witness".into(),
            ));
        }
        Ok(())
    }
}

impl StarkCircuit for StateCircuit {
    fn name(&self) -> &'static str {
        "state"
    }

    fn evaluate_constraints(&self) -> Result<(), CircuitError> {
        self.check_roots()?;
        self.check_resulting_accounts()?;
        Ok(())
    }

    fn generate_trace(&self, parameters: &StarkParameters) -> Result<ExecutionTrace, CircuitError> {
        let mut state: HashMap<_, _> = self
            .witness
            .accounts_before
            .iter()
            .cloned()
            .map(|account| (account.address.clone(), account))
            .collect();

        let mut transition_rows = Vec::new();
        for tx in &self.witness.transactions {
            let sender = state.get(&tx.payload.from).cloned().ok_or_else(|| {
                CircuitError::ConstraintViolation("sender account missing".into())
            })?;
            let receiver_before = state.get(&tx.payload.to).cloned();
            let total = tx
                .payload
                .amount
                .checked_add(tx.payload.fee as u128)
                .ok_or_else(|| CircuitError::ConstraintViolation("amount overflow".into()))?;
            let sender_after_balance = sender
                .balance
                .checked_sub(total)
                .ok_or_else(|| CircuitError::ConstraintViolation("insufficient balance".into()))?;

            let sender_mut = state
                .get_mut(&tx.payload.from)
                .ok_or_else(|| CircuitError::ConstraintViolation("sender missing".into()))?;
            sender_mut.balance = sender_after_balance;
            sender_mut.nonce = sender.nonce + 1;

            let recipient_entry = state
                .entry(tx.payload.to.clone())
                .or_insert_with(|| Account::new(tx.payload.to.clone(), 0, Stake::default()));
            let receiver_balance_before = receiver_before
                .as_ref()
                .map(|account| account.balance)
                .unwrap_or(0);
            let receiver_balance_after = recipient_entry.balance.saturating_add(tx.payload.amount);
            recipient_entry.balance = receiver_balance_after;
            recipient_entry
                .reputation
                .recompute_score(&self.witness.reputation_weights, current_timestamp());

            let row = vec![
                string_to_field(parameters, &tx.payload.from),
                string_to_field(parameters, &tx.payload.to),
                parameters.element_from_u128(tx.payload.amount),
                parameters.element_from_u64(tx.payload.fee as u64),
                parameters.element_from_u128(sender.balance),
                parameters.element_from_u128(sender_after_balance),
                parameters.element_from_u128(receiver_balance_before),
                parameters.element_from_u128(receiver_balance_after),
                parameters.element_from_u64(sender.nonce),
                parameters.element_from_u64(sender.nonce + 1),
            ];
            transition_rows.push(row);
        }

        let transitions_segment = TraceSegment::new(
            "transitions",
            vec![
                "sender".to_string(),
                "receiver".to_string(),
                "amount".to_string(),
                "fee".to_string(),
                "sender_balance_before".to_string(),
                "sender_balance_after".to_string(),
                "receiver_balance_before".to_string(),
                "receiver_balance_after".to_string(),
                "nonce_before".to_string(),
                "nonce_after".to_string(),
            ],
            transition_rows,
        )?;

        let mut accounts_before = self.witness.accounts_before.clone();
        let mut accounts_after = self.witness.accounts_after.clone();
        let computed_prev_root = Self::compute_root(&mut accounts_before);
        let computed_new_root = Self::compute_root(&mut accounts_after);
        let summary_row = vec![
            string_to_field(parameters, &self.witness.prev_state_root),
            string_to_field(parameters, &computed_prev_root),
            string_to_field(parameters, &self.witness.new_state_root),
            string_to_field(parameters, &computed_new_root),
            parameters.element_from_u64(self.witness.transactions.len() as u64),
        ];
        let summary_segment = TraceSegment::new(
            "roots",
            vec![
                "prev_root_witness".to_string(),
                "prev_root_computed".to_string(),
                "new_root_witness".to_string(),
                "new_root_computed".to_string(),
                "tx_count".to_string(),
            ],
            vec![summary_row],
        )?;

        ExecutionTrace::from_segments(vec![transitions_segment, summary_segment])
    }

    fn define_air(
        &self,
        parameters: &StarkParameters,
        trace: &ExecutionTrace,
    ) -> Result<AirDefinition, CircuitError> {
        let transitions_segment = "transitions";
        let sender_before = AirColumn::new(transitions_segment, "sender_balance_before");
        let sender_after = AirColumn::new(transitions_segment, "sender_balance_after");
        let amount = AirColumn::new(transitions_segment, "amount");
        let fee = AirColumn::new(transitions_segment, "fee");
        let receiver_before = AirColumn::new(transitions_segment, "receiver_balance_before");
        let receiver_after = AirColumn::new(transitions_segment, "receiver_balance_after");
        let nonce_before = AirColumn::new(transitions_segment, "nonce_before");
        let nonce_after = AirColumn::new(transitions_segment, "nonce_after");

        let roots_segment = "roots";
        let prev_root_witness = AirColumn::new(roots_segment, "prev_root_witness");
        let prev_root_computed = AirColumn::new(roots_segment, "prev_root_computed");
        let new_root_witness = AirColumn::new(roots_segment, "new_root_witness");
        let new_root_computed = AirColumn::new(roots_segment, "new_root_computed");
        let tx_count = AirColumn::new(roots_segment, "tx_count");

        let one = parameters.element_from_u64(1);
        let tx_len = parameters.element_from_u64(self.witness.transactions.len() as u64);

        let mut constraints = vec![
            AirConstraint::new(
                "state_sender_balance",
                transitions_segment,
                ConstraintDomain::AllRows,
                AirExpression::difference(
                    sender_before.expr(),
                    AirExpression::sum(vec![sender_after.expr(), amount.expr(), fee.expr()]),
                ),
            ),
            AirConstraint::new(
                "state_receiver_balance",
                transitions_segment,
                ConstraintDomain::AllRows,
                AirExpression::difference(
                    receiver_after.expr(),
                    AirExpression::sum(vec![receiver_before.expr(), amount.expr()]),
                ),
            ),
            AirConstraint::new(
                "state_nonce_increment",
                transitions_segment,
                ConstraintDomain::AllRows,
                AirExpression::difference(
                    AirExpression::difference(nonce_after.expr(), nonce_before.expr()),
                    AirExpression::constant(one.clone()),
                ),
            ),
            AirConstraint::new(
                "state_prev_root_matches",
                roots_segment,
                ConstraintDomain::AllRows,
                AirExpression::difference(prev_root_witness.expr(), prev_root_computed.expr()),
            ),
            AirConstraint::new(
                "state_new_root_matches",
                roots_segment,
                ConstraintDomain::AllRows,
                AirExpression::difference(new_root_witness.expr(), new_root_computed.expr()),
            ),
            AirConstraint::new(
                "state_tx_count",
                roots_segment,
                ConstraintDomain::AllRows,
                AirExpression::difference(tx_count.expr(), AirExpression::constant(tx_len)),
            ),
        ];

        if trace
            .segments
            .iter()
            .find(|segment| segment.name == transitions_segment)
            .map(|segment| segment.rows.is_empty())
            .unwrap_or(false)
        {
            constraints.retain(|constraint| constraint.segment != transitions_segment);
        }

        Ok(AirDefinition::new(constraints))
    }
}
