//! Transaction STARK constraints blueprint implementation.

use crate::official::air::{
    AirColumn, AirConstraint, AirDefinition, AirExpression, ConstraintDomain,
};
use crate::official::params::{FieldElement, StarkParameters};
use crate::reputation::{ReputationWeights, Tier};
use crate::types::{Account, SignedTransaction};

use super::{string_to_field, CircuitError, ExecutionTrace, StarkCircuit, TraceSegment};

/// Witness data required to validate a transaction constraint system.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, PartialEq)]
pub struct TransactionWitness {
    pub signed_tx: SignedTransaction,
    pub sender_account: Account,
    pub receiver_account: Option<Account>,
    pub required_tier: Tier,
    pub reputation_weights: ReputationWeights,
}

impl TransactionWitness {
    pub fn sender_balance(&self) -> u128 {
        self.sender_account.balance
    }
}

/// Circuit capturing the constraints for a single transaction proof.
#[derive(Debug)]
pub struct TransactionCircuit {
    pub witness: TransactionWitness,
}

impl TransactionCircuit {
    pub fn new(witness: TransactionWitness) -> Self {
        Self { witness }
    }

    fn check_signature(&self) -> Result<(), CircuitError> {
        self.witness
            .signed_tx
            .verify()
            .map_err(|err| CircuitError::ConstraintViolation(err.to_string()))
    }

    fn check_balances(&self) -> Result<(), CircuitError> {
        let tx = &self.witness.signed_tx.payload;
        let total = tx
            .amount
            .checked_add(tx.fee as u128)
            .ok_or_else(|| CircuitError::ConstraintViolation("amount overflow".into()))?;
        if self.witness.sender_account.balance < total {
            return Err(CircuitError::ConstraintViolation(
                "sender balance insufficient".into(),
            ));
        }
        Ok(())
    }

    fn check_nonce(&self) -> Result<(), CircuitError> {
        let tx = &self.witness.signed_tx.payload;
        if self.witness.sender_account.nonce + 1 != tx.nonce {
            return Err(CircuitError::ConstraintViolation(
                "sender nonce does not match witness".into(),
            ));
        }
        Ok(())
    }

    fn check_tier(&self) -> Result<(), CircuitError> {
        if self.witness.sender_account.reputation.tier < self.witness.required_tier {
            return Err(CircuitError::ConstraintViolation(format!(
                "sender tier {} below required {}",
                self.witness.sender_account.reputation.tier, self.witness.required_tier
            )));
        }
        Ok(())
    }

    fn check_reputation_decay(&self) -> Result<(), CircuitError> {
        let tx_timestamp = self.witness.signed_tx.payload.timestamp;
        if tx_timestamp < self.witness.sender_account.reputation.last_decay_timestamp {
            return Err(CircuitError::ConstraintViolation(
                "transaction timestamp precedes reputation decay reference".into(),
            ));
        }
        Ok(())
    }
}

impl StarkCircuit for TransactionCircuit {
    fn name(&self) -> &'static str {
        "transaction"
    }

    fn evaluate_constraints(&self) -> Result<(), CircuitError> {
        self.check_signature()?;
        self.check_balances()?;
        self.check_nonce()?;
        self.check_tier()?;
        self.check_reputation_decay()?;

        let receiver = &self.witness.receiver_account;
        if let Some(receiver_account) = receiver {
            if receiver_account.address != self.witness.signed_tx.payload.to {
                return Err(CircuitError::ConstraintViolation(
                    "receiver account mismatch".into(),
                ));
            }
        }

        Ok(())
    }

    fn generate_trace(&self, parameters: &StarkParameters) -> Result<ExecutionTrace, CircuitError> {
        let tx = &self.witness.signed_tx;
        let payload = &tx.payload;
        let total = payload
            .amount
            .checked_add(payload.fee as u128)
            .ok_or_else(|| CircuitError::ConstraintViolation("amount overflow".into()))?;
        let sender_balance_before = self.witness.sender_account.balance;
        let sender_balance_after = sender_balance_before
            .checked_sub(total)
            .ok_or_else(|| CircuitError::ConstraintViolation("sender balance underflow".into()))?;
        let (receiver_balance_before, receiver_balance_after) = match &self.witness.receiver_account
        {
            Some(account) => {
                let before = account.balance;
                let after = before.saturating_add(payload.amount);
                (before, after)
            }
            None => (0u128, payload.amount),
        };

        let tier_to_field = |tier: &Tier| -> FieldElement {
            let rank = match tier {
                Tier::Tl0 => 0u64,
                Tier::Tl1 => 1u64,
                Tier::Tl2 => 2u64,
                Tier::Tl3 => 3u64,
                Tier::Tl4 => 4u64,
                Tier::Tl5 => 5u64,
            };
            parameters.element_from_u64(rank)
        };

        let signature_flag = parameters.element_from_u64(1);
        let columns = vec![
            "sender".to_string(),
            "receiver".to_string(),
            "amount".to_string(),
            "fee".to_string(),
            "total_spent".to_string(),
            "sender_balance_before".to_string(),
            "sender_balance_after".to_string(),
            "receiver_balance_before".to_string(),
            "receiver_balance_after".to_string(),
            "nonce_before".to_string(),
            "nonce_after".to_string(),
            "required_tier".to_string(),
            "actual_tier".to_string(),
            "signature_valid".to_string(),
        ];
        let row = vec![
            string_to_field(parameters, &payload.from),
            string_to_field(parameters, &payload.to),
            parameters.element_from_u128(payload.amount),
            parameters.element_from_u64(payload.fee as u64),
            parameters.element_from_u128(total),
            parameters.element_from_u128(sender_balance_before),
            parameters.element_from_u128(sender_balance_after),
            parameters.element_from_u128(receiver_balance_before),
            parameters.element_from_u128(receiver_balance_after),
            parameters.element_from_u64(self.witness.sender_account.nonce),
            parameters.element_from_u64(payload.nonce),
            tier_to_field(&self.witness.required_tier),
            tier_to_field(&self.witness.sender_account.reputation.tier),
            signature_flag,
        ];
        let segment = TraceSegment::new("transaction", columns, vec![row])?;
        ExecutionTrace::single(segment)
    }

    fn define_air(
        &self,
        parameters: &StarkParameters,
        _trace: &ExecutionTrace,
    ) -> Result<AirDefinition, CircuitError> {
        let segment = "transaction";
        let amount = AirColumn::new(segment, "amount");
        let fee = AirColumn::new(segment, "fee");
        let total = AirColumn::new(segment, "total_spent");
        let sender_before = AirColumn::new(segment, "sender_balance_before");
        let sender_after = AirColumn::new(segment, "sender_balance_after");
        let receiver_before = AirColumn::new(segment, "receiver_balance_before");
        let receiver_after = AirColumn::new(segment, "receiver_balance_after");
        let nonce_before = AirColumn::new(segment, "nonce_before");
        let nonce_after = AirColumn::new(segment, "nonce_after");
        let signature_valid = AirColumn::new(segment, "signature_valid");

        let one = parameters.element_from_u64(1);

        let constraints = vec![
            AirConstraint::new(
                "total_matches_amount_fee",
                segment,
                ConstraintDomain::AllRows,
                AirExpression::difference(
                    total.expr(),
                    AirExpression::sum(vec![amount.expr(), fee.expr()]),
                ),
            ),
            AirConstraint::new(
                "sender_balance_updates",
                segment,
                ConstraintDomain::AllRows,
                AirExpression::difference(
                    sender_before.expr(),
                    AirExpression::sum(vec![sender_after.expr(), total.expr()]),
                ),
            ),
            AirConstraint::new(
                "receiver_balance_updates",
                segment,
                ConstraintDomain::AllRows,
                AirExpression::difference(
                    receiver_after.expr(),
                    AirExpression::sum(vec![receiver_before.expr(), amount.expr()]),
                ),
            ),
            AirConstraint::new(
                "nonce_increments",
                segment,
                ConstraintDomain::AllRows,
                AirExpression::difference(
                    AirExpression::difference(nonce_after.expr(), nonce_before.expr()),
                    AirExpression::constant(one.clone()),
                ),
            ),
            AirConstraint::new(
                "signature_flag_set",
                segment,
                ConstraintDomain::AllRows,
                AirExpression::difference(signature_valid.expr(), AirExpression::constant(one)),
            ),
        ];

        Ok(AirDefinition::new(constraints))
    }
}
