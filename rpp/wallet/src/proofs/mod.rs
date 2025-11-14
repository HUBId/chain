use thiserror::Error;

#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum ChainError {
    #[error("config error: {0}")]
    Config(String),
    #[error("transaction error: {0}")]
    Transaction(String),
}

pub type ChainResult<T> = Result<T, ChainError>;

#[cfg(feature = "prover-stwo")]
use crate::reputation::Tier;
#[cfg(feature = "prover-stwo")]
use crate::stwo::circuit::transaction::TransactionWitness;

#[cfg(feature = "prover-stwo")]
use prover_stwo_circuits::circuits::balance::{AccountSnapshot, BalanceWitness};
#[cfg(feature = "prover-stwo")]
use prover_stwo_circuits::circuits::double_spend::{DoubleSpendWitness, OutpointWitness};
#[cfg(feature = "prover-stwo")]
use prover_stwo_circuits::circuits::tier_attestation::{TierAttestationWitness, TierLevel};
#[cfg(feature = "prover-stwo")]
use prover_stwo_circuits::{
    build_balance_circuit, build_double_spend_circuit, build_tier_attestation_circuit, CircuitError,
};

/// Validate a transaction witness against wallet-level balance, double-spend,
/// and tier attestation circuits.
#[cfg(feature = "prover-stwo")]
pub fn validate_transaction_witness(witness: &TransactionWitness) -> ChainResult<()> {
    verify_balance_circuit(witness)?;
    verify_double_spend_circuit(witness)?;
    verify_tier_attestation_circuit(witness)?;
    Ok(())
}

/// Stubbed validation returning an explicit error when the STWO prover is
/// disabled at compile time.
#[cfg(not(feature = "prover-stwo"))]
pub fn validate_transaction_witness<T>(_witness: &T) -> ChainResult<()> {
    Err(ChainError::Config(
        "STWO prover feature is disabled for this build".into(),
    ))
}

#[cfg(feature = "prover-stwo")]
fn verify_balance_circuit(witness: &TransactionWitness) -> ChainResult<()> {
    let tx = &witness.signed_tx.payload;
    let sender_before = AccountSnapshot::new(
        tx.from.clone(),
        witness.sender_account.balance,
        witness.sender_account.nonce,
    );
    let total_spent = tx
        .amount
        .checked_add(tx.fee as u128)
        .ok_or_else(|| ChainError::Transaction("transaction amount overflow".into()))?;
    let sender_after_balance = witness
        .sender_account
        .balance
        .checked_sub(total_spent)
        .ok_or_else(|| ChainError::Transaction("sender balance underflow".into()))?;
    let sender_after = AccountSnapshot::new(tx.from.clone(), sender_after_balance, tx.nonce);

    let recipient_before = witness.receiver_account.as_ref().map(|account| {
        AccountSnapshot::new(account.address.clone(), account.balance, account.nonce)
    });
    let recipient_base = recipient_before
        .as_ref()
        .map(|snapshot| snapshot.balance)
        .unwrap_or_default();
    let recipient_after_balance = recipient_base
        .checked_add(tx.amount)
        .ok_or_else(|| ChainError::Transaction("recipient balance overflow".into()))?;
    let recipient_after = AccountSnapshot::new(tx.to.clone(), recipient_after_balance, 0);

    let balance_witness = BalanceWitness::new(
        sender_before,
        sender_after,
        recipient_before,
        recipient_after,
        tx.amount,
        tx.fee,
    );
    let circuit = build_balance_circuit(balance_witness).map_err(map_circuit_error)?;
    circuit.verify().map_err(map_circuit_error)
}

#[cfg(feature = "prover-stwo")]
fn verify_double_spend_circuit(witness: &TransactionWitness) -> ChainResult<()> {
    let expected_nonce = witness
        .sender_account
        .nonce
        .checked_add(1)
        .ok_or_else(|| ChainError::Transaction("sender nonce overflow".into()))?;
    let expected_index = u32::try_from(expected_nonce)
        .map_err(|_| ChainError::Transaction("sender nonce exceeds supported range".into()))?;
    let actual_index = u32::try_from(witness.signed_tx.payload.nonce)
        .map_err(|_| ChainError::Transaction("transaction nonce exceeds supported range".into()))?;

    let available = vec![OutpointWitness::new(
        witness.signed_tx.payload.from.clone(),
        expected_index,
    )];
    let consumed = vec![OutpointWitness::new(
        witness.signed_tx.payload.from.clone(),
        actual_index,
    )];
    let double_spend_witness = DoubleSpendWitness::new(available, consumed, Vec::new());
    let circuit = build_double_spend_circuit(double_spend_witness).map_err(map_circuit_error)?;
    circuit.verify().map_err(map_circuit_error)
}

#[cfg(feature = "prover-stwo")]
fn verify_tier_attestation_circuit(witness: &TransactionWitness) -> ChainResult<()> {
    let attested = tier_to_level(&witness.sender_account.reputation.tier)?;
    let required = tier_to_level(&witness.required_tier)?;
    let digest = hex::encode(witness.signed_tx.hash());
    let signature_valid = witness.signed_tx.verify().is_ok();
    let tier_witness = TierAttestationWitness::new(
        witness.signed_tx.payload.from.clone(),
        attested,
        required,
        signature_valid,
        digest,
    );
    let circuit = build_tier_attestation_circuit(tier_witness).map_err(map_circuit_error)?;
    circuit.verify().map_err(map_circuit_error)
}

#[cfg(feature = "prover-stwo")]
fn tier_to_level(tier: &Tier) -> ChainResult<TierLevel> {
    let rank = match tier {
        Tier::Tl0 => 0,
        Tier::Tl1 => 1,
        Tier::Tl2 => 2,
        Tier::Tl3 => 3,
        Tier::Tl4 => 4,
        Tier::Tl5 => 5,
    };
    TierLevel::from_rank(rank).map_err(map_circuit_error)
}

#[cfg(feature = "prover-stwo")]
fn map_circuit_error(err: CircuitError) -> ChainError {
    ChainError::Transaction(err.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn disabled_prover_reports_configuration_error() {
        #[cfg(feature = "prover-stwo")]
        {
            // Feature enabled branch is covered by integration tests elsewhere.
            assert!(true);
        }

        #[cfg(not(feature = "prover-stwo"))]
        {
            let result = validate_transaction_witness(&());
            assert!(matches!(result, Err(ChainError::Config(_))));
        }
    }
}
