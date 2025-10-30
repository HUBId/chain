use serde::{Deserialize, Serialize};

use super::CircuitError;

/// Snapshot of an account state used by the balance circuit.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct AccountSnapshot {
    pub address: String,
    pub balance: u128,
    pub nonce: u64,
}

impl AccountSnapshot {
    pub fn new(address: impl Into<String>, balance: u128, nonce: u64) -> Self {
        Self {
            address: address.into(),
            balance,
            nonce,
        }
    }
}

/// Witness describing a transfer between two accounts.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct BalanceWitness {
    pub sender_before: AccountSnapshot,
    pub sender_after: AccountSnapshot,
    pub recipient_before: Option<AccountSnapshot>,
    pub recipient_after: AccountSnapshot,
    pub transfer_amount: u128,
    pub fee: u64,
}

impl BalanceWitness {
    pub fn new(
        sender_before: AccountSnapshot,
        sender_after: AccountSnapshot,
        recipient_before: Option<AccountSnapshot>,
        recipient_after: AccountSnapshot,
        transfer_amount: u128,
        fee: u64,
    ) -> Self {
        Self {
            sender_before,
            sender_after,
            recipient_before,
            recipient_after,
            transfer_amount,
            fee,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct BalanceCircuit {
    witness: BalanceWitness,
}

impl BalanceCircuit {
    pub fn new(witness: BalanceWitness) -> Result<Self, CircuitError> {
        if witness.transfer_amount == 0 {
            return Err(CircuitError::invalid(
                "transfer amount must be greater than zero",
            ));
        }
        if witness.sender_before.address.is_empty() {
            return Err(CircuitError::invalid("sender address must not be empty"));
        }
        if witness.sender_before.address != witness.sender_after.address {
            return Err(CircuitError::invalid(
                "sender snapshots must reference the same address",
            ));
        }
        if witness.recipient_after.address.is_empty() {
            return Err(CircuitError::invalid("recipient address must not be empty"));
        }
        if let Some(before) = &witness.recipient_before {
            if before.address != witness.recipient_after.address {
                return Err(CircuitError::invalid(
                    "recipient snapshots must reference the same address",
                ));
            }
        }
        Ok(Self { witness })
    }

    pub fn verify(&self) -> Result<(), CircuitError> {
        let fee = u128::from(self.witness.fee);
        let total_spent = self
            .witness
            .transfer_amount
            .checked_add(fee)
            .ok_or_else(|| CircuitError::violated("transfer amount overflow"))?;

        if self.witness.sender_before.balance < total_spent {
            return Err(CircuitError::violated("sender balance is insufficient"));
        }

        if self.witness.sender_before.nonce + 1 != self.witness.sender_after.nonce {
            return Err(CircuitError::violated(
                "sender nonce must increment exactly by one",
            ));
        }

        let expected_balance_after = self
            .witness
            .sender_before
            .balance
            .checked_sub(total_spent)
            .ok_or_else(|| CircuitError::violated("sender balance underflow"))?;
        if expected_balance_after != self.witness.sender_after.balance {
            return Err(CircuitError::violated(
                "sender balance after transfer does not match",
            ));
        }

        let recipient_before = self
            .witness
            .recipient_before
            .as_ref()
            .map(|snapshot| snapshot.balance)
            .unwrap_or_default();
        let recipient_expected = recipient_before
            .checked_add(self.witness.transfer_amount)
            .ok_or_else(|| CircuitError::violated("recipient balance overflow"))?;
        if recipient_expected != self.witness.recipient_after.balance {
            return Err(CircuitError::violated(
                "recipient balance after transfer does not match",
            ));
        }

        Ok(())
    }

    pub fn witness(&self) -> &BalanceWitness {
        &self.witness
    }
}
