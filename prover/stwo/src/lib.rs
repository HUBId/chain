//! Helper circuits modelling wallet-level invariants enforced before running
//! the full STWO proving pipeline.  The consensus gadgets expose structured
//! public inputs so that VRF outputs, witness commitments, and reputation roots
//! are validated alongside the usual quorum signatures.

pub mod circuits;

pub use circuits::balance::{AccountSnapshot, BalanceCircuit, BalanceWitness};
pub use circuits::double_spend::{DoubleSpendCircuit, DoubleSpendWitness, OutpointWitness};
pub use circuits::tier_attestation::{TierAttestationCircuit, TierAttestationWitness, TierLevel};
pub use circuits::CircuitError;

/// Build a balance circuit from the provided witness.
pub fn build_balance_circuit(witness: BalanceWitness) -> Result<BalanceCircuit, CircuitError> {
    BalanceCircuit::new(witness)
}

/// Build a double spend circuit from the provided witness.
pub fn build_double_spend_circuit(
    witness: DoubleSpendWitness,
) -> Result<DoubleSpendCircuit, CircuitError> {
    DoubleSpendCircuit::new(witness)
}

/// Build a tier attestation circuit from the provided witness.
pub fn build_tier_attestation_circuit(
    witness: TierAttestationWitness,
) -> Result<TierAttestationCircuit, CircuitError> {
    TierAttestationCircuit::new(witness)
}
