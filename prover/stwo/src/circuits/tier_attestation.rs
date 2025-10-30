use serde::{Deserialize, Serialize};

use super::CircuitError;

/// Tier levels recognised by the attestation circuit.
#[derive(
    Clone, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash, Copy,
)]
pub enum TierLevel {
    Tl0,
    Tl1,
    Tl2,
    Tl3,
    Tl4,
    Tl5,
}

impl TierLevel {
    pub fn from_rank(rank: u8) -> Result<Self, CircuitError> {
        match rank {
            0 => Ok(Self::Tl0),
            1 => Ok(Self::Tl1),
            2 => Ok(Self::Tl2),
            3 => Ok(Self::Tl3),
            4 => Ok(Self::Tl4),
            5 => Ok(Self::Tl5),
            _ => Err(CircuitError::invalid("tier rank must be between 0 and 5")),
        }
    }
}

/// Witness confirming that an account satisfies the required tier constraints.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct TierAttestationWitness {
    pub wallet_address: String,
    pub attested_tier: TierLevel,
    pub required_tier: TierLevel,
    pub signature_valid: bool,
    pub attestation_digest: String,
}

impl TierAttestationWitness {
    pub fn new(
        wallet_address: impl Into<String>,
        attested_tier: TierLevel,
        required_tier: TierLevel,
        signature_valid: bool,
        attestation_digest: impl Into<String>,
    ) -> Self {
        Self {
            wallet_address: wallet_address.into(),
            attested_tier,
            required_tier,
            signature_valid,
            attestation_digest: attestation_digest.into(),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct TierAttestationCircuit {
    witness: TierAttestationWitness,
}

impl TierAttestationCircuit {
    pub fn new(witness: TierAttestationWitness) -> Result<Self, CircuitError> {
        if witness.wallet_address.is_empty() {
            return Err(CircuitError::invalid("wallet address must not be empty"));
        }
        if witness.attestation_digest.is_empty() {
            return Err(CircuitError::invalid("attestation digest must not be empty"));
        }
        Ok(Self { witness })
    }

    pub fn verify(&self) -> Result<(), CircuitError> {
        if !self.witness.signature_valid {
            return Err(CircuitError::violated(
                "tier attestation signature failed verification",
            ));
        }
        if self.witness.attested_tier < self.witness.required_tier {
            return Err(CircuitError::violated(
                "wallet tier below the minimum required threshold",
            ));
        }
        Ok(())
    }

    pub fn witness(&self) -> &TierAttestationWitness {
        &self.witness
    }
}
