use hex;
use serde::{Deserialize, Serialize};
use crate::proof_backend::Blake2sHasher;

use crate::errors::{ChainError, ChainResult};

use super::Address;
use super::proofs::ChainProof;

/// Metadata describing the uptime observation a wallet wants to attest to.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UptimeClaim {
    pub wallet_address: Address,
    pub node_clock: u64,
    pub epoch: u64,
    pub head_hash: String,
    pub window_start: u64,
    pub window_end: u64,
}

impl UptimeClaim {
    pub fn commitment(&self) -> String {
        let bytes =
            UptimeProof::commitment_bytes(&self.wallet_address, self.window_start, self.window_end);
        hex::encode(bytes)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UptimeProof {
    pub wallet_address: Address,
    pub window_start: u64,
    pub window_end: u64,
    pub proof_commitment: String,
    #[serde(default)]
    pub node_clock: Option<u64>,
    #[serde(default)]
    pub epoch: Option<u64>,
    #[serde(default)]
    pub head_hash: Option<String>,
    #[serde(default)]
    pub proof: Option<ChainProof>,
}

impl UptimeProof {
    pub fn new(claim: UptimeClaim, proof: ChainProof) -> Self {
        let commitment = claim.commitment();
        Self {
            wallet_address: claim.wallet_address.clone(),
            window_start: claim.window_start,
            window_end: claim.window_end,
            proof_commitment: commitment,
            node_clock: Some(claim.node_clock),
            epoch: Some(claim.epoch),
            head_hash: Some(claim.head_hash),
            proof: Some(proof),
        }
    }

    pub fn legacy(address: Address, window_start: u64, window_end: u64) -> Self {
        let commitment = Self::commitment_bytes(&address, window_start, window_end);
        Self {
            wallet_address: address,
            window_start,
            window_end,
            proof_commitment: hex::encode(commitment),
            node_clock: None,
            epoch: None,
            head_hash: None,
            proof: None,
        }
    }

    pub fn commitment_bytes(address: &str, window_start: u64, window_end: u64) -> [u8; 32] {
        let mut data = Vec::new();
        data.extend_from_slice(address.as_bytes());
        data.extend_from_slice(&window_start.to_be_bytes());
        data.extend_from_slice(&window_end.to_be_bytes());
        Blake2sHasher::hash(&data).into()
    }

    pub fn verify_commitment(&self) -> bool {
        let expected =
            Self::commitment_bytes(&self.wallet_address, self.window_start, self.window_end);
        hex::encode(expected) == self.proof_commitment
    }

    pub fn claim(&self) -> ChainResult<UptimeClaim> {
        let node_clock = self
            .node_clock
            .ok_or_else(|| ChainError::Crypto("uptime proof missing node clock metadata".into()))?;
        let epoch = self
            .epoch
            .ok_or_else(|| ChainError::Crypto("uptime proof missing epoch metadata".into()))?;
        let head_hash = self
            .head_hash
            .clone()
            .ok_or_else(|| ChainError::Crypto("uptime proof missing head hash".into()))?;
        Ok(UptimeClaim {
            wallet_address: self.wallet_address.clone(),
            node_clock,
            epoch,
            head_hash,
            window_start: self.window_start,
            window_end: self.window_end,
        })
    }

    pub fn proof(&self) -> ChainResult<&ChainProof> {
        self.proof
            .as_ref()
            .ok_or_else(|| ChainError::Crypto("uptime proof is missing a zk proof payload".into()))
    }
}
