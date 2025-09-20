use hex;
use serde::{Deserialize, Serialize};
use stwo::core::vcs::blake2_hash::Blake2sHasher;

use super::Address;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UptimeProof {
    pub wallet_address: Address,
    pub window_start: u64,
    pub window_end: u64,
    pub proof_commitment: String,
}

impl UptimeProof {
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
}
