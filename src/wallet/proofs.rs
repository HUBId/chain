use std::time::{SystemTime, UNIX_EPOCH};

use serde::Serialize;
use stwo::core::vcs::blake2_hash::Blake2sHasher;

use crate::types::{Address, SignedTransaction};

#[derive(Clone, Debug, Serialize)]
pub struct TxProof {
    pub wallet_address: Address,
    pub tx_hash: String,
    pub proof_commitment: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct UptimeProof {
    pub wallet_address: Address,
    pub window_start: u64,
    pub window_end: u64,
    pub proof_commitment: String,
}

#[derive(Clone)]
pub struct ProofGenerator {
    wallet_address: Address,
}

impl ProofGenerator {
    pub fn new(wallet_address: Address) -> Self {
        Self { wallet_address }
    }

    pub fn generate_tx_proof(&self, tx: &SignedTransaction) -> TxProof {
        let mut data = Vec::new();
        data.extend_from_slice(self.wallet_address.as_bytes());
        data.extend_from_slice(&tx.hash());
        let commitment: [u8; 32] = Blake2sHasher::hash(&data).into();
        TxProof {
            wallet_address: self.wallet_address.clone(),
            tx_hash: hex::encode(tx.hash()),
            proof_commitment: hex::encode(commitment),
        }
    }

    pub fn generate_uptime_proof(&self) -> UptimeProof {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let window_start = now.saturating_sub(3600);
        let mut data = Vec::new();
        data.extend_from_slice(self.wallet_address.as_bytes());
        data.extend_from_slice(&window_start.to_be_bytes());
        data.extend_from_slice(&now.to_be_bytes());
        let commitment: [u8; 32] = Blake2sHasher::hash(&data).into();
        UptimeProof {
            wallet_address: self.wallet_address.clone(),
            window_start,
            window_end: now,
            proof_commitment: hex::encode(commitment),
        }
    }
}
