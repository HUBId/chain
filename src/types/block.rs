use std::time::{SystemTime, UNIX_EPOCH};

use ed25519_dalek::{PublicKey, Signature};
use serde::{Deserialize, Serialize};
use stwo::core::vcs::blake2_hash::Blake2sHasher;

use crate::crypto::{signature_from_hex, signature_to_hex, verify_signature};
use crate::errors::ChainResult;

use super::{Address, SignedTransaction};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BlockHeader {
    pub height: u64,
    pub previous_hash: String,
    pub tx_root: String,
    pub state_root: String,
    pub total_stake: String,
    pub randomness: String,
    pub timestamp: u64,
    pub proposer: Address,
}

impl BlockHeader {
    pub fn new(
        height: u64,
        previous_hash: String,
        tx_root: String,
        state_root: String,
        total_stake: String,
        randomness: String,
        proposer: Address,
    ) -> Self {
        Self {
            height,
            previous_hash,
            tx_root,
            state_root,
            total_stake,
            randomness,
            proposer,
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        }
    }

    pub fn canonical_bytes(&self) -> Vec<u8> {
        serde_json::to_vec(self).expect("serializing block header")
    }

    pub fn hash(&self) -> [u8; 32] {
        let bytes = self.canonical_bytes();
        Blake2sHasher::hash(bytes.as_slice()).into()
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Block {
    pub header: BlockHeader,
    pub transactions: Vec<SignedTransaction>,
    pub signature: String,
    pub hash: String,
}

impl Block {
    pub fn new(
        header: BlockHeader,
        transactions: Vec<SignedTransaction>,
        signature: Signature,
    ) -> Self {
        let hash = header.hash();
        Self {
            header,
            transactions,
            signature: signature_to_hex(&signature),
            hash: hex::encode(hash),
        }
    }

    pub fn verify_signature(&self, public_key: &PublicKey) -> ChainResult<()> {
        let signature = signature_from_hex(&self.signature)?;
        verify_signature(public_key, &self.header.canonical_bytes(), &signature)
    }

    pub fn block_hash(&self) -> [u8; 32] {
        self.header.hash()
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BlockMetadata {
    pub height: u64,
    pub hash: String,
    pub timestamp: u64,
}

impl From<&Block> for BlockMetadata {
    fn from(block: &Block) -> Self {
        Self {
            height: block.header.height,
            hash: block.hash.clone(),
            timestamp: block.header.timestamp,
        }
    }
}
