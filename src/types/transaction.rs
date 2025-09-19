use std::time::{SystemTime, UNIX_EPOCH};

use ed25519_dalek::{PublicKey, Signature};
use serde::{Deserialize, Serialize};
use stwo::core::vcs::blake2_hash::Blake2sHasher;
use uuid::Uuid;

use crate::crypto::{signature_from_hex, signature_to_hex, verify_signature};
use crate::errors::{ChainError, ChainResult};

use super::Address;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Transaction {
    pub from: Address,
    pub to: Address,
    pub amount: u128,
    pub fee: u64,
    pub nonce: u64,
    pub memo: Option<String>,
    pub timestamp: u64,
}

impl Transaction {
    pub fn new(
        from: Address,
        to: Address,
        amount: u128,
        fee: u64,
        nonce: u64,
        memo: Option<String>,
    ) -> Self {
        Self {
            from,
            to,
            amount,
            fee,
            nonce,
            memo,
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        }
    }

    pub fn hash(&self) -> [u8; 32] {
        let bytes = serde_json::to_vec(self).expect("serializing transaction for hashing");
        Blake2sHasher::hash(bytes.as_slice()).into()
    }

    pub fn canonical_bytes(&self) -> Vec<u8> {
        serde_json::to_vec(self).expect("serializing transaction")
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SignedTransaction {
    pub id: Uuid,
    pub payload: Transaction,
    pub signature: String,
    pub public_key: String,
}

impl SignedTransaction {
    pub fn new(payload: Transaction, signature: Signature, public_key: &PublicKey) -> Self {
        Self {
            id: Uuid::new_v4(),
            signature: signature_to_hex(&signature),
            payload,
            public_key: hex::encode(public_key.to_bytes()),
        }
    }

    pub fn hash(&self) -> [u8; 32] {
        self.payload.hash()
    }

    pub fn verify(&self) -> ChainResult<()> {
        let signature = signature_from_hex(&self.signature)?;
        let public_key = PublicKey::from_bytes(&hex::decode(&self.public_key).map_err(|err| {
            ChainError::Transaction(format!("invalid public key encoding: {err}"))
        })?)
        .map_err(|err| ChainError::Transaction(format!("invalid public key: {err}")))?;
        verify_signature(&public_key, &self.payload.canonical_bytes(), &signature)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TransactionEnvelope {
    pub tx: SignedTransaction,
    pub hash: String,
}

impl TransactionEnvelope {
    pub fn new(tx: SignedTransaction) -> Self {
        let hash = hex::encode(tx.hash());
        Self { tx, hash }
    }
}
