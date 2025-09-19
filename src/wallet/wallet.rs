use std::sync::Arc;

use ed25519_dalek::Keypair;
use serde::Serialize;
use stwo::core::vcs::blake2_hash::Blake2sHasher;

use crate::crypto::{address_from_public_key, sign_message};
use crate::errors::{ChainError, ChainResult};
use crate::reputation::Tier;
use crate::storage::Storage;
use crate::types::{Address, SignedTransaction, Transaction};

use super::proofs::{ProofGenerator, TxProof, UptimeProof};
use super::tabs::{HistoryEntry, HistoryStatus, NodeTabMetrics, ReceiveTabAddress, SendPreview};

#[derive(Clone)]
pub struct Wallet {
    storage: Storage,
    keypair: Arc<Keypair>,
    address: Address,
    proof_generator: ProofGenerator,
}

#[derive(Clone, Debug, Serialize)]
pub struct WalletAccountSummary {
    pub address: Address,
    pub balance: u128,
    pub nonce: u64,
    pub reputation_score: f64,
    pub tier: Tier,
    pub uptime_hours: u64,
}

impl Wallet {
    pub fn new(storage: Storage, keypair: Keypair) -> Self {
        let address = address_from_public_key(&keypair.public);
        let proof_generator = ProofGenerator::new(address.clone());
        Self {
            storage,
            keypair: Arc::new(keypair),
            address,
            proof_generator,
        }
    }

    pub fn address(&self) -> &Address {
        &self.address
    }

    pub fn account_summary(&self) -> ChainResult<WalletAccountSummary> {
        let account = self
            .storage
            .read_account(&self.address)?
            .ok_or_else(|| ChainError::Config("wallet account not found".into()))?;
        Ok(WalletAccountSummary {
            address: account.address.clone(),
            balance: account.balance,
            nonce: account.nonce,
            reputation_score: account.reputation.score,
            tier: account.reputation.tier.clone(),
            uptime_hours: account.reputation.timetokes.hours_online,
        })
    }

    pub fn build_transaction(
        &self,
        to: Address,
        amount: u128,
        fee: u64,
        memo: Option<String>,
    ) -> ChainResult<Transaction> {
        let account = self
            .storage
            .read_account(&self.address)?
            .ok_or_else(|| ChainError::Transaction("wallet account not found".into()))?;
        let total = amount
            .checked_add(fee as u128)
            .ok_or_else(|| ChainError::Transaction("amount overflow".into()))?;
        if account.balance < total {
            return Err(ChainError::Transaction("insufficient balance".into()));
        }
        let nonce = account.nonce + 1;
        Ok(Transaction::new(
            self.address.clone(),
            to,
            amount,
            fee,
            nonce,
            memo,
        ))
    }

    pub fn preview_send(
        &self,
        to: Address,
        amount: u128,
        fee: u64,
        memo: Option<String>,
    ) -> ChainResult<SendPreview> {
        let account = self
            .storage
            .read_account(&self.address)?
            .ok_or_else(|| ChainError::Transaction("wallet account not found".into()))?;
        let total = amount
            .checked_add(fee as u128)
            .ok_or_else(|| ChainError::Transaction("amount overflow".into()))?;
        let remaining_balance = account.balance.saturating_sub(total);
        Ok(SendPreview {
            from: self.address.clone(),
            to,
            amount,
            fee,
            memo,
            nonce: account.nonce + 1,
            balance_before: account.balance,
            balance_after: remaining_balance,
        })
    }

    pub fn sign_transaction(&self, tx: Transaction) -> SignedTransaction {
        let signature = sign_message(&self.keypair, &tx.canonical_bytes());
        SignedTransaction::new(tx, signature, &self.keypair.public)
    }

    pub fn prove_transaction(&self, tx: &SignedTransaction) -> TxProof {
        self.proof_generator.generate_tx_proof(tx)
    }

    pub fn generate_uptime_proof(&self) -> UptimeProof {
        self.proof_generator.generate_uptime_proof()
    }

    pub fn history(&self) -> ChainResult<Vec<HistoryEntry>> {
        let blocks = self.storage.load_blockchain()?;
        let mut history = Vec::new();
        for block in blocks {
            for tx in &block.transactions {
                if tx.payload.from == self.address || tx.payload.to == self.address {
                    let status = HistoryStatus::Confirmed {
                        height: block.header.height,
                        timestamp: block.header.timestamp,
                    };
                    history.push(HistoryEntry {
                        transaction: tx.clone(),
                        status,
                        reputation_delta: self.estimate_reputation_delta(tx),
                    });
                }
            }
        }
        history.sort_by_key(|entry| entry.status.confirmation_height());
        Ok(history)
    }

    fn estimate_reputation_delta(&self, tx: &SignedTransaction) -> i64 {
        if tx.payload.to == self.address {
            1
        } else if tx.payload.from == self.address {
            -1
        } else {
            0
        }
    }

    pub fn receive_addresses(&self, count: usize) -> Vec<ReceiveTabAddress> {
        (0..count)
            .map(|index| self.derive_address(index as u32))
            .collect()
    }

    pub fn derive_address(&self, index: u32) -> ReceiveTabAddress {
        let mut seed = Vec::new();
        seed.extend_from_slice(self.address.as_bytes());
        seed.extend_from_slice(&index.to_be_bytes());
        let hash: [u8; 32] = Blake2sHasher::hash(&seed).into();
        ReceiveTabAddress {
            derivation_index: index,
            address: hex::encode(hash),
        }
    }

    pub fn node_metrics(&self) -> ChainResult<NodeTabMetrics> {
        let tip = self.storage.tip()?;
        let account = self
            .storage
            .read_account(&self.address)?
            .ok_or_else(|| ChainError::Config("wallet account not found".into()))?;
        Ok(NodeTabMetrics {
            reputation_score: account.reputation.score,
            tier: account.reputation.tier.clone(),
            uptime_hours: account.reputation.timetokes.hours_online,
            latest_block_height: tip.as_ref().map(|meta| meta.height).unwrap_or(0),
            latest_block_hash: tip.as_ref().map(|meta| meta.hash.clone()),
            total_blocks: self.storage.load_blockchain()?.len() as u64,
        })
    }
}
