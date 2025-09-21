use std::str::FromStr;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use ed25519_dalek::Keypair;
use malachite::Natural;
use serde::Serialize;
use stwo::core::vcs::blake2_hash::Blake2sHasher;

use crate::consensus::evaluate_vrf;
use crate::crypto::{address_from_public_key, sign_message};
use crate::errors::{ChainError, ChainResult};
use crate::ledger::{DEFAULT_EPOCH_LENGTH, Ledger, ReputationAudit};
use crate::proof_system::ProofProver;
use crate::reputation::Tier;
use crate::storage::Storage;
use crate::stwo::prover::WalletProver;
use crate::types::{
    Address, IdentityDeclaration, IdentityGenesis, IdentityProof, SignedTransaction, Transaction,
    TransactionProofBundle, UptimeClaim, UptimeProof,
};

use super::tabs::{HistoryEntry, HistoryStatus, NodeTabMetrics, ReceiveTabAddress, SendPreview};

#[derive(Clone)]
pub struct Wallet {
    storage: Storage,
    keypair: Arc<Keypair>,
    address: Address,
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

#[derive(Clone, Debug, Serialize)]
pub struct ConsensusReceipt {
    pub height: u64,
    pub block_hash: String,
    pub proposer: Address,
    pub round: u64,
    pub total_power: String,
    pub quorum_threshold: String,
    pub pre_vote_power: String,
    pub pre_commit_power: String,
    pub commit_power: String,
    pub observers: u64,
    pub quorum_reached: bool,
}

impl Wallet {
    pub fn new(storage: Storage, keypair: Keypair) -> Self {
        let address = address_from_public_key(&keypair.public);
        Self {
            storage,
            keypair: Arc::new(keypair),
            address,
        }
    }

    fn stark_prover(&self) -> WalletProver<'_> {
        WalletProver::new(&self.storage)
    }

    pub fn address(&self) -> &Address {
        &self.address
    }

    pub fn build_identity_declaration(&self) -> ChainResult<IdentityDeclaration> {
        let accounts = self.storage.load_accounts()?;
        let mut tip_height = 0;
        if let Some(metadata) = self.storage.tip()? {
            tip_height = metadata.height.saturating_add(1);
        }
        let ledger = Ledger::load(accounts.clone(), DEFAULT_EPOCH_LENGTH);
        ledger.sync_epoch_for_height(tip_height);
        let epoch_nonce = ledger.current_epoch_nonce();
        let state_root = hex::encode(ledger.state_root());
        let identity_root = hex::encode(ledger.identity_root());

        let wallet_pk = hex::encode(self.keypair.public.to_bytes());
        let wallet_addr = self.address.clone();
        let vrf = evaluate_vrf(&epoch_nonce, 0, &wallet_addr, 0);
        let commitment_proof = ledger.identity_commitment_proof(&wallet_addr);
        let genesis = IdentityGenesis {
            wallet_pk,
            wallet_addr,
            vrf_tag: vrf.proof.clone(),
            epoch_nonce: hex::encode(epoch_nonce),
            state_root,
            identity_root,
            initial_reputation: 0,
            commitment_proof: commitment_proof.clone(),
        };

        let prover = self.stark_prover();
        let witness = prover.build_identity_witness(&genesis)?;
        let commitment_hex = witness.commitment.clone();
        let proof = prover.prove_identity(witness)?;
        let identity_proof = IdentityProof {
            commitment: commitment_hex,
            zk_proof: proof,
        };
        let declaration = IdentityDeclaration {
            genesis,
            proof: identity_proof,
        };
        declaration.verify()?;
        Ok(declaration)
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

    pub fn prove_transaction(&self, tx: &SignedTransaction) -> ChainResult<TransactionProofBundle> {
        let prover = self.stark_prover();
        let witness = prover.build_transaction_witness(tx)?;
        let proof = prover.prove_transaction(witness)?;
        Ok(TransactionProofBundle::new(tx.clone(), proof))
    }

    pub fn generate_uptime_proof(&self) -> ChainResult<UptimeProof> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let window_end = now;
        let window_start = window_end.saturating_sub(3600);
        let node_clock = now;

        let tip_metadata = self.storage.tip()?;
        let (tip_height, head_hash) = match tip_metadata {
            Some(meta) => (meta.height, meta.hash),
            None => (0, hex::encode([0u8; 32])),
        };

        let accounts = self.storage.load_accounts()?;
        let ledger = Ledger::load(accounts, DEFAULT_EPOCH_LENGTH);
        ledger.sync_epoch_for_height(tip_height);
        let epoch = ledger.current_epoch();

        let claim = UptimeClaim {
            wallet_address: self.address.clone(),
            node_clock,
            epoch,
            head_hash,
            window_start,
            window_end,
        };
        let prover = self.stark_prover();
        let witness = prover.build_uptime_witness(&claim)?;
        let proof = prover.prove_uptime(witness)?;
        Ok(UptimeProof::new(claim, proof))
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

    pub fn latest_consensus_receipt(&self) -> ChainResult<Option<ConsensusReceipt>> {
        let tip = match self.storage.tip()? {
            Some(tip) => tip,
            None => return Ok(None),
        };
        let block = match self.storage.read_block(tip.height)? {
            Some(block) => block,
            None => return Ok(None),
        };
        let certificate = &block.consensus;
        let commit =
            Natural::from_str(&certificate.commit_power).unwrap_or_else(|_| Natural::from(0u32));
        let quorum = Natural::from_str(&certificate.quorum_threshold)
            .unwrap_or_else(|_| Natural::from(0u32));
        Ok(Some(ConsensusReceipt {
            height: block.header.height,
            block_hash: block.hash.clone(),
            proposer: block.header.proposer.clone(),
            round: certificate.round,
            total_power: certificate.total_power.clone(),
            quorum_threshold: certificate.quorum_threshold.clone(),
            pre_vote_power: certificate.pre_vote_power.clone(),
            pre_commit_power: certificate.pre_commit_power.clone(),
            commit_power: certificate.commit_power.clone(),
            observers: certificate.observers,
            quorum_reached: commit >= quorum && commit > Natural::from(0u32),
        }))
    }

    pub fn reputation_audit(&self) -> ChainResult<ReputationAudit> {
        let account = self
            .storage
            .read_account(&self.address)?
            .ok_or_else(|| ChainError::Config("wallet account not found".into()))?;
        Ok(ReputationAudit {
            address: account.address.clone(),
            balance: account.balance,
            stake: account.stake.to_string(),
            score: account.reputation.score,
            tier: account.reputation.tier.clone(),
            uptime_hours: account.reputation.timetokes.hours_online,
            consensus_success: account.reputation.consensus_success,
            peer_feedback: account.reputation.peer_feedback,
            last_decay_timestamp: account.reputation.last_decay_timestamp,
            zsi_validated: account.reputation.zsi.validated,
            zsi_commitment: account.reputation.zsi.public_key_commitment.clone(),
            zsi_reputation_proof: account.reputation.zsi.reputation_proof.clone(),
        })
    }
}
