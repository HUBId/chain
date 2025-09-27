use std::str::FromStr;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use ed25519_dalek::Keypair;
use malachite::Natural;
use parking_lot::RwLock;
use serde::{Serialize, de::DeserializeOwned};
use stwo::core::vcs::blake2_hash::Blake2sHasher;
use tokio::sync::Mutex;

use crate::config::NodeConfig;
use crate::consensus::evaluate_vrf;
use crate::crypto::{
    StoredVrfKeypair, VrfKeypair, address_from_public_key, generate_vrf_keypair, sign_message,
    vrf_public_key_from_hex, vrf_public_key_to_hex, vrf_secret_key_from_hex, vrf_secret_key_to_hex,
};
use crate::errors::{ChainError, ChainResult};
use crate::ledger::{DEFAULT_EPOCH_LENGTH, Ledger, ReputationAudit};
use crate::node::NodeHandle;
use crate::orchestration::{PipelineDashboardSnapshot, PipelineOrchestrator, PipelineStage};
use crate::proof_system::ProofProver;
use crate::reputation::Tier;
use crate::rpp::UtxoRecord;
use crate::storage::Storage;
use crate::stwo::prover::WalletProver;
use crate::types::{
    Account, Address, IdentityDeclaration, IdentityGenesis, IdentityProof, SignedTransaction,
    Transaction, TransactionProofBundle, UptimeClaim, UptimeProof,
};

use super::workflows::synthetic_account_utxos;
use super::{WalletNodeRuntime, start_node};

use super::tabs::{HistoryEntry, HistoryStatus, NodeTabMetrics, ReceiveTabAddress, SendPreview};

const IDENTITY_WORKFLOW_KEY: &[u8] = b"wallet_identity_workflow";
const IDENTITY_VRF_KEY: &[u8] = b"wallet_identity_vrf_keypair";
const NODE_RUNTIME_CONFIG_KEY: &[u8] = b"wallet_node_runtime_config";

#[derive(Clone, Debug, Serialize)]
pub struct WalletNodeRuntimeStatus {
    pub running: bool,
    pub config: Option<NodeConfig>,
    pub address: Option<Address>,
}

#[derive(Clone)]
pub struct Wallet {
    storage: Storage,
    keypair: Arc<Keypair>,
    address: Address,
    node_runtime: Arc<Mutex<Option<WalletNodeRuntime>>>,
    node_handle: Arc<RwLock<Option<NodeHandle>>>,
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
            node_runtime: Arc::new(Mutex::new(None)),
            node_handle: Arc::new(RwLock::new(None)),
        }
    }

    fn stark_prover(&self) -> WalletProver<'_> {
        WalletProver::new(&self.storage)
    }

    pub fn address(&self) -> &Address {
        &self.address
    }

    pub fn firewood_state_root(&self) -> ChainResult<String> {
        Ok(hex::encode(self.storage.state_root()?))
    }

    pub fn persist_node_runtime_config(&self, config: &NodeConfig) -> ChainResult<()> {
        let mut encoded = serde_json::to_vec(config).map_err(|err| {
            ChainError::Config(format!(
                "failed to encode wallet node runtime config for persistence: {err}"
            ))
        })?;
        if encoded.is_empty() {
            encoded = b"{}".to_vec();
        }
        self.storage
            .write_metadata_blob(NODE_RUNTIME_CONFIG_KEY, encoded)
    }

    pub fn configure_node_runtime(&self, config: &NodeConfig) -> ChainResult<()> {
        config.ensure_directories()?;
        self.persist_node_runtime_config(config)
    }

    pub fn load_node_runtime_config(&self) -> ChainResult<Option<NodeConfig>> {
        let maybe_bytes = self.storage.read_metadata_blob(NODE_RUNTIME_CONFIG_KEY)?;
        let Some(bytes) = maybe_bytes else {
            return Ok(None);
        };
        let config: NodeConfig = serde_json::from_slice(&bytes).map_err(|err| {
            ChainError::Config(format!(
                "failed to decode wallet node runtime config: {err}"
            ))
        })?;
        Ok(Some(config))
    }

    pub async fn start_node_runtime(&self) -> ChainResult<WalletNodeRuntimeStatus> {
        let mut guard = self.node_runtime.lock().await;
        if let Some(runtime) = guard.as_ref() {
            return Ok(WalletNodeRuntimeStatus {
                running: true,
                config: Some(runtime.config().clone()),
                address: Some(runtime.address().to_string()),
            });
        }

        let config = self.load_node_runtime_config()?.ok_or_else(|| {
            ChainError::Config("wallet node runtime configuration not found".into())
        })?;
        config.ensure_directories()?;
        let runtime = start_node(config.clone()).await?;
        let handle = runtime.node_handle();
        *self.node_handle.write() = Some(handle);
        let address = runtime.address().to_string();
        let status = WalletNodeRuntimeStatus {
            running: true,
            config: Some(config.clone()),
            address: Some(address),
        };
        *guard = Some(runtime);
        Ok(status)
    }

    pub async fn stop_node_runtime(&self) -> ChainResult<WalletNodeRuntimeStatus> {
        let mut guard = self.node_runtime.lock().await;
        let Some(runtime) = guard.take() else {
            let config = self.load_node_runtime_config()?;
            return Ok(WalletNodeRuntimeStatus {
                running: false,
                config,
                address: None,
            });
        };
        let config = runtime.config().clone();
        *self.node_handle.write() = None;
        runtime.shutdown().await?;
        Ok(WalletNodeRuntimeStatus {
            running: false,
            config: Some(config),
            address: None,
        })
    }

    pub fn node_runtime_running(&self) -> bool {
        self.node_handle.read().is_some()
    }

    pub fn node_runtime_handle(&self) -> Option<NodeHandle> {
        self.node_handle.read().clone()
    }

    pub fn node_runtime_status(&self) -> ChainResult<WalletNodeRuntimeStatus> {
        let config = self.load_node_runtime_config()?;
        if let Some(handle) = self.node_handle.read().clone() {
            return Ok(WalletNodeRuntimeStatus {
                running: true,
                config,
                address: Some(handle.address().to_string()),
            });
        }
        Ok(WalletNodeRuntimeStatus {
            running: false,
            config,
            address: None,
        })
    }

    pub fn persist_identity_workflow_state<T: Serialize>(&self, state: &T) -> ChainResult<()> {
        let encoded = serde_json::to_vec(state).map_err(|err| {
            ChainError::Config(format!(
                "failed to encode identity workflow state for persistence: {err}"
            ))
        })?;
        self.storage
            .write_metadata_blob(IDENTITY_WORKFLOW_KEY, encoded)
    }

    pub fn load_identity_workflow_state<T: DeserializeOwned>(&self) -> ChainResult<Option<T>> {
        let maybe_bytes = self.storage.read_metadata_blob(IDENTITY_WORKFLOW_KEY)?;
        match maybe_bytes {
            Some(bytes) => {
                let state = serde_json::from_slice(&bytes).map_err(|err| {
                    ChainError::Config(format!(
                        "failed to decode persisted identity workflow state: {err}"
                    ))
                })?;
                Ok(Some(state))
            }
            None => Ok(None),
        }
    }

    pub fn clear_identity_workflow_state(&self) -> ChainResult<()> {
        self.storage.delete_metadata_blob(IDENTITY_WORKFLOW_KEY)
    }

    fn persist_identity_vrf_keypair(&self, keypair: &VrfKeypair) -> ChainResult<()> {
        let stored = StoredVrfKeypair {
            public_key: vrf_public_key_to_hex(&keypair.public),
            secret_key: vrf_secret_key_to_hex(&keypair.secret),
        };
        let encoded = serde_json::to_vec(&stored).map_err(|err| {
            ChainError::Config(format!(
                "failed to encode VRF keypair for wallet persistence: {err}"
            ))
        })?;
        self.storage.write_metadata_blob(IDENTITY_VRF_KEY, encoded)
    }

    fn load_identity_vrf_keypair(&self) -> ChainResult<Option<VrfKeypair>> {
        let maybe_bytes = self.storage.read_metadata_blob(IDENTITY_VRF_KEY)?;
        let Some(bytes) = maybe_bytes else {
            return Ok(None);
        };
        let stored: StoredVrfKeypair = serde_json::from_slice(&bytes).map_err(|err| {
            ChainError::Config(format!(
                "failed to decode persisted VRF keypair for wallet: {err}"
            ))
        })?;
        let secret = vrf_secret_key_from_hex(&stored.secret_key)?;
        let public = vrf_public_key_from_hex(&stored.public_key)?;
        Ok(Some(VrfKeypair { public, secret }))
    }

    fn load_or_generate_identity_vrf_keypair(&self) -> ChainResult<VrfKeypair> {
        if let Some(keypair) = self.load_identity_vrf_keypair()? {
            return Ok(keypair);
        }
        let keypair = generate_vrf_keypair()?;
        self.persist_identity_vrf_keypair(&keypair)?;
        Ok(keypair)
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
        let vrf_keypair = self.load_or_generate_identity_vrf_keypair()?;
        let vrf = evaluate_vrf(&epoch_nonce, 0, &wallet_addr, 0, Some(&vrf_keypair.secret))?;
        let commitment_proof = ledger.identity_commitment_proof(&wallet_addr);
        let genesis = IdentityGenesis {
            wallet_pk,
            wallet_addr,
            vrf_public_key: vrf_public_key_to_hex(&vrf_keypair.public),
            vrf_proof: vrf.clone(),
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

    pub fn account_by_address(&self, address: &Address) -> ChainResult<Option<Account>> {
        self.storage.read_account(address)
    }

    pub fn accounts_snapshot(&self) -> ChainResult<Vec<Account>> {
        self.storage.load_accounts()
    }

    pub fn unspent_utxos(&self, owner: &Address) -> ChainResult<Vec<UtxoRecord>> {
        let accounts = self.storage.load_accounts()?;
        let ledger = Ledger::load(accounts, DEFAULT_EPOCH_LENGTH);
        let mut records = ledger.utxos_for_owner(owner);
        if records.is_empty() {
            if let Some(account) = ledger.get_account(owner) {
                records = synthetic_account_utxos(owner, account.balance);
            }
        }
        Ok(records)
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

    pub fn pipeline_dashboard(
        &self,
        orchestrator: &PipelineOrchestrator,
    ) -> PipelineDashboardSnapshot {
        let receiver = orchestrator.subscribe_dashboard();
        receiver.borrow().clone()
    }

    pub async fn wait_for_pipeline_stage(
        &self,
        orchestrator: &PipelineOrchestrator,
        hash: &str,
        stage: PipelineStage,
        timeout: Duration,
    ) -> ChainResult<()> {
        orchestrator.wait_for_stage(hash, stage, timeout).await
    }

    pub fn shutdown_pipeline(&self, orchestrator: &PipelineOrchestrator) {
        orchestrator.shutdown();
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
