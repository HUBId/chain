use std::collections::{HashMap, HashSet, VecDeque};
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use ed25519_dalek::Keypair;
use malachite::Natural;
use parking_lot::RwLock;
use tokio::time;
use tracing::{debug, info, warn};

use hex;
use serde::Serialize;
use serde_json;

use crate::config::{FeatureGates, GenesisAccount, NodeConfig, ReleaseChannel, TelemetryConfig};
use crate::consensus::{
    BftVote, BftVoteKind, ConsensusCertificate, ConsensusRound, EvidenceKind, EvidencePool,
    EvidenceRecord, SignedBftVote, ValidatorCandidate, aggregate_total_stake,
    classify_participants, evaluate_vrf,
};
use crate::crypto::{
    VrfKeypair, address_from_public_key, load_or_generate_keypair, load_or_generate_vrf_keypair,
    sign_message, signature_to_hex, vrf_public_key_to_hex,
};
use crate::errors::{ChainError, ChainResult};
use crate::ledger::{
    EpochInfo, Ledger, ReputationAudit, SlashingEvent, SlashingReason, VrfHistoryRecord,
};
#[cfg(feature = "backend-plonky3")]
use crate::plonky3::circuit::transaction::TransactionWitness as Plonky3TransactionWitness;
use crate::proof_system::{ProofProver, ProofVerifierRegistry};
use crate::reputation::Tier;
use crate::rpp::{ModuleWitnessBundle, ProofArtifact, ProofModule, TimetokeRecord};
use crate::state::lifecycle::StateLifecycle;
use crate::state::merkle::compute_merkle_root;
use crate::storage::{StateTransitionReceipt, Storage};
use crate::stwo::proof::ProofPayload;
use crate::stwo::prover::WalletProver;
use crate::sync::{PayloadProvider, ReconstructionEngine, ReconstructionPlan};
use crate::types::{
    Account, Address, Block, BlockHeader, BlockMetadata, BlockProofBundle, ChainProof,
    IdentityDeclaration, PruningProof, RecursiveProof, ReputationUpdate, SignedTransaction, Stake,
    TimetokeUpdate, TransactionProofBundle, UptimeProof,
};
use crate::vrf::{
    self, PoseidonVrfInput, VrfEpochManager, VrfProof, VrfSubmission, VrfSubmissionPool,
};
use rpp_p2p::NodeIdentity;
use stwo::core::vcs::blake2_hash::Blake2sHasher;

const BASE_BLOCK_REWARD: u64 = 5;
const LEADER_BONUS_PERCENT: u8 = 20;

#[derive(Clone, Copy)]
struct ChainTip {
    height: u64,
    last_hash: [u8; 32],
}

#[derive(Clone, Debug, Serialize)]
pub struct NodeStatus {
    pub address: Address,
    pub height: u64,
    pub last_hash: String,
    pub epoch: u64,
    pub epoch_nonce: String,
    pub pending_transactions: usize,
    pub pending_identities: usize,
    pub pending_votes: usize,
    pub pending_uptime_proofs: usize,
    pub vrf_metrics: crate::vrf::VrfSelectionMetrics,
    pub tip: Option<BlockMetadata>,
}

#[derive(Clone, Debug, Serialize)]
pub struct PendingTransactionSummary {
    pub hash: String,
    pub from: Address,
    pub to: Address,
    pub amount: u128,
    pub fee: u64,
    pub nonce: u64,
}

#[derive(Clone, Debug, Serialize)]
pub struct PendingIdentitySummary {
    pub wallet_addr: Address,
    pub commitment: String,
    pub epoch_nonce: String,
    pub state_root: String,
    pub identity_root: String,
    pub vrf_tag: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct PendingVoteSummary {
    pub hash: String,
    pub voter: Address,
    pub height: u64,
    pub round: u64,
    pub block_hash: String,
    pub kind: BftVoteKind,
}

#[derive(Clone, Debug, Serialize)]
pub struct MempoolStatus {
    pub transactions: Vec<PendingTransactionSummary>,
    pub identities: Vec<PendingIdentitySummary>,
    pub votes: Vec<PendingVoteSummary>,
    pub uptime_proofs: Vec<PendingUptimeSummary>,
}

#[derive(Clone, Debug, Serialize)]
pub struct PendingUptimeSummary {
    pub identity: Address,
    pub window_start: u64,
    pub window_end: u64,
    pub credited_hours: u64,
}

#[derive(Clone, Debug, Serialize)]
pub struct ConsensusStatus {
    pub height: u64,
    pub block_hash: Option<String>,
    pub proposer: Option<Address>,
    pub round: u64,
    pub total_power: String,
    pub quorum_threshold: String,
    pub pre_vote_power: String,
    pub pre_commit_power: String,
    pub commit_power: String,
    pub quorum_reached: bool,
    pub observers: u64,
    pub epoch: u64,
    pub epoch_nonce: String,
    pub pending_votes: usize,
}

#[derive(Clone, Debug, Serialize)]
pub struct VrfStatus {
    pub address: Address,
    pub epoch: u64,
    pub epoch_nonce: String,
    pub public_key: String,
    pub proof: crate::vrf::VrfProof,
}

#[derive(Clone, Debug, Serialize)]
pub struct ValidatorMembershipEntry {
    pub address: Address,
    pub stake: Stake,
    pub reputation_score: f64,
    pub tier: Tier,
    pub timetoke_hours: u64,
}

#[derive(Clone, Debug, Serialize)]
pub struct ObserverMembershipEntry {
    pub address: Address,
    pub tier: Tier,
}

#[derive(Clone, Debug, Serialize)]
pub struct BftMembership {
    pub height: u64,
    pub epoch: u64,
    pub epoch_nonce: String,
    pub validators: Vec<ValidatorMembershipEntry>,
    pub observers: Vec<ObserverMembershipEntry>,
}

#[derive(Clone, Debug, Serialize)]
pub struct BlockProofArtifactsView {
    pub hash: String,
    pub height: u64,
    pub pruning_proof: PruningProof,
    pub recursive_proof: RecursiveProof,
    pub stark: BlockProofBundle,
    pub module_witnesses: ModuleWitnessBundle,
    pub proof_artifacts: Vec<ProofArtifact>,
    pub consensus_proof: Option<ChainProof>,
    pub pruned: bool,
}

#[derive(Clone, Debug, Serialize)]
pub struct TelemetryRuntimeStatus {
    pub enabled: bool,
    pub endpoint: Option<String>,
    pub sample_interval_secs: u64,
    pub last_observed_height: Option<u64>,
}

#[derive(Clone, Debug, Serialize)]
pub struct RolloutStatus {
    pub release_channel: ReleaseChannel,
    pub feature_gates: FeatureGates,
    pub telemetry: TelemetryRuntimeStatus,
}

#[derive(Clone, Debug, Serialize)]
pub struct NodeTelemetrySnapshot {
    pub release_channel: ReleaseChannel,
    pub feature_gates: FeatureGates,
    pub node: NodeStatus,
    pub consensus: ConsensusStatus,
    pub mempool: MempoolStatus,
}

pub struct Node {
    inner: Arc<NodeInner>,
}

struct NodeInner {
    config: NodeConfig,
    keypair: Keypair,
    vrf_keypair: VrfKeypair,
    p2p_identity: Arc<NodeIdentity>,
    address: Address,
    storage: Storage,
    ledger: Ledger,
    mempool: RwLock<VecDeque<TransactionProofBundle>>,
    identity_mempool: RwLock<VecDeque<IdentityDeclaration>>,
    uptime_mempool: RwLock<VecDeque<RecordedUptimeProof>>,
    vrf_mempool: RwLock<VrfSubmissionPool>,
    vrf_epoch: RwLock<VrfEpochManager>,
    chain_tip: RwLock<ChainTip>,
    block_interval: Duration,
    vote_mempool: RwLock<VecDeque<SignedBftVote>>,
    proposal_inbox: RwLock<HashMap<(u64, Address), VerifiedProposal>>,
    evidence_pool: RwLock<EvidencePool>,
    telemetry_last_height: RwLock<Option<u64>>,
    vrf_metrics: RwLock<crate::vrf::VrfSelectionMetrics>,
    verifiers: ProofVerifierRegistry,
}

#[derive(Clone)]
pub struct NodeHandle {
    inner: Arc<NodeInner>,
}

#[derive(Clone)]
struct RecordedUptimeProof {
    proof: UptimeProof,
    credited_hours: u64,
}

#[derive(Clone)]
struct VerifiedProposal {
    block: Block,
}

impl Node {
    pub fn new(config: NodeConfig) -> ChainResult<Self> {
        config.ensure_directories()?;
        let keypair = load_or_generate_keypair(&config.key_path)?;
        let vrf_keypair = load_or_generate_vrf_keypair(&config.vrf_key_path)?;
        let p2p_identity = Arc::new(
            NodeIdentity::load_or_generate(&config.p2p_key_path)
                .map_err(|err| ChainError::Config(format!("unable to load p2p identity: {err}")))?,
        );
        let address = address_from_public_key(&keypair.public);
        let db_path = config.data_dir.join("db");
        let storage = Storage::open(&db_path)?;
        let mut accounts = storage.load_accounts()?;
        let mut tip_metadata = storage.tip()?;
        if tip_metadata.is_none() {
            let genesis_accounts = if config.genesis.accounts.is_empty() {
                vec![GenesisAccount {
                    address: address.clone(),
                    balance: 1_000_000_000,
                    stake: "1000".to_string(),
                }]
            } else {
                config.genesis.accounts.clone()
            };
            accounts = build_genesis_accounts(genesis_accounts)?;
            for account in &accounts {
                storage.persist_account(account)?;
            }
            let ledger = Ledger::load(accounts.clone(), config.epoch_length);
            let module_witnesses = ledger.drain_module_witnesses();
            let module_artifacts = ledger.stage_module_witnesses(&module_witnesses)?;
            let mut tx_hashes: Vec<[u8; 32]> = Vec::new();
            let tx_root = compute_merkle_root(&mut tx_hashes);
            let commitments = ledger.global_commitments();
            let state_root_hex = hex::encode(commitments.global_state_root);
            let stakes = ledger.stake_snapshot();
            let total_stake = aggregate_total_stake(&stakes);
            let genesis_seed = [0u8; 32];
            let vrf = evaluate_vrf(&genesis_seed, 0, &address, 0, Some(&vrf_keypair.secret));
            let header = BlockHeader::new(
                0,
                hex::encode([0u8; 32]),
                hex::encode(tx_root),
                state_root_hex.clone(),
                hex::encode(commitments.utxo_root),
                hex::encode(commitments.reputation_root),
                hex::encode(commitments.timetoke_root),
                hex::encode(commitments.zsi_root),
                hex::encode(commitments.proof_root),
                total_stake.to_string(),
                vrf.randomness.to_string(),
                vrf_public_key_to_hex(&vrf_keypair.public),
                vrf.proof.clone(),
                address.clone(),
                Tier::Tl5.to_string(),
                0,
            );
            let pruning_proof = PruningProof::genesis(&state_root_hex);
            let recursive_proof = RecursiveProof::genesis(&header, &pruning_proof);
            let prover = WalletProver::new(&storage);
            let transactions: Vec<SignedTransaction> = Vec::new();
            let transaction_proofs: Vec<ChainProof> = Vec::new();
            let identity_proofs: Vec<ChainProof> = Vec::new();
            let state_witness = prover.build_state_witness(
                &pruning_proof.previous_state_root,
                &header.state_root,
                &Vec::new(),
                &transactions,
            )?;
            let state_proof = prover.prove_state_transition(state_witness)?;
            let pruning_witness = prover.build_pruning_witness(
                &Vec::new(),
                &transactions,
                &pruning_proof,
                Vec::new(),
            )?;
            let pruning_stark = prover.prove_pruning(pruning_witness)?;
            let recursive_witness = prover.build_recursive_witness(
                None,
                &identity_proofs,
                &transaction_proofs,
                &[],
                &[],
                &commitments,
                &state_proof,
                &pruning_stark,
                header.height,
            )?;
            let recursive_stark = prover.prove_recursive(recursive_witness)?;
            let stark_bundle = BlockProofBundle::new(
                transaction_proofs,
                state_proof,
                pruning_stark,
                recursive_stark,
            );
            let mut proof_artifacts =
                NodeInner::collect_proof_artifacts(&stark_bundle, config.max_proof_size_bytes)?;
            proof_artifacts.extend(module_artifacts);
            let signature = sign_message(&keypair, &header.canonical_bytes());
            let consensus_certificate = ConsensusCertificate::genesis();
            let genesis_block = Block::new(
                header,
                Vec::new(),
                Vec::new(),
                Vec::new(),
                Vec::new(),
                Vec::new(),
                Vec::new(),
                module_witnesses,
                proof_artifacts,
                pruning_proof,
                recursive_proof,
                stark_bundle,
                signature,
                consensus_certificate,
                None,
            );
            genesis_block.verify(None)?;
            let genesis_metadata = BlockMetadata::from(&genesis_block);
            storage.store_block(&genesis_block, &genesis_metadata)?;
            tip_metadata = Some(genesis_metadata);
        }

        if accounts.is_empty() {
            accounts = storage.load_accounts()?;
        }

        let ledger = Ledger::load(accounts, config.epoch_length);

        let node_pk_hex = hex::encode(keypair.public.to_bytes());
        if ledger.get_account(&address).is_none() {
            let mut account = Account::new(address.clone(), 0, Stake::default());
            let _ = account.ensure_wallet_binding(&node_pk_hex)?;
            ledger.upsert_account(account)?;
        }
        ledger.ensure_node_binding(&address, &node_pk_hex)?;

        let next_height = tip_metadata
            .as_ref()
            .map(|meta| meta.height.saturating_add(1))
            .unwrap_or(0);
        ledger.sync_epoch_for_height(next_height);
        let epoch_manager = VrfEpochManager::new(config.epoch_length, ledger.current_epoch());

        let inner = Arc::new(NodeInner {
            block_interval: Duration::from_millis(config.block_time_ms),
            config,
            keypair,
            vrf_keypair,
            p2p_identity,
            address,
            storage,
            ledger,
            mempool: RwLock::new(VecDeque::new()),
            identity_mempool: RwLock::new(VecDeque::new()),
            uptime_mempool: RwLock::new(VecDeque::new()),
            vrf_mempool: RwLock::new(VrfSubmissionPool::new()),
            vrf_epoch: RwLock::new(epoch_manager),
            chain_tip: RwLock::new(ChainTip {
                height: 0,
                last_hash: [0u8; 32],
            }),
            vote_mempool: RwLock::new(VecDeque::new()),
            proposal_inbox: RwLock::new(HashMap::new()),
            evidence_pool: RwLock::new(EvidencePool::default()),
            telemetry_last_height: RwLock::new(None),
            vrf_metrics: RwLock::new(crate::vrf::VrfSelectionMetrics::default()),
            verifiers: ProofVerifierRegistry::default(),
        });
        debug!(peer_id = %inner.p2p_identity.peer_id(), "libp2p identity initialised");
        inner.bootstrap()?;
        Ok(Self { inner })
    }

    pub fn handle(&self) -> NodeHandle {
        NodeHandle {
            inner: self.inner.clone(),
        }
    }

    pub async fn start(self) -> ChainResult<()> {
        self.inner.clone().run().await
    }
}

impl NodeHandle {
    pub fn submit_transaction(&self, bundle: TransactionProofBundle) -> ChainResult<String> {
        self.inner.submit_transaction(bundle)
    }

    pub fn submit_identity(&self, declaration: IdentityDeclaration) -> ChainResult<String> {
        self.inner.submit_identity(declaration)
    }

    pub fn submit_vote(&self, vote: SignedBftVote) -> ChainResult<String> {
        self.inner.submit_vote(vote)
    }

    pub fn submit_block_proposal(&self, block: Block) -> ChainResult<String> {
        self.inner.submit_block_proposal(block)
    }

    pub fn submit_vrf_submission(&self, submission: VrfSubmission) -> ChainResult<()> {
        self.inner.submit_vrf_submission(submission)
    }

    pub fn submit_uptime_proof(&self, proof: UptimeProof) -> ChainResult<u64> {
        self.inner.submit_uptime_proof(proof)
    }

    pub fn get_block(&self, height: u64) -> ChainResult<Option<Block>> {
        self.inner.get_block(height)
    }

    pub fn latest_block(&self) -> ChainResult<Option<Block>> {
        self.inner.latest_block()
    }

    pub fn get_account(&self, address: &str) -> ChainResult<Option<Account>> {
        self.inner.get_account(address)
    }

    pub fn node_status(&self) -> ChainResult<NodeStatus> {
        self.inner.node_status()
    }

    pub fn mempool_status(&self) -> ChainResult<MempoolStatus> {
        self.inner.mempool_status()
    }

    pub fn rollout_status(&self) -> RolloutStatus {
        self.inner.rollout_status()
    }

    pub fn consensus_status(&self) -> ChainResult<ConsensusStatus> {
        self.inner.consensus_status()
    }

    pub fn vrf_status(&self, address: &str) -> ChainResult<VrfStatus> {
        self.inner.vrf_status(address)
    }

    pub fn vrf_history(&self, epoch: Option<u64>) -> ChainResult<Vec<VrfHistoryRecord>> {
        self.inner.vrf_history(epoch)
    }

    pub fn slashing_events(&self, limit: usize) -> ChainResult<Vec<SlashingEvent>> {
        self.inner.slashing_events(limit)
    }

    pub fn reputation_audit(&self, address: &str) -> ChainResult<Option<ReputationAudit>> {
        self.inner.reputation_audit(address)
    }

    pub fn bft_membership(&self) -> ChainResult<BftMembership> {
        self.inner.bft_membership()
    }

    pub fn timetoke_snapshot(&self) -> ChainResult<Vec<TimetokeRecord>> {
        self.inner.timetoke_snapshot()
    }

    pub fn sync_timetoke_records(&self, records: Vec<TimetokeRecord>) -> ChainResult<Vec<Address>> {
        self.inner.sync_timetoke_records(records)
    }

    pub fn address(&self) -> &str {
        &self.inner.address
    }

    pub fn storage(&self) -> Storage {
        self.inner.storage.clone()
    }

    pub fn state_root(&self) -> ChainResult<String> {
        Ok(hex::encode(self.inner.ledger.state_root()))
    }

    pub fn block_proofs(&self, height: u64) -> ChainResult<Option<BlockProofArtifactsView>> {
        self.inner.block_proofs(height)
    }

    pub fn telemetry_snapshot(&self) -> ChainResult<NodeTelemetrySnapshot> {
        self.inner.telemetry_snapshot()
    }

    pub fn reconstruction_plan(&self, start_height: u64) -> ChainResult<ReconstructionPlan> {
        self.inner.reconstruction_plan(start_height)
    }

    pub fn verify_proof_chain(&self) -> ChainResult<()> {
        self.inner.verify_proof_chain()
    }

    pub fn reconstruct_block<P: PayloadProvider>(
        &self,
        height: u64,
        provider: &P,
    ) -> ChainResult<Block> {
        self.inner.reconstruct_block(height, provider)
    }

    pub fn reconstruct_range<P: PayloadProvider>(
        &self,
        start_height: u64,
        end_height: u64,
        provider: &P,
    ) -> ChainResult<Vec<Block>> {
        self.inner
            .reconstruct_range(start_height, end_height, provider)
    }

    pub fn execute_reconstruction_plan<P: PayloadProvider>(
        &self,
        plan: &ReconstructionPlan,
        provider: &P,
    ) -> ChainResult<Vec<Block>> {
        self.inner.execute_reconstruction_plan(plan, provider)
    }
}

impl NodeInner {
    async fn run(self: Arc<Self>) -> ChainResult<()> {
        info!(
            address = %self.address,
            channel = ?self.config.rollout.release_channel,
            ?self.config.rollout.feature_gates,
            telemetry_enabled = self.config.rollout.telemetry.enabled,
            "starting node"
        );
        if self.config.rollout.telemetry.enabled {
            let config = self.config.rollout.telemetry.clone();
            let worker = self.clone();
            tokio::spawn(async move {
                worker.telemetry_loop(config).await;
            });
        }
        let mut ticker = time::interval(self.block_interval);
        loop {
            ticker.tick().await;
            if let Err(err) = self.produce_block() {
                warn!(?err, "block production failed");
            }
        }
    }

    async fn telemetry_loop(self: Arc<Self>, config: TelemetryConfig) {
        let interval = Duration::from_secs(config.sample_interval_secs.max(1));
        let mut ticker = time::interval(interval);
        loop {
            ticker.tick().await;
            if let Err(err) = self.emit_telemetry(&config) {
                warn!(?err, "failed to emit telemetry snapshot");
            }
        }
    }

    fn emit_telemetry(&self, config: &TelemetryConfig) -> ChainResult<()> {
        let snapshot = self.build_telemetry_snapshot()?;
        let encoded = serde_json::to_string(&snapshot).map_err(|err| {
            ChainError::Config(format!("unable to encode telemetry snapshot: {err}"))
        })?;
        if let Some(endpoint) = &config.endpoint {
            if endpoint.is_empty() {
                info!(target = "telemetry", payload = %encoded, "telemetry snapshot");
            } else {
                info!(
                    target = "telemetry",
                    ?endpoint,
                    payload = %encoded,
                    "telemetry snapshot dispatched"
                );
            }
        } else {
            info!(target = "telemetry", payload = %encoded, "telemetry snapshot");
        }
        *self.telemetry_last_height.write() = Some(snapshot.node.height);
        Ok(())
    }

    fn telemetry_snapshot(&self) -> ChainResult<NodeTelemetrySnapshot> {
        self.build_telemetry_snapshot()
    }

    fn build_telemetry_snapshot(&self) -> ChainResult<NodeTelemetrySnapshot> {
        let node = self.node_status()?;
        let consensus = self.consensus_status()?;
        let mempool = self.mempool_status()?;
        Ok(NodeTelemetrySnapshot {
            release_channel: self.config.rollout.release_channel,
            feature_gates: self.config.rollout.feature_gates.clone(),
            node,
            consensus,
            mempool,
        })
    }

    fn block_proofs(&self, height: u64) -> ChainResult<Option<BlockProofArtifactsView>> {
        let stored = self.storage.read_block_record(height)?;
        Ok(stored.map(|record| {
            let envelope = record.envelope;
            BlockProofArtifactsView {
                hash: envelope.hash.clone(),
                height,
                pruning_proof: envelope.pruning_proof.clone(),
                recursive_proof: envelope.recursive_proof.clone(),
                stark: envelope.stark.clone(),
                module_witnesses: envelope.module_witnesses.clone(),
                proof_artifacts: envelope.proof_artifacts.clone(),
                consensus_proof: envelope.consensus_proof.clone(),
                pruned: envelope.pruned,
            }
        }))
    }

    fn bft_membership(&self) -> ChainResult<BftMembership> {
        let accounts_snapshot = self.ledger.accounts_snapshot();
        let (validators, observers) = classify_participants(&accounts_snapshot);
        let validator_entries = validators
            .into_iter()
            .map(|candidate| ValidatorMembershipEntry {
                address: candidate.address,
                stake: candidate.stake,
                reputation_score: candidate.reputation_score,
                tier: candidate.tier,
                timetoke_hours: candidate.timetoke_hours,
            })
            .collect();
        let observer_entries = observers
            .into_iter()
            .map(|observer| ObserverMembershipEntry {
                address: observer.address,
                tier: observer.tier,
            })
            .collect();
        let epoch_info = self.ledger.epoch_info();
        let node_status = self.node_status()?;
        Ok(BftMembership {
            height: node_status.height,
            epoch: epoch_info.epoch,
            epoch_nonce: epoch_info.epoch_nonce,
            validators: validator_entries,
            observers: observer_entries,
        })
    }

    fn reconstruction_plan(&self, start_height: u64) -> ChainResult<ReconstructionPlan> {
        if !self.config.rollout.feature_gates.reconstruction {
            return Err(ChainError::Config(
                "reconstruction feature gate disabled".into(),
            ));
        }
        let engine = ReconstructionEngine::with_snapshot_dir(
            self.storage.clone(),
            self.config.snapshot_dir.clone(),
        );
        let plan = engine.plan_from_height(start_height)?;
        if let Some(path) = engine.persist_plan(&plan)? {
            info!(?path, "persisted reconstruction plan snapshot");
        }
        Ok(plan)
    }

    fn verify_proof_chain(&self) -> ChainResult<()> {
        if !self.config.rollout.feature_gates.recursive_proofs {
            return Err(ChainError::Config(
                "recursive proof verification disabled by rollout".into(),
            ));
        }
        let engine = ReconstructionEngine::new(self.storage.clone());
        engine.verify_proof_chain()
    }

    fn reconstruct_block<P: PayloadProvider>(
        &self,
        height: u64,
        provider: &P,
    ) -> ChainResult<Block> {
        if !self.config.rollout.feature_gates.reconstruction {
            return Err(ChainError::Config(
                "reconstruction feature gate disabled".into(),
            ));
        }
        let engine = ReconstructionEngine::new(self.storage.clone());
        engine.reconstruct_block(height, provider)
    }

    fn reconstruct_range<P: PayloadProvider>(
        &self,
        start_height: u64,
        end_height: u64,
        provider: &P,
    ) -> ChainResult<Vec<Block>> {
        if !self.config.rollout.feature_gates.reconstruction {
            return Err(ChainError::Config(
                "reconstruction feature gate disabled".into(),
            ));
        }
        let engine = ReconstructionEngine::new(self.storage.clone());
        engine.reconstruct_range(start_height, end_height, provider)
    }

    fn execute_reconstruction_plan<P: PayloadProvider>(
        &self,
        plan: &ReconstructionPlan,
        provider: &P,
    ) -> ChainResult<Vec<Block>> {
        if !self.config.rollout.feature_gates.reconstruction {
            return Err(ChainError::Config(
                "reconstruction feature gate disabled".into(),
            ));
        }
        let engine = ReconstructionEngine::new(self.storage.clone());
        engine.execute_plan(plan, provider)
    }

    fn submit_transaction(&self, bundle: TransactionProofBundle) -> ChainResult<String> {
        bundle.transaction.verify()?;
        if self.config.rollout.feature_gates.recursive_proofs {
            self.verifiers.verify_transaction(&bundle.proof)?;
            Self::ensure_transaction_payload(&bundle.proof, &bundle.transaction)?;
        }
        let mut mempool = self.mempool.write();
        if mempool.len() >= self.config.mempool_limit {
            return Err(ChainError::Transaction("mempool full".into()));
        }
        let tx_hash = bundle.hash();
        if mempool
            .iter()
            .any(|existing| existing.transaction.id == bundle.transaction.id)
        {
            return Err(ChainError::Transaction("transaction already queued".into()));
        }
        mempool.push_back(bundle);
        Ok(tx_hash)
    }

    fn ensure_transaction_payload(
        proof: &ChainProof,
        expected: &SignedTransaction,
    ) -> ChainResult<()> {
        match proof {
            ChainProof::Stwo(stark) => match &stark.payload {
                ProofPayload::Transaction(witness) if &witness.signed_tx == expected => Ok(()),
                ProofPayload::Transaction(_) => Err(ChainError::Crypto(
                    "transaction proof does not match submitted transaction".into(),
                )),
                _ => Err(ChainError::Crypto(
                    "transaction proof payload mismatch".into(),
                )),
            },
            #[cfg(feature = "backend-plonky3")]
            ChainProof::Plonky3(value) => {
                let witness_value = value.get("witness").cloned().ok_or_else(|| {
                    ChainError::Crypto("plonky3 transaction proof missing witness payload".into())
                })?;
                let witness: Plonky3TransactionWitness = serde_json::from_value(witness_value)
                    .map_err(|err| {
                        ChainError::Crypto(format!(
                            "failed to decode plonky3 transaction witness: {err}"
                        ))
                    })?;
                if &witness.transaction == expected {
                    Ok(())
                } else {
                    Err(ChainError::Crypto(
                        "transaction proof does not match submitted transaction".into(),
                    ))
                }
            }
        }
    }

    fn submit_identity(&self, declaration: IdentityDeclaration) -> ChainResult<String> {
        let next_height = self.chain_tip.read().height.saturating_add(1);
        self.ledger.sync_epoch_for_height(next_height);
        if self.config.rollout.feature_gates.recursive_proofs {
            self.verifiers
                .verify_identity(&declaration.proof.zk_proof)?;
        }
        declaration.verify()?;

        let expected_epoch_nonce = hex::encode(self.ledger.current_epoch_nonce());
        if expected_epoch_nonce != declaration.genesis.epoch_nonce {
            return Err(ChainError::Transaction(
                "identity declaration references an outdated epoch nonce".into(),
            ));
        }

        let expected_state_root = hex::encode(self.ledger.state_root());
        if expected_state_root != declaration.genesis.state_root {
            return Err(ChainError::Transaction(
                "identity declaration references an outdated state root".into(),
            ));
        }
        let expected_identity_root = hex::encode(self.ledger.identity_root());
        if expected_identity_root != declaration.genesis.identity_root {
            return Err(ChainError::Transaction(
                "identity declaration references an outdated identity root".into(),
            ));
        }

        let hash = hex::encode(declaration.hash()?);
        let mut mempool = self.identity_mempool.write();
        if mempool.len() >= self.config.mempool_limit {
            return Err(ChainError::Transaction("identity mempool full".into()));
        }
        if mempool
            .iter()
            .any(|existing| existing.genesis.wallet_addr == declaration.genesis.wallet_addr)
        {
            return Err(ChainError::Transaction(
                "identity for this wallet already queued".into(),
            ));
        }
        mempool.push_back(declaration);
        Ok(hash)
    }

    fn submit_vote(&self, vote: SignedBftVote) -> ChainResult<String> {
        if self.config.rollout.feature_gates.consensus_enforcement {
            vote.verify()?;
        }
        let next_height = self.chain_tip.read().height.saturating_add(1);
        if vote.vote.height < next_height {
            return Err(ChainError::Transaction(
                "vote references an already finalized height".into(),
            ));
        }
        if let Some(evidence) = self.evidence_pool.write().record_vote(&vote) {
            self.apply_evidence(evidence);
            return Err(ChainError::Transaction(
                "conflicting vote detected for validator".into(),
            ));
        }
        let mut mempool = self.vote_mempool.write();
        if mempool.len() >= self.config.mempool_limit {
            return Err(ChainError::Transaction("vote mempool full".into()));
        }
        let vote_hash = vote.hash();
        if mempool.iter().any(|existing| existing.hash() == vote_hash) {
            return Err(ChainError::Transaction("vote already queued".into()));
        }
        mempool.push_back(vote);
        Ok(vote_hash)
    }

    fn submit_block_proposal(&self, block: Block) -> ChainResult<String> {
        let height = block.header.height;
        let round = block.consensus.round;
        let proposer = block.header.proposer.clone();
        let previous_block = if height == 0 {
            None
        } else {
            self.storage.read_block(height - 1)?
        };
        match block.verify_without_stark(previous_block.as_ref()) {
            Ok(()) => {
                let hash = block.hash.clone();
                let mut inbox = self.proposal_inbox.write();
                inbox.insert((height, proposer), VerifiedProposal { block });
                Ok(hash)
            }
            Err(err) => {
                let evidence = self.evidence_pool.write().record_invalid_proposal(
                    &proposer,
                    height,
                    round,
                    Some(block.hash.clone()),
                );
                self.apply_evidence(evidence);
                Err(err)
            }
        }
    }

    fn apply_evidence(&self, evidence: EvidenceRecord) {
        let (reason, reason_label) = match evidence.kind {
            EvidenceKind::DoubleSignPrevote | EvidenceKind::DoubleSignPrecommit => {
                (SlashingReason::ConsensusFault, "double-sign")
            }
            EvidenceKind::InvalidProof => (SlashingReason::InvalidVote, "invalid-proof"),
            EvidenceKind::InvalidProposal => (SlashingReason::ConsensusFault, "invalid-proposal"),
        };
        if let Err(err) = self.ledger.slash_validator(&evidence.address, reason) {
            warn!(
                address = %evidence.address,
                ?err,
                reason = reason_label,
                "failed to apply slashing evidence"
            );
            return;
        }
        debug!(
            address = %evidence.address,
            height = evidence.height,
            round = evidence.round,
            reason = reason_label,
            "recorded consensus evidence"
        );
        if let Some(vote_kind) = evidence.vote_kind {
            let mut mempool = self.vote_mempool.write();
            mempool.retain(|vote| {
                !(vote.vote.voter == evidence.address
                    && vote.vote.height == evidence.height
                    && vote.vote.round == evidence.round
                    && vote.vote.kind == vote_kind)
            });
        }
    }

    fn submit_vrf_submission(&self, submission: VrfSubmission) -> ChainResult<()> {
        let address = submission.address.clone();
        let epoch = submission.input.epoch;
        {
            let mut epoch_manager = self.vrf_epoch.write();
            if !epoch_manager.register_submission(&submission) {
                debug!(address = %address, epoch, "duplicate VRF submission ignored");
                return Ok(());
            }
        }
        let mut pool = self.vrf_mempool.write();
        if let Some(existing) = pool.get(&address) {
            if existing.input != submission.input {
                debug!(
                    address = %address,
                    prev_epoch = existing.input.epoch,
                    new_epoch = epoch,
                    "updated VRF submission"
                );
            }
        } else {
            debug!(address = %address, epoch, "recorded VRF submission");
        }
        vrf::submit_vrf(&mut pool, submission);
        Ok(())
    }

    fn submit_uptime_proof(&self, proof: UptimeProof) -> ChainResult<u64> {
        let credited = self.ledger.apply_uptime_proof(&proof)?;
        if let Some(account) = self.ledger.get_account(&proof.wallet_address) {
            self.storage.persist_account(&account)?;
        }
        {
            let mut queue = self.uptime_mempool.write();
            queue.push_back(RecordedUptimeProof {
                proof: proof.clone(),
                credited_hours: credited,
            });
        }
        Ok(credited)
    }

    fn timetoke_snapshot(&self) -> ChainResult<Vec<TimetokeRecord>> {
        let records = self.ledger.timetoke_snapshot();
        for record in &records {
            if let Some(account) = self.ledger.get_account(&record.identity) {
                self.storage.persist_account(&account)?;
            }
        }
        Ok(records)
    }

    fn sync_timetoke_records(&self, records: Vec<TimetokeRecord>) -> ChainResult<Vec<Address>> {
        let updated = self.ledger.sync_timetoke_records(&records)?;
        for address in &updated {
            if let Some(account) = self.ledger.get_account(address) {
                self.storage.persist_account(&account)?;
            }
        }
        Ok(updated)
    }

    fn get_block(&self, height: u64) -> ChainResult<Option<Block>> {
        self.storage.read_block(height)
    }

    fn latest_block(&self) -> ChainResult<Option<Block>> {
        let tip_height = self.chain_tip.read().height;
        self.storage.read_block(tip_height)
    }

    fn get_account(&self, address: &str) -> ChainResult<Option<Account>> {
        Ok(self.ledger.get_account(address))
    }

    fn node_status(&self) -> ChainResult<NodeStatus> {
        let tip = *self.chain_tip.read();
        let epoch_info: EpochInfo = self.ledger.epoch_info();
        let metadata = self.storage.tip()?;
        Ok(NodeStatus {
            address: self.address.clone(),
            height: tip.height,
            last_hash: hex::encode(tip.last_hash),
            epoch: epoch_info.epoch,
            epoch_nonce: epoch_info.epoch_nonce,
            pending_transactions: self.mempool.read().len(),
            pending_identities: self.identity_mempool.read().len(),
            pending_votes: self.vote_mempool.read().len(),
            pending_uptime_proofs: self.uptime_mempool.read().len(),
            vrf_metrics: self.vrf_metrics.read().clone(),
            tip: metadata,
        })
    }

    fn mempool_status(&self) -> ChainResult<MempoolStatus> {
        let transactions = self
            .mempool
            .read()
            .iter()
            .map(|bundle| PendingTransactionSummary {
                hash: bundle.hash(),
                from: bundle.transaction.payload.from.clone(),
                to: bundle.transaction.payload.to.clone(),
                amount: bundle.transaction.payload.amount,
                fee: bundle.transaction.payload.fee,
                nonce: bundle.transaction.payload.nonce,
            })
            .collect();
        let identities = self
            .identity_mempool
            .read()
            .iter()
            .map(|declaration| PendingIdentitySummary {
                wallet_addr: declaration.genesis.wallet_addr.clone(),
                commitment: declaration.commitment().to_string(),
                epoch_nonce: declaration.genesis.epoch_nonce.clone(),
                state_root: declaration.genesis.state_root.clone(),
                identity_root: declaration.genesis.identity_root.clone(),
                vrf_tag: declaration.genesis.vrf_tag.clone(),
            })
            .collect();
        let votes = self
            .vote_mempool
            .read()
            .iter()
            .map(|vote| PendingVoteSummary {
                hash: vote.hash(),
                voter: vote.vote.voter.clone(),
                height: vote.vote.height,
                round: vote.vote.round,
                block_hash: vote.vote.block_hash.clone(),
                kind: vote.vote.kind,
            })
            .collect();
        let uptime_proofs = self
            .uptime_mempool
            .read()
            .iter()
            .map(|record| PendingUptimeSummary {
                identity: record.proof.wallet_address.clone(),
                window_start: record.proof.window_start,
                window_end: record.proof.window_end,
                credited_hours: record.credited_hours,
            })
            .collect();
        Ok(MempoolStatus {
            transactions,
            identities,
            votes,
            uptime_proofs,
        })
    }

    fn rollout_status(&self) -> RolloutStatus {
        RolloutStatus {
            release_channel: self.config.rollout.release_channel,
            feature_gates: self.config.rollout.feature_gates.clone(),
            telemetry: TelemetryRuntimeStatus {
                enabled: self.config.rollout.telemetry.enabled,
                endpoint: self.config.rollout.telemetry.endpoint.clone(),
                sample_interval_secs: self.config.rollout.telemetry.sample_interval_secs,
                last_observed_height: *self.telemetry_last_height.read(),
            },
        }
    }

    fn consensus_status(&self) -> ChainResult<ConsensusStatus> {
        let tip = *self.chain_tip.read();
        let block = self.storage.read_block(tip.height)?;
        let epoch_info = self.ledger.epoch_info();
        let pending_votes = self.vote_mempool.read().len();
        let (
            block_hash,
            proposer,
            round,
            total_power,
            quorum_threshold,
            pre_vote_power,
            pre_commit_power,
            commit_power,
            observers,
            quorum_reached,
        ) = if let Some(block) = block.as_ref() {
            let certificate = &block.consensus;
            let commit = Natural::from_str(&certificate.commit_power)
                .unwrap_or_else(|_| Natural::from(0u32));
            let quorum = Natural::from_str(&certificate.quorum_threshold)
                .unwrap_or_else(|_| Natural::from(0u32));
            (
                Some(block.hash.clone()),
                Some(block.header.proposer.clone()),
                certificate.round,
                certificate.total_power.clone(),
                certificate.quorum_threshold.clone(),
                certificate.pre_vote_power.clone(),
                certificate.pre_commit_power.clone(),
                certificate.commit_power.clone(),
                certificate.observers,
                commit >= quorum && commit > Natural::from(0u32),
            )
        } else {
            (
                None,
                None,
                0,
                "0".to_string(),
                "0".to_string(),
                "0".to_string(),
                "0".to_string(),
                "0".to_string(),
                0,
                false,
            )
        };

        Ok(ConsensusStatus {
            height: tip.height,
            block_hash,
            proposer,
            round,
            total_power,
            quorum_threshold,
            pre_vote_power,
            pre_commit_power,
            commit_power,
            quorum_reached,
            observers,
            epoch: epoch_info.epoch,
            epoch_nonce: epoch_info.epoch_nonce,
            pending_votes,
        })
    }

    fn vrf_status(&self, address: &str) -> ChainResult<VrfStatus> {
        let epoch_info = self.ledger.epoch_info();
        let nonce = self.ledger.current_epoch_nonce();
        let proof = evaluate_vrf(
            &nonce,
            0,
            &address.to_string(),
            0,
            Some(&self.vrf_keypair.secret),
        );
        Ok(VrfStatus {
            address: address.to_string(),
            epoch: epoch_info.epoch,
            epoch_nonce: epoch_info.epoch_nonce,
            public_key: vrf_public_key_to_hex(&self.vrf_keypair.public),
            proof,
        })
    }

    fn vrf_history(&self, epoch: Option<u64>) -> ChainResult<Vec<VrfHistoryRecord>> {
        Ok(self.ledger.vrf_history(epoch))
    }

    fn slashing_events(&self, limit: usize) -> ChainResult<Vec<SlashingEvent>> {
        Ok(self.ledger.slashing_events(limit))
    }

    fn reputation_audit(&self, address: &str) -> ChainResult<Option<ReputationAudit>> {
        self.ledger.reputation_audit(address)
    }

    fn build_local_vote(
        &self,
        height: u64,
        round: u64,
        block_hash: &str,
        kind: BftVoteKind,
    ) -> SignedBftVote {
        let vote = BftVote {
            round,
            height,
            block_hash: block_hash.to_string(),
            voter: self.address.clone(),
            kind,
        };
        let signature = sign_message(&self.keypair, &vote.message_bytes());
        SignedBftVote {
            vote,
            public_key: hex::encode(self.keypair.public.to_bytes()),
            signature: signature_to_hex(&signature),
        }
    }

    fn gather_vrf_submissions(
        &self,
        epoch: u64,
        seed: [u8; 32],
        candidates: &[ValidatorCandidate],
    ) -> VrfSubmissionPool {
        let candidate_addresses: HashSet<Address> = candidates
            .iter()
            .map(|candidate| candidate.address.clone())
            .collect();
        let mut pool = {
            let mut mempool = self.vrf_mempool.write();
            mempool.retain(|address, submission| {
                submission.input.epoch == epoch
                    && submission.input.last_block_header == seed
                    && candidate_addresses.contains(address)
            });
            mempool.clone()
        };

        for candidate in candidates {
            if candidate.address != self.address {
                continue;
            }
            let tier_seed = vrf::derive_tier_seed(&candidate.address, candidate.timetoke_hours);
            let input = PoseidonVrfInput::new(seed, epoch, tier_seed);
            match vrf::generate_vrf(&input, &self.vrf_keypair.secret) {
                Ok(output) => {
                    let submission = VrfSubmission {
                        address: candidate.address.clone(),
                        public_key: Some(self.vrf_keypair.public.clone()),
                        input,
                        proof: VrfProof::from_output(&output),
                        tier: candidate.tier.clone(),
                        timetoke_hours: candidate.timetoke_hours,
                    };
                    vrf::submit_vrf(&mut pool, submission.clone());
                    if let Err(err) = self.submit_vrf_submission(submission) {
                        warn!(
                            address = %candidate.address,
                            ?err,
                            "failed to persist local VRF submission"
                        );
                    }
                }
                Err(err) => {
                    warn!(
                        address = %candidate.address,
                        ?err,
                        "failed to produce local VRF submission"
                    );
                }
            }
        }
        pool
    }

    fn drain_votes_for(&self, height: u64, block_hash: &str) -> Vec<SignedBftVote> {
        let mut mempool = self.vote_mempool.write();
        let mut retained = VecDeque::new();
        let mut matched = Vec::new();
        while let Some(vote) = mempool.pop_front() {
            if vote.vote.height == height && vote.vote.block_hash == block_hash {
                matched.push(vote);
            } else {
                retained.push_back(vote);
            }
        }
        *mempool = retained;
        matched
    }

    fn take_verified_proposal(&self, height: u64, proposer: &Address) -> Option<Block> {
        let mut inbox = self.proposal_inbox.write();
        inbox
            .remove(&(height, proposer.clone()))
            .map(|proposal| proposal.block)
    }

    fn collect_proof_artifacts(
        bundle: &BlockProofBundle,
        max_bytes: usize,
    ) -> ChainResult<Vec<ProofArtifact>> {
        let mut artifacts = Vec::new();
        for proof in &bundle.transaction_proofs {
            if let Some(artifact) = Self::proof_artifact(ProofModule::Utxo, proof, max_bytes)? {
                artifacts.push(artifact);
            }
        }
        if let Some(artifact) =
            Self::proof_artifact(ProofModule::BlockTransition, &bundle.state_proof, max_bytes)?
        {
            artifacts.push(artifact);
        }
        if let Some(artifact) =
            Self::proof_artifact(ProofModule::Consensus, &bundle.pruning_proof, max_bytes)?
        {
            artifacts.push(artifact);
        }
        if let Some(artifact) =
            Self::proof_artifact(ProofModule::Consensus, &bundle.recursive_proof, max_bytes)?
        {
            artifacts.push(artifact);
        }
        Ok(artifacts)
    }

    fn proof_artifact(
        module: ProofModule,
        proof: &ChainProof,
        max_bytes: usize,
    ) -> ChainResult<Option<ProofArtifact>> {
        match proof {
            ChainProof::Stwo(stark) => {
                let bytes = match hex::decode(&stark.commitment) {
                    Ok(bytes) => bytes,
                    Err(_) => return Ok(None),
                };
                let mut commitment = [0u8; 32];
                if bytes.len() >= 32 {
                    commitment.copy_from_slice(&bytes[..32]);
                } else {
                    commitment[..bytes.len()].copy_from_slice(&bytes);
                }
                let encoded = serde_json::to_vec(proof).map_err(|err| {
                    ChainError::Config(format!(
                        "failed to encode {:?} proof artifact: {err}",
                        module
                    ))
                })?;
                if encoded.len() > max_bytes {
                    return Err(ChainError::Config(format!(
                        "proof artifact for {:?} exceeds max_proof_size_bytes ({max_bytes})",
                        module
                    )));
                }
                Ok(Some(ProofArtifact {
                    module,
                    commitment,
                    proof: encoded,
                    verification_key: None,
                }))
            }
            #[cfg(feature = "backend-plonky3")]
            ChainProof::Plonky3(_) => Ok(None),
        }
    }

    fn produce_block(&self) -> ChainResult<()> {
        let mut identity_pending: Vec<IdentityDeclaration> = Vec::new();
        {
            let mut mempool = self.identity_mempool.write();
            while identity_pending.len() < self.config.max_block_identity_registrations {
                if let Some(declaration) = mempool.pop_front() {
                    identity_pending.push(declaration);
                } else {
                    break;
                }
            }
        }

        let mut pending: Vec<TransactionProofBundle> = Vec::new();
        {
            let mut mempool = self.mempool.write();
            while pending.len() < self.config.max_block_transactions {
                if let Some(tx) = mempool.pop_front() {
                    pending.push(tx);
                } else {
                    break;
                }
            }
        }
        let has_uptime = !self.uptime_mempool.read().is_empty();
        if pending.is_empty() && identity_pending.is_empty() && !has_uptime {
            return Ok(());
        }
        let mut uptime_pending: Vec<RecordedUptimeProof> = Vec::new();
        {
            let mut mempool = self.uptime_mempool.write();
            while let Some(record) = mempool.pop_front() {
                uptime_pending.push(record);
            }
        }
        let tip_snapshot = *self.chain_tip.read();
        let height = tip_snapshot.height + 1;
        self.ledger.sync_epoch_for_height(height);
        let epoch = self.ledger.current_epoch();
        let accounts_snapshot = self.ledger.accounts_snapshot();
        let (validators, observers) = classify_participants(&accounts_snapshot);
        let vrf_pool = self.gather_vrf_submissions(epoch, tip_snapshot.last_hash, &validators);
        let mut round = ConsensusRound::new(
            height,
            tip_snapshot.last_hash,
            self.config.target_validator_count,
            validators,
            observers,
            &vrf_pool,
        );
        let round_metrics = round.vrf_metrics().clone();
        {
            let mut metrics = self.vrf_metrics.write();
            *metrics = round_metrics.clone();
        }
        if let Some(epoch_value) = round_metrics.latest_epoch {
            if let Ok(bytes) = hex::decode(&round_metrics.entropy_beacon) {
                if bytes.len() == 32 {
                    let mut beacon = [0u8; 32];
                    beacon.copy_from_slice(&bytes);
                    self.vrf_epoch.write().record_entropy(epoch_value, beacon);
                }
            }
        }
        self.ledger
            .record_vrf_history(epoch, round.round(), round.vrf_audit());
        let selection = match round.select_proposer() {
            Some(selection) => selection,
            None => {
                warn!("no proposer could be selected");
                return Ok(());
            }
        };
        if selection.proposer != self.address {
            if let Some(proposal) = self.take_verified_proposal(height, &selection.proposer) {
                info!(
                    proposer = %selection.proposer,
                    height,
                    "processing verified external proposal"
                );
                let block_hash = proposal.hash.clone();
                round.set_block_hash(block_hash.clone());
                let local_prevote =
                    self.build_local_vote(height, round.round(), &block_hash, BftVoteKind::PreVote);
                if let Err(err) = round.register_prevote(&local_prevote) {
                    warn!(
                        ?err,
                        "failed to register local prevote for external proposal"
                    );
                }
                let local_precommit = self.build_local_vote(
                    height,
                    round.round(),
                    &block_hash,
                    BftVoteKind::PreCommit,
                );
                if let Err(err) = round.register_precommit(&local_precommit) {
                    warn!(
                        ?err,
                        "failed to register local precommit for external proposal"
                    );
                }
                let external_votes = self.drain_votes_for(height, &block_hash);
                for vote in &external_votes {
                    let result = match vote.vote.kind {
                        BftVoteKind::PreVote => round.register_prevote(vote),
                        BftVoteKind::PreCommit => round.register_precommit(vote),
                    };
                    if let Err(err) = result {
                        warn!(?err, voter = %vote.vote.voter, "rejecting invalid consensus vote");
                        if self.config.rollout.feature_gates.consensus_enforcement {
                            if let Err(slash_err) = self
                                .ledger
                                .slash_validator(&vote.vote.voter, SlashingReason::InvalidVote)
                            {
                                warn!(
                                    ?slash_err,
                                    voter = %vote.vote.voter,
                                    "failed to slash validator for invalid vote"
                                );
                            }
                        }
                    }
                }
                if round.commit_reached() {
                    info!(height, proposer = %selection.proposer, "commit quorum observed externally");
                    self.evidence_pool.write().prune_below(height);
                }
            } else {
                info!(
                    proposer = %selection.proposer,
                    height,
                    "no verified proposal available for external leader"
                );
            }
            return Ok(());
        }
        if round.total_power().clone() == Natural::from(0u32) {
            warn!("validator set has no voting power");
            return Ok(());
        }

        let mut accepted_identities: Vec<IdentityDeclaration> = Vec::new();
        for declaration in identity_pending {
            match self.ledger.register_identity(declaration.clone()) {
                Ok(_) => accepted_identities.push(declaration),
                Err(err) => {
                    warn!(?err, "dropping invalid identity declaration");
                    if self.config.rollout.feature_gates.consensus_enforcement {
                        if let Err(slash_err) = self
                            .ledger
                            .slash_validator(&self.address, SlashingReason::InvalidIdentity)
                        {
                            warn!(?slash_err, "failed to slash proposer for invalid identity");
                        }
                    }
                }
            }
        }

        let mut accepted: Vec<TransactionProofBundle> = Vec::new();
        let mut total_fees: u64 = 0;
        for bundle in pending {
            match self.ledger.apply_transaction(&bundle.transaction) {
                Ok(fee) => {
                    total_fees = total_fees.saturating_add(fee);
                    accepted.push(bundle);
                }
                Err(err) => warn!(?err, "dropping invalid transaction"),
            }
        }

        if accepted.is_empty() && accepted_identities.is_empty() && uptime_pending.is_empty() {
            return Ok(());
        }

        let block_reward = BASE_BLOCK_REWARD.saturating_add(total_fees);
        self.ledger.distribute_consensus_rewards(
            &selection.proposer,
            round.validators(),
            block_reward,
            LEADER_BONUS_PERCENT,
        )?;

        let (transactions, transaction_proofs): (Vec<SignedTransaction>, Vec<_>) = accepted
            .into_iter()
            .map(|bundle| (bundle.transaction, bundle.proof))
            .unzip();

        let identity_proofs: Vec<ChainProof> = accepted_identities
            .iter()
            .map(|declaration| declaration.proof.zk_proof.clone())
            .collect();

        let mut uptime_proofs = Vec::new();
        let mut timetoke_updates = Vec::new();
        for record in uptime_pending {
            let RecordedUptimeProof {
                proof,
                credited_hours,
            } = record;
            timetoke_updates.push(TimetokeUpdate {
                identity: proof.wallet_address.clone(),
                window_start: proof.window_start,
                window_end: proof.window_end,
                credited_hours,
            });
            uptime_proofs.push(proof);
        }

        let mut touched_identities: HashSet<Address> = HashSet::new();
        for tx in &transactions {
            touched_identities.insert(tx.payload.from.clone());
            touched_identities.insert(tx.payload.to.clone());
        }
        for declaration in &accepted_identities {
            touched_identities.insert(declaration.genesis.wallet_addr.clone());
        }
        for update in &timetoke_updates {
            touched_identities.insert(update.identity.clone());
        }

        let mut reputation_updates = Vec::new();
        for identity in touched_identities {
            if let Some(audit) = self.ledger.reputation_audit(&identity)? {
                reputation_updates.push(ReputationUpdate::from(audit));
            }
        }
        reputation_updates.sort_by(|a, b| a.identity.cmp(&b.identity));

        let mut operation_hashes = Vec::new();
        for declaration in &accepted_identities {
            operation_hashes.push(declaration.hash()?);
        }
        for tx in &transactions {
            operation_hashes.push(tx.hash());
        }
        for proof in &uptime_proofs {
            let encoded = serde_json::to_vec(proof).expect("serialize uptime proof");
            operation_hashes.push(Blake2sHasher::hash(&encoded).into());
        }
        for update in &timetoke_updates {
            let encoded = serde_json::to_vec(update).expect("serialize timetoke update");
            operation_hashes.push(Blake2sHasher::hash(&encoded).into());
        }
        for update in &reputation_updates {
            let encoded = serde_json::to_vec(update).expect("serialize reputation update");
            operation_hashes.push(Blake2sHasher::hash(&encoded).into());
        }
        let tx_root = compute_merkle_root(&mut operation_hashes);
        let commitments = self.ledger.global_commitments();
        let header = BlockHeader::new(
            height,
            hex::encode(tip_snapshot.last_hash),
            hex::encode(tx_root),
            hex::encode(commitments.global_state_root),
            hex::encode(commitments.utxo_root),
            hex::encode(commitments.reputation_root),
            hex::encode(commitments.timetoke_root),
            hex::encode(commitments.zsi_root),
            hex::encode(commitments.proof_root),
            selection.total_voting_power.to_string(),
            selection.randomness.to_string(),
            selection.vrf_public_key.clone(),
            selection.proof.proof.clone(),
            self.address.clone(),
            selection.tier.to_string(),
            selection.timetoke_hours,
        );
        let block_hash_hex = hex::encode(header.hash());
        round.set_block_hash(block_hash_hex.clone());

        let local_prevote =
            self.build_local_vote(height, round.round(), &block_hash_hex, BftVoteKind::PreVote);
        round.register_prevote(&local_prevote)?;
        let local_precommit = self.build_local_vote(
            height,
            round.round(),
            &block_hash_hex,
            BftVoteKind::PreCommit,
        );
        round.register_precommit(&local_precommit)?;

        let external_votes = self.drain_votes_for(height, &block_hash_hex);
        for vote in &external_votes {
            let result = match vote.vote.kind {
                BftVoteKind::PreVote => round.register_prevote(vote),
                BftVoteKind::PreCommit => round.register_precommit(vote),
            };
            if let Err(err) = result {
                warn!(?err, voter = %vote.vote.voter, "rejecting invalid consensus vote");
                if self.config.rollout.feature_gates.consensus_enforcement {
                    if let Err(slash_err) = self
                        .ledger
                        .slash_validator(&vote.vote.voter, SlashingReason::InvalidVote)
                    {
                        warn!(
                            ?slash_err,
                            voter = %vote.vote.voter,
                            "failed to slash validator for invalid vote"
                        );
                    }
                }
            }
        }

        let mut recorded_votes = vec![local_prevote.clone(), local_precommit.clone()];
        recorded_votes.extend(external_votes.clone());

        let previous_block = self.storage.read_block(tip_snapshot.height)?;
        let pruning_proof = PruningProof::from_previous(previous_block.as_ref(), &header);
        let recursive_proof = match previous_block.as_ref() {
            Some(block) => RecursiveProof::extend(&block.recursive_proof, &header, &pruning_proof),
            None => RecursiveProof::genesis(&header, &pruning_proof),
        };

        let prover = WalletProver::new(&self.storage);
        let state_witness = prover.build_state_witness(
            &pruning_proof.previous_state_root,
            &header.state_root,
            &accepted_identities,
            &transactions,
        )?;
        let state_proof = prover.prove_state_transition(state_witness)?;

        let previous_transactions = previous_block
            .as_ref()
            .map(|block| block.transactions.clone())
            .unwrap_or_default();
        let previous_identities = previous_block
            .as_ref()
            .map(|block| block.identities.clone())
            .unwrap_or_default();
        let pruning_witness = prover.build_pruning_witness(
            &previous_identities,
            &previous_transactions,
            &pruning_proof,
            Vec::new(),
        )?;
        let pruning_stark = prover.prove_pruning(pruning_witness)?;

        let previous_recursive_stark = previous_block
            .as_ref()
            .map(|block| &block.stark.recursive_proof);

        let signature = sign_message(&self.keypair, &header.canonical_bytes());
        if !round.commit_reached() {
            warn!("quorum not reached for commit");
            return Ok(());
        }
        let participants = round.commit_participants();
        self.ledger
            .record_consensus_witness(height, round.round(), participants);
        let module_witnesses = self.ledger.drain_module_witnesses();
        let module_artifacts = self.ledger.stage_module_witnesses(&module_witnesses)?;
        let consensus_certificate = round.certificate();
        let consensus_witness =
            prover.build_consensus_witness(&block_hash_hex, &consensus_certificate)?;
        let consensus_proof = prover.prove_consensus(consensus_witness)?;
        let uptime_chain_proofs: Vec<ChainProof> = uptime_proofs
            .iter()
            .map(|proof| {
                proof.proof.clone().ok_or_else(|| {
                    ChainError::Crypto("uptime proof missing zk proof payload".into())
                })
            })
            .collect::<ChainResult<_>>()?;
        let consensus_chain_proofs = vec![consensus_proof.clone()];
        let recursive_witness = prover.build_recursive_witness(
            previous_recursive_stark,
            &identity_proofs,
            &transaction_proofs,
            &uptime_chain_proofs,
            &consensus_chain_proofs,
            &commitments,
            &state_proof,
            &pruning_stark,
            header.height,
        )?;
        let recursive_stark = prover.prove_recursive(recursive_witness)?;

        let stark_bundle = BlockProofBundle::new(
            transaction_proofs,
            state_proof,
            pruning_stark,
            recursive_stark,
        );
        let state_proof_artifact = stark_bundle.state_proof.clone();
        let mut proof_artifacts =
            Self::collect_proof_artifacts(&stark_bundle, self.config.max_proof_size_bytes)?;
        proof_artifacts.extend(module_artifacts);
        let block = Block::new(
            header,
            accepted_identities,
            transactions,
            uptime_proofs,
            timetoke_updates,
            reputation_updates,
            recorded_votes,
            module_witnesses,
            proof_artifacts,
            pruning_proof,
            recursive_proof,
            stark_bundle,
            signature,
            consensus_certificate,
            Some(consensus_proof),
        );
        block.verify(previous_block.as_ref())?;
        self.ledger.sync_epoch_for_height(height.saturating_add(1));
        let receipt = self.persist_accounts(height)?;
        let encoded_new_root = hex::encode(receipt.new_root);
        if encoded_new_root != block.header.state_root {
            return Err(ChainError::Config(
                "firewood state root does not match block header".into(),
            ));
        }
        let lifecycle = StateLifecycle::new(&self.storage);
        lifecycle.verify_transition(
            &state_proof_artifact,
            &receipt.previous_root,
            &receipt.new_root,
        )?;
        let mut metadata = BlockMetadata::from(&block);
        metadata.previous_state_root = hex::encode(receipt.previous_root);
        metadata.new_state_root = encoded_new_root;
        metadata.pruning_root = receipt
            .pruning_proof
            .as_ref()
            .map(|proof| hex::encode(proof.root));
        self.storage.store_block(&block, &metadata)?;
        if self.config.rollout.feature_gates.pruning && block.header.height > 0 {
            let _ = self.storage.prune_block_payload(block.header.height - 1)?;
        }
        let mut tip = self.chain_tip.write();
        tip.height = block.header.height;
        tip.last_hash = block.block_hash();
        info!(height = tip.height, "sealed block");
        self.evidence_pool
            .write()
            .prune_below(block.header.height.saturating_add(1));
        Ok(())
    }

    fn persist_accounts(&self, block_height: u64) -> ChainResult<StateTransitionReceipt> {
        let accounts = self.ledger.accounts_snapshot();
        let lifecycle = StateLifecycle::new(&self.storage);
        lifecycle.apply_block(block_height, &accounts)
    }

    fn bootstrap(&self) -> ChainResult<()> {
        if let Some(metadata) = self.storage.tip()? {
            let block = self
                .storage
                .read_block(metadata.height)?
                .ok_or_else(|| ChainError::Config("tip metadata missing block".into()))?;
            block.verify(None)?;
            let mut tip = self.chain_tip.write();
            tip.height = block.header.height;
            tip.last_hash = block.block_hash();
            if self.config.rollout.feature_gates.pruning {
                for height in 0..block.header.height {
                    let _ = self.storage.prune_block_payload(height)?;
                }
            }
        } else {
            let mut tip = self.chain_tip.write();
            tip.height = 0;
            tip.last_hash = [0u8; 32];
        }
        Ok(())
    }
}

fn build_genesis_accounts(entries: Vec<GenesisAccount>) -> ChainResult<Vec<Account>> {
    entries
        .into_iter()
        .map(|entry| {
            let stake = entry.stake_value()?;
            Ok(Account::new(entry.address, entry.balance, stake))
        })
        .collect()
}
