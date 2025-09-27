//! Stateful runtime node coordinating consensus, storage, and external services.
//!
//! The [`Node`] type wraps the chain runtime, orchestrating mempool management,
//! block production, and proof generation. Invariants maintained here include:
//!
//! * The in-memory tip (`ChainTip`) always reflects the latest committed block
//!   stored in [`Storage`].
//! * VRF submissions are validated against the current epoch before they are
//!   admitted to consensus queues.
//! * Side-effectful subsystems (telemetry, gossip, prover tasks) are spawned and
//!   owned by [`NodeHandle`], which ensures graceful shutdown via the async
//!   join handles it tracks.
//!
//! Public status/reporting structs are defined alongside the runtime to expose
//! snapshot views without leaking internal locks.
use std::collections::{HashMap, HashSet, VecDeque};
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use ed25519_dalek::Keypair;
use malachite::Natural;
use parking_lot::RwLock;
use tokio::sync::{Mutex, Notify, broadcast};
use tokio::task::JoinHandle;
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
use crate::reputation::{Tier, TimetokeParams};
use crate::rpp::{
    GlobalStateCommitments, ModuleWitnessBundle, ProofArtifact, ProofModule, TimetokeRecord,
};
use crate::state::lifecycle::StateLifecycle;
use crate::state::merkle::compute_merkle_root;
use crate::storage::{StateTransitionReceipt, Storage};
use crate::stwo::proof::ProofPayload;
use crate::stwo::prover::WalletProver;
use crate::sync::{PayloadProvider, ReconstructionEngine, ReconstructionPlan};
use crate::types::{
    Account, Address, AttestedIdentityRequest, Block, BlockHeader, BlockMetadata, BlockProofBundle,
    ChainProof, IDENTITY_ATTESTATION_GOSSIP_MIN, IDENTITY_ATTESTATION_QUORUM, IdentityDeclaration,
    PruningProof, RecursiveProof, ReputationUpdate, SignedTransaction, Stake, TimetokeUpdate,
    TransactionProofBundle, UptimeProof,
};
use crate::vrf::{
    self, PoseidonVrfInput, VrfEpochManager, VrfProof, VrfSubmission, VrfSubmissionPool,
};
use rpp_p2p::{HandshakePayload, NodeIdentity, TierLevel, VRF_HANDSHAKE_CONTEXT};
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
    pub attested_votes: usize,
    pub gossip_confirmations: usize,
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
    pub timetoke_params: TimetokeParams,
}

pub struct Node {
    inner: Arc<NodeInner>,
}

pub(crate) struct NodeInner {
    config: NodeConfig,
    keypair: Keypair,
    vrf_keypair: VrfKeypair,
    p2p_identity: Arc<NodeIdentity>,
    address: Address,
    storage: Storage,
    ledger: Ledger,
    mempool: RwLock<VecDeque<TransactionProofBundle>>,
    identity_mempool: RwLock<VecDeque<AttestedIdentityRequest>>,
    uptime_mempool: RwLock<VecDeque<RecordedUptimeProof>>,
    vrf_mempool: RwLock<VrfSubmissionPool>,
    vrf_epoch: RwLock<VrfEpochManager>,
    chain_tip: RwLock<ChainTip>,
    block_interval: Duration,
    vote_mempool: RwLock<VecDeque<SignedBftVote>>,
    proposal_inbox: RwLock<HashMap<(u64, Address), VerifiedProposal>>,
    consensus_rounds: RwLock<HashMap<u64, u64>>,
    evidence_pool: RwLock<EvidencePool>,
    telemetry_last_height: RwLock<Option<u64>>,
    vrf_metrics: RwLock<crate::vrf::VrfSelectionMetrics>,
    verifiers: ProofVerifierRegistry,
    shutdown: broadcast::Sender<()>,
    worker_tasks: Mutex<Vec<JoinHandle<()>>>,
    completion: Notify,
}

enum FinalizationContext {
    Local(LocalFinalizationContext),
    #[allow(dead_code)]
    External(ExternalFinalizationContext),
}

struct LocalFinalizationContext {
    round: ConsensusRound,
    block_hash: String,
    header: BlockHeader,
    parent_height: u64,
    commitments: GlobalStateCommitments,
    accepted_identities: Vec<AttestedIdentityRequest>,
    transactions: Vec<SignedTransaction>,
    transaction_proofs: Vec<ChainProof>,
    identity_proofs: Vec<ChainProof>,
    uptime_proofs: Vec<UptimeProof>,
    timetoke_updates: Vec<TimetokeUpdate>,
    reputation_updates: Vec<ReputationUpdate>,
    recorded_votes: Vec<SignedBftVote>,
}

#[allow(dead_code)]
struct ExternalFinalizationContext {
    round: ConsensusRound,
    block: Block,
    previous_block: Option<Block>,
    archived_votes: Vec<SignedBftVote>,
}

enum FinalizationOutcome {
    Sealed { block: Block, tip_height: u64 },
    AwaitingQuorum,
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

#[derive(Clone, Debug)]
pub struct NetworkIdentityProfile {
    pub zsi_id: String,
    pub tier: TierLevel,
    pub vrf_public_key: Vec<u8>,
    pub vrf_proof: Vec<u8>,
}

impl Node {
    pub fn new(config: NodeConfig) -> ChainResult<Self> {
        config.validate()?;
        config.ensure_directories()?;
        let keypair = load_or_generate_keypair(&config.key_path)?;
        let vrf_keypair = load_or_generate_vrf_keypair(&config.vrf_key_path)?;
        let p2p_identity = Arc::new(
            NodeIdentity::load_or_generate(&config.p2p_key_path)
                .map_err(|err| ChainError::Config(format!("unable to load p2p identity: {err}")))?,
        );
        let address = address_from_public_key(&keypair.public);
        let reputation_params = config.reputation.reputation_params();
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
            let utxo_snapshot = storage.load_utxo_snapshot()?.unwrap_or_default();
            let mut ledger = Ledger::load(accounts.clone(), utxo_snapshot, config.epoch_length);
            ledger.set_reputation_params(reputation_params.clone());
            let module_witnesses = ledger.drain_module_witnesses();
            let module_artifacts = ledger.stage_module_witnesses(&module_witnesses)?;
            let mut tx_hashes: Vec<[u8; 32]> = Vec::new();
            let tx_root = compute_merkle_root(&mut tx_hashes);
            let commitments = ledger.global_commitments();
            let state_root_hex = hex::encode(commitments.global_state_root);
            let stakes = ledger.stake_snapshot();
            let total_stake = aggregate_total_stake(&stakes);
            let genesis_seed = [0u8; 32];
            let vrf = evaluate_vrf(&genesis_seed, 0, &address, 0, Some(&vrf_keypair.secret))?;
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
                vrf.preoutput.clone(),
                vrf.proof.clone(),
                address.clone(),
                Tier::Tl5.to_string(),
                0,
            );
            let pruning_proof = PruningProof::genesis(&state_root_hex);
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
            let recursive_proof =
                RecursiveProof::genesis(&header, &pruning_proof, &stark_bundle.recursive_proof)?;
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
            genesis_block.verify(None, &keypair.public)?;
            let genesis_metadata = BlockMetadata::from(&genesis_block);
            storage.store_block(&genesis_block, &genesis_metadata)?;
            tip_metadata = Some(genesis_metadata);
        }

        if accounts.is_empty() {
            accounts = storage.load_accounts()?;
        }

        let utxo_snapshot = storage.load_utxo_snapshot()?.unwrap_or_default();
        let mut ledger = Ledger::load(accounts, utxo_snapshot, config.epoch_length);
        ledger.set_reputation_params(reputation_params);

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

        let (shutdown, _shutdown_rx) = broadcast::channel(1);
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
            consensus_rounds: RwLock::new(HashMap::new()),
            evidence_pool: RwLock::new(EvidencePool::default()),
            telemetry_last_height: RwLock::new(None),
            vrf_metrics: RwLock::new(crate::vrf::VrfSelectionMetrics::default()),
            verifiers: ProofVerifierRegistry::default(),
            shutdown,
            worker_tasks: Mutex::new(Vec::new()),
            completion: Notify::new(),
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
        let join = self.inner.spawn_runtime();
        join.await
            .map_err(|err| ChainError::Config(format!("node runtime join error: {err}")))
    }

    pub fn network_identity_profile(&self) -> ChainResult<NetworkIdentityProfile> {
        self.inner.network_identity_profile()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{GenesisAccount, NodeConfig};
    use crate::consensus::{
        BftVote, BftVoteKind, ConsensusRound, SignedBftVote, classify_participants, evaluate_vrf,
    };
    use crate::crypto::{
        address_from_public_key, generate_vrf_keypair, load_or_generate_keypair,
        vrf_public_key_from_hex, vrf_public_key_to_hex,
    };
    use crate::errors::ChainError;
    use crate::ledger::Ledger;
    use crate::reputation::Tier;
    use crate::stwo::circuit::{
        StarkCircuit,
        identity::{IdentityCircuit, IdentityWitness},
        string_to_field,
    };
    use crate::stwo::fri::FriProver;
    use crate::stwo::params::StarkParameters;
    use crate::stwo::proof::{ProofKind, ProofPayload, StarkProof};
    use crate::types::{ChainProof, IdentityDeclaration, IdentityGenesis, IdentityProof};
    use crate::vrf::{self, PoseidonVrfInput, VrfProof, VrfSubmission, VrfSubmissionPool};
    use ed25519_dalek::{Keypair, PublicKey, SecretKey, Signer};
    use malachite::Natural;
    use stwo::core::vcs::blake2_hash::Blake2sHasher;
    use tempfile::tempdir;

    fn seeded_keypair(seed: u8) -> Keypair {
        let secret = SecretKey::from_bytes(&[seed; 32]).expect("secret");
        let public = PublicKey::from(&secret);
        Keypair { secret, public }
    }

    fn sign_identity_vote(keypair: &Keypair, height: u64, hash: &str) -> SignedBftVote {
        let voter = address_from_public_key(&keypair.public);
        let vote = BftVote {
            round: 0,
            height,
            block_hash: hash.to_string(),
            voter: voter.clone(),
            kind: BftVoteKind::PreCommit,
        };
        let signature = keypair.sign(&vote.message_bytes());
        SignedBftVote {
            vote,
            public_key: hex::encode(keypair.public.to_bytes()),
            signature: hex::encode(signature.to_bytes()),
        }
    }

    fn sample_identity_declaration(ledger: &Ledger) -> IdentityDeclaration {
        ledger.sync_epoch_for_height(1);
        let pk_bytes = vec![1u8; 32];
        let wallet_pk = hex::encode(&pk_bytes);
        let wallet_addr = hex::encode::<[u8; 32]>(Blake2sHasher::hash(&pk_bytes).into());
        let epoch_nonce_bytes = ledger.current_epoch_nonce();
        let vrf_keypair = generate_vrf_keypair().expect("generate vrf keypair");
        let vrf = evaluate_vrf(
            &epoch_nonce_bytes,
            0,
            &wallet_addr,
            0,
            Some(&vrf_keypair.secret),
        )
        .expect("evaluate vrf");
        let commitment_proof = ledger.identity_commitment_proof(&wallet_addr);
        let genesis = IdentityGenesis {
            wallet_pk,
            wallet_addr,
            vrf_public_key: vrf_public_key_to_hex(&vrf_keypair.public),
            vrf_proof: vrf.clone(),
            epoch_nonce: hex::encode(epoch_nonce_bytes),
            state_root: hex::encode(ledger.state_root()),
            identity_root: hex::encode(ledger.identity_root()),
            initial_reputation: 0,
            commitment_proof: commitment_proof.clone(),
        };
        let parameters = StarkParameters::blueprint_default();
        let expected_commitment = genesis.expected_commitment().expect("commitment");
        let witness = IdentityWitness {
            wallet_pk: genesis.wallet_pk.clone(),
            wallet_addr: genesis.wallet_addr.clone(),
            vrf_tag: genesis.vrf_tag().to_string(),
            epoch_nonce: genesis.epoch_nonce.clone(),
            state_root: genesis.state_root.clone(),
            identity_root: genesis.identity_root.clone(),
            initial_reputation: genesis.initial_reputation,
            commitment: expected_commitment.clone(),
            identity_leaf: commitment_proof.leaf.clone(),
            identity_path: commitment_proof.siblings.clone(),
        };
        let circuit = IdentityCircuit::new(witness.clone());
        circuit.evaluate_constraints().expect("constraints");
        let trace = circuit
            .generate_trace(&parameters)
            .expect("trace generation");
        circuit
            .verify_air(&parameters, &trace)
            .expect("air verification");
        let inputs = vec![
            string_to_field(&parameters, &witness.wallet_addr),
            string_to_field(&parameters, &witness.vrf_tag),
            string_to_field(&parameters, &witness.identity_root),
            string_to_field(&parameters, &witness.state_root),
        ];
        let hasher = parameters.poseidon_hasher();
        let fri_prover = FriProver::new(&parameters);
        let fri_proof = fri_prover.prove(&trace, &inputs);
        let proof = StarkProof::new(
            ProofKind::Identity,
            ProofPayload::Identity(witness),
            inputs,
            trace,
            fri_proof,
            &hasher,
        );
        IdentityDeclaration {
            genesis,
            proof: IdentityProof {
                commitment: expected_commitment,
                zk_proof: ChainProof::Stwo(proof),
            },
        }
    }

    fn attested_request(ledger: &Ledger, height: u64) -> AttestedIdentityRequest {
        let declaration = sample_identity_declaration(ledger);
        let identity_hash = hex::encode(declaration.hash().expect("hash"));
        let voters: Vec<Keypair> = (0..IDENTITY_ATTESTATION_QUORUM)
            .map(|idx| seeded_keypair(50 + idx as u8))
            .collect();
        let attested_votes = voters
            .iter()
            .map(|kp| sign_identity_vote(kp, height, &identity_hash))
            .collect();
        let gossip_confirmations = voters
            .iter()
            .take(IDENTITY_ATTESTATION_GOSSIP_MIN)
            .map(|kp| address_from_public_key(&kp.public))
            .collect();
        AttestedIdentityRequest {
            declaration,
            attested_votes,
            gossip_confirmations,
        }
    }

    fn temp_config() -> (tempfile::TempDir, NodeConfig) {
        let dir = tempdir().expect("tempdir");
        let base = dir.path();
        let mut config = NodeConfig::default();
        config.data_dir = base.join("data");
        config.key_path = base.join("node_key.toml");
        config.p2p_key_path = base.join("p2p_key.toml");
        config.vrf_key_path = base.join("vrf_key.toml");
        config.snapshot_dir = base.join("snapshots");
        config.proof_cache_dir = base.join("proofs");
        (dir, config)
    }

    #[test]
    fn node_accepts_valid_identity_attestation() {
        let (_tmp, config) = temp_config();
        let node = Node::new(config).expect("node");
        let height = node.inner.chain_tip.read().height + 1;
        let request = attested_request(&node.inner.ledger, height);
        node.inner
            .validate_identity_attestation(&request, height)
            .expect("valid attestation accepted");
    }

    #[test]
    fn node_rejects_attestation_below_quorum() {
        let (_tmp, config) = temp_config();
        let node = Node::new(config).expect("node");
        let height = node.inner.chain_tip.read().height + 1;
        let mut request = attested_request(&node.inner.ledger, height);
        request
            .attested_votes
            .truncate(IDENTITY_ATTESTATION_QUORUM - 1);
        let err = node
            .inner
            .validate_identity_attestation(&request, height)
            .expect_err("insufficient quorum rejected");
        match err {
            ChainError::Transaction(message) => {
                assert!(message.contains("quorum"));
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn node_rejects_attestation_with_insufficient_gossip() {
        let (_tmp, config) = temp_config();
        let node = Node::new(config).expect("node");
        let height = node.inner.chain_tip.read().height + 1;
        let mut request = attested_request(&node.inner.ledger, height);
        request
            .gossip_confirmations
            .truncate(IDENTITY_ATTESTATION_GOSSIP_MIN - 1);
        let err = node
            .inner
            .validate_identity_attestation(&request, height)
            .expect_err("insufficient gossip rejected");
        match err {
            ChainError::Transaction(message) => {
                assert!(message.contains("gossip"));
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn finalizes_external_block_from_remote_proposer() {
        let (_tmp_a, mut config_a) = temp_config();
        let (_tmp_b, mut config_b) = temp_config();

        config_a.rollout.feature_gates.pruning = false;
        config_b.rollout.feature_gates.pruning = false;
        config_a.rollout.feature_gates.consensus_enforcement = false;
        config_b.rollout.feature_gates.consensus_enforcement = false;

        let key_a = load_or_generate_keypair(&config_a.key_path).expect("generate key a");
        let key_b = load_or_generate_keypair(&config_b.key_path).expect("generate key b");
        let address_a = address_from_public_key(&key_a.public);
        let address_b = address_from_public_key(&key_b.public);

        let genesis_accounts = vec![
            GenesisAccount {
                address: address_a.clone(),
                balance: 1_000_000_000,
                stake: "1000".to_string(),
            },
            GenesisAccount {
                address: address_b.clone(),
                balance: 1_000_000_000,
                stake: "1000".to_string(),
            },
        ];
        config_a.genesis.accounts = genesis_accounts.clone();
        config_b.genesis.accounts = genesis_accounts;

        let node_a = Node::new(config_a).expect("node a");
        let node_b = Node::new(config_b).expect("node b");

        let height = node_a.inner.chain_tip.read().height + 1;
        let request = attested_request(&node_a.inner.ledger, height);
        node_a
            .inner
            .submit_identity(request)
            .expect("submit identity");
        node_a.inner.produce_block().expect("produce block");

        let block = node_a
            .inner
            .storage
            .read_block(height)
            .expect("read block")
            .expect("block exists");
        assert_eq!(block.header.proposer, address_a);

        let previous_hash_bytes =
            hex::decode(&block.header.previous_hash).expect("decode prev hash");
        let mut seed = [0u8; 32];
        if !previous_hash_bytes.is_empty() {
            seed.copy_from_slice(&previous_hash_bytes);
        }

        let accounts_snapshot = node_b.inner.ledger.accounts_snapshot();
        let (validators, observers) = classify_participants(&accounts_snapshot);
        let proposer_candidate = validators
            .iter()
            .find(|candidate| candidate.address == block.header.proposer)
            .expect("proposer candidate")
            .clone();

        node_b
            .inner
            .ledger
            .sync_epoch_for_height(block.header.height);
        let epoch = node_b.inner.ledger.current_epoch();

        let tier = match block.header.leader_tier.as_str() {
            "New" => Tier::Tl0,
            "Validated" => Tier::Tl1,
            "Available" => Tier::Tl2,
            "Committed" => Tier::Tl3,
            "Reliable" => Tier::Tl4,
            "Trusted" => Tier::Tl5,
            other => panic!("unexpected leader tier: {other}"),
        };
        let tier_seed = vrf::derive_tier_seed(
            &proposer_candidate.address,
            proposer_candidate.timetoke_hours,
        );
        let input = PoseidonVrfInput::new(seed, epoch, tier_seed);
        let randomness = Natural::from_str(&block.header.randomness).expect("parse randomness");
        let proof = VrfProof {
            randomness,
            preoutput: block.header.vrf_preoutput.clone(),
            proof: block.header.vrf_proof.clone(),
        };
        let public_key = if block.header.vrf_public_key.trim().is_empty() {
            None
        } else {
            Some(vrf_public_key_from_hex(&block.header.vrf_public_key).expect("vrf key"))
        };
        let mut pool = VrfSubmissionPool::new();
        pool.insert(VrfSubmission {
            address: block.header.proposer.clone(),
            public_key,
            input,
            proof,
            tier,
            timetoke_hours: block.header.leader_timetoke,
        });

        let mut round = ConsensusRound::new(
            block.header.height,
            block.consensus.round,
            seed,
            node_b.inner.config.target_validator_count,
            validators,
            observers,
            &pool,
        );
        round.set_block_hash(block.hash.clone());
        for record in &block.consensus.pre_votes {
            round
                .register_prevote(&record.vote)
                .expect("register prevote");
        }
        for record in &block.consensus.pre_commits {
            round
                .register_precommit(&record.vote)
                .expect("register precommit");
        }
        assert!(round.commit_reached());

        let previous_block = if block.header.height == 0 {
            None
        } else {
            node_b
                .inner
                .storage
                .read_block(block.header.height - 1)
                .expect("read previous block")
        };

        let outcome = node_b
            .inner
            .finalize_block(FinalizationContext::External(ExternalFinalizationContext {
                round,
                block: block.clone(),
                previous_block,
                archived_votes: block.bft_votes.clone(),
            }))
            .expect("finalize external");

        let sealed = match outcome {
            FinalizationOutcome::Sealed { block: sealed, .. } => sealed,
            FinalizationOutcome::AwaitingQuorum => panic!("expected sealed block"),
        };
        assert_eq!(sealed.hash, block.hash);

        let tip_metadata = node_b
            .inner
            .storage
            .tip()
            .expect("tip metadata")
            .expect("metadata");
        assert_eq!(tip_metadata.height, block.header.height);
        assert_eq!(tip_metadata.new_state_root, block.header.state_root);

        let stored_record = node_b
            .inner
            .storage
            .read_block_record(block.header.height)
            .expect("read record")
            .expect("stored block");
        let stored_pruning = &stored_record.envelope.pruning_proof;
        assert_eq!(
            stored_pruning.pruned_height,
            block.pruning_proof.pruned_height
        );
        assert_eq!(
            stored_pruning.previous_block_hash,
            block.pruning_proof.previous_block_hash
        );
        assert_eq!(
            stored_pruning.resulting_state_root,
            block.pruning_proof.resulting_state_root
        );
        let stored_consensus = &stored_record.envelope.consensus;
        assert_eq!(stored_consensus.round, block.consensus.round);
        assert_eq!(stored_consensus.total_power, block.consensus.total_power);
        assert_eq!(
            stored_consensus.pre_votes.len(),
            block.consensus.pre_votes.len()
        );
        assert_eq!(
            stored_consensus.pre_commits.len(),
            block.consensus.pre_commits.len()
        );

        assert_eq!(
            hex::encode(node_b.inner.ledger.state_root()),
            block.header.state_root
        );
        assert_eq!(node_b.inner.chain_tip.read().height, block.header.height);
    }
}

impl NodeHandle {
    pub async fn stop(&self) -> ChainResult<()> {
        self.inner.stop().await
    }

    pub fn submit_transaction(&self, bundle: TransactionProofBundle) -> ChainResult<String> {
        self.inner.submit_transaction(bundle)
    }

    pub fn submit_identity(&self, request: AttestedIdentityRequest) -> ChainResult<String> {
        self.inner.submit_identity(request)
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
    fn spawn_runtime(self: &Arc<Self>) -> JoinHandle<()> {
        let runner = Arc::clone(self);
        let shutdown = runner.subscribe_shutdown();
        let run_task = tokio::spawn(async move { runner.run(shutdown).await });

        let completion = Arc::clone(self);
        tokio::spawn(async move {
            match run_task.await {
                Ok(Ok(())) => {}
                Ok(Err(err)) => {
                    warn!(?err, "node runtime exited with error");
                }
                Err(err) => {
                    warn!(?err, "node runtime join error");
                }
            }
            completion.drain_worker_tasks().await;
            completion.completion.notify_waiters();
        })
    }

    pub async fn start(config: NodeConfig) -> ChainResult<(NodeHandle, JoinHandle<()>)> {
        let node = Node::new(config)?;
        let handle = node.handle();
        let join = handle.inner.spawn_runtime();
        Ok((handle, join))
    }

    pub async fn stop(&self) -> ChainResult<()> {
        self.signal_shutdown();
        self.completion.notified().await;
        self.drain_worker_tasks().await;
        Ok(())
    }

    async fn run(self: Arc<Self>, mut shutdown: broadcast::Receiver<()>) -> ChainResult<()> {
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
            let telemetry_shutdown = self.shutdown.subscribe();
            self.spawn_worker(tokio::spawn(async move {
                worker.telemetry_loop(config, telemetry_shutdown).await;
            }))
            .await;
        }
        let mut ticker = time::interval(self.block_interval);
        loop {
            tokio::select! {
                _ = ticker.tick() => {
                    if let Err(err) = self.produce_block() {
                        warn!(?err, "block production failed");
                    }
                }
                result = shutdown.recv() => {
                    match result {
                        Ok(_) | Err(broadcast::error::RecvError::Lagged(_)) => {
                            info!("node shutdown signal received");
                        }
                        Err(broadcast::error::RecvError::Closed) => {
                            info!("node shutdown channel closed");
                        }
                    }
                    break;
                }
            }
        }
        Ok(())
    }

    async fn telemetry_loop(
        self: Arc<Self>,
        config: TelemetryConfig,
        mut shutdown: broadcast::Receiver<()>,
    ) {
        let interval = Duration::from_secs(config.sample_interval_secs.max(1));
        let mut ticker = time::interval(interval);
        let client = reqwest::Client::new();
        loop {
            tokio::select! {
                _ = ticker.tick() => {
                    if let Err(err) = self.emit_telemetry(&client, &config).await {
                        warn!(?err, "failed to emit telemetry snapshot");
                    }
                }
                result = shutdown.recv() => {
                    if let Err(err) = result {
                        if !matches!(err, broadcast::error::RecvError::Lagged(_)) {
                            debug!(?err, "telemetry shutdown channel closed");
                        }
                    }
                    break;
                }
            }
        }
    }

    async fn spawn_worker(&self, handle: JoinHandle<()>) {
        let mut workers = self.worker_tasks.lock().await;
        workers.push(handle);
    }

    async fn drain_worker_tasks(&self) {
        let mut workers = self.worker_tasks.lock().await;
        while let Some(handle) = workers.pop() {
            if let Err(err) = handle.await {
                if !err.is_cancelled() {
                    warn!(?err, "node worker task terminated unexpectedly");
                }
            }
        }
    }

    fn subscribe_shutdown(&self) -> broadcast::Receiver<()> {
        self.shutdown.subscribe()
    }

    fn signal_shutdown(&self) {
        let _ = self.shutdown.send(());
    }

    async fn emit_telemetry(
        &self,
        client: &reqwest::Client,
        config: &TelemetryConfig,
    ) -> ChainResult<()> {
        let snapshot = self.build_telemetry_snapshot()?;
        send_telemetry_with_tracking(client, config, &snapshot, &self.telemetry_last_height).await
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
            timetoke_params: self.ledger.timetoke_params(),
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
                let witness_value = value
                    .get("public_inputs")
                    .and_then(|inputs| inputs.get("witness"))
                    .cloned()
                    .ok_or_else(|| {
                        ChainError::Crypto(
                            "plonky3 transaction proof missing witness payload".into(),
                        )
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

    fn submit_identity(&self, request: AttestedIdentityRequest) -> ChainResult<String> {
        let next_height = self.chain_tip.read().height.saturating_add(1);
        self.ledger.sync_epoch_for_height(next_height);
        if self.config.rollout.feature_gates.recursive_proofs {
            self.verifiers
                .verify_identity(&request.declaration.proof.zk_proof)?;
        }
        self.validate_identity_attestation(&request, next_height)?;
        let declaration = &request.declaration;
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

        let hash = request.identity_hash()?;
        let mut mempool = self.identity_mempool.write();
        if mempool.len() >= self.config.mempool_limit {
            return Err(ChainError::Transaction("identity mempool full".into()));
        }
        if mempool.iter().any(|existing| {
            existing.declaration.genesis.wallet_addr == declaration.genesis.wallet_addr
        }) {
            return Err(ChainError::Transaction(
                "identity for this wallet already queued".into(),
            ));
        }
        if mempool
            .iter()
            .any(|existing| existing.identity_hash().ok().as_deref() == Some(hash.as_str()))
        {
            return Err(ChainError::Transaction(
                "identity request already queued for attestation".into(),
            ));
        }
        mempool.push_back(request);
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
        self.observe_consensus_round(vote.vote.height, vote.vote.round);
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

    fn validate_identity_attestation(
        &self,
        request: &AttestedIdentityRequest,
        expected_height: u64,
    ) -> ChainResult<()> {
        request.declaration.verify()?;
        let identity_hash = request.identity_hash()?;
        let mut voters = HashSet::new();
        for vote in &request.attested_votes {
            if let Err(err) = vote.verify() {
                self.punish_invalid_identity(
                    &vote.vote.voter,
                    "invalid identity attestation signature",
                );
                return Err(err);
            }
            if vote.vote.block_hash != identity_hash {
                self.punish_invalid_identity(
                    &vote.vote.voter,
                    "identity attestation references mismatched hash",
                );
                return Err(ChainError::Transaction(
                    "identity attestation vote references mismatched request".into(),
                ));
            }
            if vote.vote.height != expected_height {
                self.punish_invalid_identity(
                    &vote.vote.voter,
                    "identity attestation references wrong height",
                );
                return Err(ChainError::Transaction(
                    "identity attestation vote references unexpected height".into(),
                ));
            }
            if vote.vote.kind != BftVoteKind::PreCommit {
                self.punish_invalid_identity(
                    &vote.vote.voter,
                    "identity attestation wrong vote kind",
                );
                return Err(ChainError::Transaction(
                    "identity attestation must be composed of pre-commit votes".into(),
                ));
            }
            if !voters.insert(vote.vote.voter.clone()) {
                return Err(ChainError::Transaction(
                    "duplicate attestation vote detected for identity request".into(),
                ));
            }
        }
        if voters.len() < IDENTITY_ATTESTATION_QUORUM {
            return Err(ChainError::Transaction(
                "insufficient quorum power for identity attestation".into(),
            ));
        }
        let mut gossip = HashSet::new();
        for address in &request.gossip_confirmations {
            gossip.insert(address.clone());
        }
        if gossip.len() < IDENTITY_ATTESTATION_GOSSIP_MIN {
            return Err(ChainError::Transaction(
                "insufficient gossip confirmations for identity attestation".into(),
            ));
        }
        Ok(())
    }

    fn punish_invalid_identity(&self, address: &str, context: &str) {
        if !self.config.rollout.feature_gates.consensus_enforcement {
            return;
        }
        if let Err(err) = self
            .ledger
            .slash_validator(address, SlashingReason::InvalidIdentity)
        {
            warn!(
                offender = %address,
                ?err,
                context,
                "failed to slash validator for invalid identity attestation"
            );
        }
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
        let proposer_key = self.ledger.validator_public_key(&proposer)?;
        match block.verify_without_stark(previous_block.as_ref(), &proposer_key) {
            Ok(()) => {
                let hash = block.hash.clone();
                self.observe_consensus_round(height, round);
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
            .map(|request| PendingIdentitySummary {
                wallet_addr: request.declaration.genesis.wallet_addr.clone(),
                commitment: request.declaration.commitment().to_string(),
                epoch_nonce: request.declaration.genesis.epoch_nonce.clone(),
                state_root: request.declaration.genesis.state_root.clone(),
                identity_root: request.declaration.genesis.identity_root.clone(),
                vrf_tag: request.declaration.genesis.vrf_tag().to_string(),
                attested_votes: request.attested_votes.len(),
                gossip_confirmations: request.gossip_confirmations.len(),
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
        )?;
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

    fn current_consensus_round(&self, height: u64) -> u64 {
        self.consensus_rounds
            .read()
            .get(&height)
            .copied()
            .unwrap_or(0)
    }

    fn observe_consensus_round(&self, height: u64, round: u64) {
        let mut rounds = self.consensus_rounds.write();
        let entry = rounds.entry(height).or_insert(round);
        if round > *entry {
            *entry = round;
        }
    }

    fn prune_consensus_rounds_below(&self, threshold_height: u64) {
        self.consensus_rounds
            .write()
            .retain(|&tracked_height, _| tracked_height >= threshold_height);
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
        let mut identity_pending: Vec<AttestedIdentityRequest> = Vec::new();
        {
            let mut mempool = self.identity_mempool.write();
            while identity_pending.len() < self.config.max_block_identity_registrations {
                if let Some(request) = mempool.pop_front() {
                    identity_pending.push(request);
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
        self.prune_consensus_rounds_below(height);
        self.ledger.sync_epoch_for_height(height);
        let epoch = self.ledger.current_epoch();
        let accounts_snapshot = self.ledger.accounts_snapshot();
        let (validators, observers) = classify_participants(&accounts_snapshot);
        let vrf_pool = self.gather_vrf_submissions(epoch, tip_snapshot.last_hash, &validators);
        let round_number = self.current_consensus_round(height);
        self.observe_consensus_round(height, round_number);
        let mut round = ConsensusRound::new(
            height,
            round_number,
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
                    let previous_block = if height == 0 {
                        None
                    } else {
                        self.storage.read_block(height - 1)?
                    };
                    let mut archived_votes = vec![local_prevote.clone(), local_precommit.clone()];
                    archived_votes.extend(external_votes.clone());
                    let finalization_ctx =
                        FinalizationContext::External(ExternalFinalizationContext {
                            round,
                            block: proposal,
                            previous_block,
                            archived_votes,
                        });
                    match self.finalize_block(finalization_ctx)? {
                        FinalizationOutcome::Sealed { block, tip_height } => {
                            let _ = (block, tip_height);
                        }
                        FinalizationOutcome::AwaitingQuorum => {}
                    }
                    return Ok(());
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

        let mut accepted_identities: Vec<AttestedIdentityRequest> = Vec::new();
        for request in identity_pending {
            match self.ledger.register_identity(
                &request,
                height,
                IDENTITY_ATTESTATION_QUORUM,
                IDENTITY_ATTESTATION_GOSSIP_MIN,
            ) {
                Ok(_) => accepted_identities.push(request),
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

        let identity_declarations: Vec<IdentityDeclaration> = accepted_identities
            .iter()
            .map(|request| request.declaration.clone())
            .collect();

        let mut accepted: Vec<TransactionProofBundle> = Vec::new();
        let mut total_fees: u64 = 0;
        for bundle in pending {
            match self
                .ledger
                .select_inputs_for_transaction(&bundle.transaction)
                .and_then(|inputs| self.ledger.apply_transaction(&bundle.transaction, &inputs))
            {
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
            .map(|request| request.declaration.proof.zk_proof.clone())
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
        for declaration in &identity_declarations {
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
        for declaration in &identity_declarations {
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
            selection.proof.preoutput.clone(),
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

        let finalization_ctx = FinalizationContext::Local(LocalFinalizationContext {
            round,
            block_hash: block_hash_hex,
            header,
            parent_height: tip_snapshot.height,
            commitments,
            accepted_identities,
            transactions,
            transaction_proofs,
            identity_proofs,
            uptime_proofs,
            timetoke_updates,
            reputation_updates,
            recorded_votes,
        });

        match self.finalize_block(finalization_ctx)? {
            FinalizationOutcome::Sealed { block, tip_height } => {
                let _ = (block, tip_height);
            }
            FinalizationOutcome::AwaitingQuorum => {}
        }
        Ok(())
    }

    fn finalize_block(&self, ctx: FinalizationContext) -> ChainResult<FinalizationOutcome> {
        match ctx {
            FinalizationContext::Local(ctx) => self.finalize_local_block(ctx),
            FinalizationContext::External(ctx) => self.finalize_external_block(ctx),
        }
    }

    fn finalize_local_block(
        &self,
        ctx: LocalFinalizationContext,
    ) -> ChainResult<FinalizationOutcome> {
        let LocalFinalizationContext {
            round,
            block_hash,
            header,
            parent_height,
            commitments,
            accepted_identities,
            transactions,
            transaction_proofs,
            identity_proofs,
            uptime_proofs,
            timetoke_updates,
            reputation_updates,
            recorded_votes,
        } = ctx;

        if !round.commit_reached() {
            warn!("quorum not reached for commit");
            return Ok(FinalizationOutcome::AwaitingQuorum);
        }

        let height = header.height;
        let previous_block = self.storage.read_block(parent_height)?;
        let pruning_proof = PruningProof::from_previous(previous_block.as_ref(), &header);
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

        let participants = round.commit_participants();
        self.ledger
            .record_consensus_witness(height, round.round(), participants);
        let module_witnesses = self.ledger.drain_module_witnesses();
        let module_artifacts = self.ledger.stage_module_witnesses(&module_witnesses)?;
        let consensus_certificate = round.certificate();
        let consensus_witness =
            prover.build_consensus_witness(&block_hash, &consensus_certificate)?;
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
        let recursive_proof = match previous_block.as_ref() {
            Some(block) => RecursiveProof::extend(
                &block.recursive_proof,
                &header,
                &pruning_proof,
                &stark_bundle.recursive_proof,
            )?,
            None => {
                RecursiveProof::genesis(&header, &pruning_proof, &stark_bundle.recursive_proof)?
            }
        };
        let signature = sign_message(&self.keypair, &header.canonical_bytes());
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
        block.verify(previous_block.as_ref(), &self.keypair.public)?;
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
        self.prune_consensus_rounds_below(block.header.height.saturating_add(1));

        Ok(FinalizationOutcome::Sealed {
            tip_height: block.header.height,
            block,
        })
    }

    fn finalize_external_block(
        &self,
        ctx: ExternalFinalizationContext,
    ) -> ChainResult<FinalizationOutcome> {
        let ExternalFinalizationContext {
            round,
            mut block,
            mut previous_block,
            archived_votes,
        } = ctx;

        if !round.commit_reached() {
            warn!("quorum not reached for commit");
            return Ok(FinalizationOutcome::AwaitingQuorum);
        }

        let height = block.header.height;
        if previous_block.is_none() && height > 0 {
            previous_block = self.storage.read_block(height - 1)?;
        }

        let proposer_key = self.ledger.validator_public_key(&block.header.proposer)?;

        let mut recorded_votes = block.bft_votes.clone();
        let mut vote_index = HashSet::new();
        for vote in &recorded_votes {
            vote_index.insert((
                vote.vote.voter.clone(),
                vote.vote.kind,
                vote.vote.round,
                vote.vote.height,
                vote.vote.block_hash.clone(),
            ));
        }
        for vote in archived_votes {
            let key = (
                vote.vote.voter.clone(),
                vote.vote.kind,
                vote.vote.round,
                vote.vote.height,
                vote.vote.block_hash.clone(),
            );
            if vote_index.insert(key) {
                recorded_votes.push(vote);
            }
        }
        block.bft_votes = recorded_votes;

        block.verify(previous_block.as_ref(), &proposer_key)?;

        self.ledger.sync_epoch_for_height(height);

        let participants = round.commit_participants();
        self.ledger
            .record_consensus_witness(height, round.round(), participants);

        for request in &block.identities {
            self.ledger.register_identity(
                request,
                height,
                IDENTITY_ATTESTATION_QUORUM,
                IDENTITY_ATTESTATION_GOSSIP_MIN,
            )?;
        }

        let mut total_fees: u64 = 0;
        for tx in &block.transactions {
            let fee = self
                .ledger
                .select_inputs_for_transaction(tx)
                .and_then(|inputs| self.ledger.apply_transaction(tx, &inputs))?;
            total_fees = total_fees.saturating_add(fee);
        }

        for proof in &block.uptime_proofs {
            if let Err(err) = self.ledger.apply_uptime_proof(proof) {
                match err {
                    ChainError::Transaction(message)
                        if message == "uptime proof does not extend the recorded online window" =>
                    {
                        debug!(
                            identity = %proof.wallet_address,
                            "skipping previously applied uptime proof"
                        );
                    }
                    other => return Err(other),
                }
            }
        }

        let block_reward = BASE_BLOCK_REWARD.saturating_add(total_fees);
        self.ledger.distribute_consensus_rewards(
            &block.header.proposer,
            round.validators(),
            block_reward,
            LEADER_BONUS_PERCENT,
        )?;

        let produced_witnesses = self.ledger.drain_module_witnesses();
        let produced_bytes =
            bincode::serialize(&produced_witnesses).map_err(ChainError::Serialization)?;
        let block_bytes =
            bincode::serialize(&block.module_witnesses).map_err(ChainError::Serialization)?;
        if produced_bytes != block_bytes {
            return Err(ChainError::Config(
                "module witness bundle mismatch for external block".into(),
            ));
        }
        let module_artifacts = self.ledger.stage_module_witnesses(&produced_witnesses)?;
        for artifact in module_artifacts {
            if !block.proof_artifacts.iter().any(|existing| {
                existing.module == artifact.module
                    && existing.commitment == artifact.commitment
                    && existing.proof == artifact.proof
            }) {
                return Err(ChainError::Config(
                    "external block missing module proof artifact".into(),
                ));
            }
        }

        let mut touched_identities: HashSet<Address> = HashSet::new();
        for tx in &block.transactions {
            touched_identities.insert(tx.payload.from.clone());
            touched_identities.insert(tx.payload.to.clone());
        }
        for identity in &block.identities {
            touched_identities.insert(identity.declaration.genesis.wallet_addr.clone());
        }
        for update in &block.timetoke_updates {
            touched_identities.insert(update.identity.clone());
        }
        let mut expected_reputation = Vec::new();
        for identity in touched_identities {
            if let Some(audit) = self.ledger.reputation_audit(&identity)? {
                expected_reputation.push(ReputationUpdate::from(audit));
            }
        }
        expected_reputation.sort_by(|a, b| a.identity.cmp(&b.identity));
        let expected_bytes =
            bincode::serialize(&expected_reputation).map_err(ChainError::Serialization)?;
        let provided_bytes =
            bincode::serialize(&block.reputation_updates).map_err(ChainError::Serialization)?;
        if expected_bytes != provided_bytes {
            return Err(ChainError::Config(
                "external block reputation updates mismatch ledger state".into(),
            ));
        }

        let state_proof_artifact = block.stark.state_proof.clone();
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
        info!(
            height = tip.height,
            proposer = %block.header.proposer,
            "sealed external block"
        );
        drop(tip);

        self.evidence_pool
            .write()
            .prune_below(block.header.height.saturating_add(1));
        self.prune_consensus_rounds_below(block.header.height.saturating_add(1));

        Ok(FinalizationOutcome::Sealed {
            tip_height: block.header.height,
            block,
        })
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
            let proposer_key = self.ledger.validator_public_key(&block.header.proposer)?;
            block.verify(None, &proposer_key)?;
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

    fn network_identity_profile(&self) -> ChainResult<NetworkIdentityProfile> {
        let account = self
            .ledger
            .get_account(&self.address)
            .ok_or_else(|| ChainError::Config("node account missing in ledger".into()))?;
        let tier_level = tier_to_level(&account.reputation.tier);
        let zsi_id = account.reputation.zsi.public_key_commitment.clone();
        let vrf_public_key = self.vrf_keypair.public.to_bytes().to_vec();
        let template = HandshakePayload::new(
            zsi_id.clone(),
            Some(vrf_public_key.clone()),
            None,
            tier_level,
        );
        let sr_keypair = self.vrf_keypair.secret.expand_to_keypair();
        let signature = sr_keypair.sign_simple(VRF_HANDSHAKE_CONTEXT, &template.vrf_message());
        let vrf_proof = signature.to_bytes().to_vec();
        Ok(NetworkIdentityProfile {
            zsi_id,
            tier: tier_level,
            vrf_public_key,
            vrf_proof,
        })
    }
}

fn tier_to_level(tier: &Tier) -> TierLevel {
    match tier {
        Tier::Tl0 => TierLevel::Tl0,
        Tier::Tl1 => TierLevel::Tl1,
        Tier::Tl2 => TierLevel::Tl2,
        Tier::Tl3 => TierLevel::Tl3,
        Tier::Tl4 => TierLevel::Tl4,
        Tier::Tl5 => TierLevel::Tl5,
    }
}

pub(super) async fn send_telemetry_with_tracking(
    client: &reqwest::Client,
    config: &TelemetryConfig,
    snapshot: &NodeTelemetrySnapshot,
    telemetry_last_height: &RwLock<Option<u64>>,
) -> ChainResult<()> {
    dispatch_telemetry_snapshot(client, config.endpoint.as_deref(), snapshot).await?;
    *telemetry_last_height.write() = Some(snapshot.node.height);
    Ok(())
}

pub(super) async fn dispatch_telemetry_snapshot(
    client: &reqwest::Client,
    endpoint: Option<&str>,
    snapshot: &NodeTelemetrySnapshot,
) -> ChainResult<()> {
    let encoded = serde_json::to_string(snapshot)
        .map_err(|err| ChainError::Config(format!("unable to encode telemetry snapshot: {err}")))?;

    match endpoint {
        Some(endpoint) if !endpoint.is_empty() => {
            info!(target = "telemetry", ?endpoint, payload = %encoded, "telemetry snapshot dispatching");
            let response = match client.post(endpoint).json(snapshot).send().await {
                Ok(response) => response,
                Err(err) => {
                    warn!(
                        target = "telemetry",
                        ?endpoint,
                        error = %err,
                        "telemetry snapshot dispatch failed"
                    );
                    return Err(ChainError::Config(format!(
                        "unable to dispatch telemetry snapshot: {err}"
                    )));
                }
            };

            if !response.status().is_success() {
                let status = response.status();
                let body = match response.text().await {
                    Ok(body) => body,
                    Err(err) => {
                        warn!(
                            target = "telemetry",
                            ?endpoint,
                            %status,
                            error = %err,
                            "failed to read telemetry endpoint response"
                        );
                        String::new()
                    }
                };
                warn!(
                    target = "telemetry",
                    ?endpoint,
                    %status,
                    body = %body,
                    "telemetry snapshot dispatch failed"
                );
                return Err(ChainError::Config(format!(
                    "telemetry endpoint responded with status {status}"
                )));
            }

            info!(
                target = "telemetry",
                ?endpoint,
                payload = %encoded,
                "telemetry snapshot dispatched"
            );
        }
        _ => {
            info!(target = "telemetry", payload = %encoded, "telemetry snapshot");
        }
    }

    Ok(())
}

#[cfg(test)]
mod telemetry_tests {
    use super::{
        ConsensusStatus, FeatureGates, MempoolStatus, NodeStatus, NodeTelemetrySnapshot,
        ReleaseChannel, TelemetryConfig, TimetokeParams, dispatch_telemetry_snapshot,
        send_telemetry_with_tracking,
    };
    use crate::vrf::VrfSelectionMetrics;
    use axum::http::StatusCode;
    use axum::{Router, routing::post};
    use parking_lot::RwLock;
    use reqwest::Client;
    use std::net::SocketAddr;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::sync::oneshot;
    use tracing_test::traced_test;

    #[tokio::test]
    async fn telemetry_dispatch_posts_and_updates_height() {
        let (addr, counter, shutdown) = spawn_test_server(StatusCode::OK).await;
        let endpoint = format!("http://{addr}/");
        let config = TelemetryConfig {
            enabled: true,
            endpoint: Some(endpoint),
            auth_token: None,
            timeout_ms: 5_000,
            retry_max: 3,
            sample_interval_secs: 1,
            redact_logs: true,
        };
        let client = Client::new();
        let snapshot = sample_snapshot(42);
        let last_height = RwLock::new(None);

        send_telemetry_with_tracking(&client, &config, &snapshot, &last_height)
            .await
            .expect("dispatch succeeds");

        assert_eq!(counter.load(Ordering::SeqCst), 1);
        assert_eq!(*last_height.read(), Some(42));
        let _ = shutdown.send(());
    }

    #[tokio::test]
    #[traced_test]
    async fn telemetry_dispatch_logs_on_failure_and_preserves_height() {
        let (addr, counter, shutdown) = spawn_test_server(StatusCode::INTERNAL_SERVER_ERROR).await;
        let endpoint = format!("http://{addr}/");
        let config = TelemetryConfig {
            enabled: true,
            endpoint: Some(endpoint),
            auth_token: None,
            timeout_ms: 5_000,
            retry_max: 3,
            sample_interval_secs: 1,
            redact_logs: true,
        };
        let client = Client::new();
        let snapshot = sample_snapshot(24);
        let last_height = RwLock::new(None);

        let result = send_telemetry_with_tracking(&client, &config, &snapshot, &last_height).await;

        assert!(result.is_err());
        assert_eq!(counter.load(Ordering::SeqCst), 1);
        assert_eq!(*last_height.read(), None);
        assert!(logs_contain("telemetry snapshot dispatch failed"));
        let _ = shutdown.send(());
    }

    #[tokio::test]
    #[traced_test]
    async fn telemetry_dispatch_falls_back_to_logging_without_endpoint() {
        let config = TelemetryConfig {
            enabled: true,
            endpoint: None,
            auth_token: None,
            timeout_ms: 5_000,
            retry_max: 3,
            sample_interval_secs: 1,
            redact_logs: true,
        };
        let client = Client::new();
        let snapshot = sample_snapshot(7);
        let last_height = RwLock::new(None);

        send_telemetry_with_tracking(&client, &config, &snapshot, &last_height)
            .await
            .expect("dispatch succeeds");

        assert_eq!(*last_height.read(), Some(7));
        assert!(logs_contain("telemetry snapshot"));
    }

    #[tokio::test]
    async fn telemetry_dispatch_invokes_endpoint_directly() {
        let (addr, counter, shutdown) = spawn_test_server(StatusCode::OK).await;
        let endpoint = format!("http://{addr}/");
        let client = Client::new();
        let snapshot = sample_snapshot(99);

        dispatch_telemetry_snapshot(&client, Some(&endpoint), &snapshot)
            .await
            .expect("dispatch succeeds");

        assert_eq!(counter.load(Ordering::SeqCst), 1);
        let _ = shutdown.send(());
    }

    fn sample_snapshot(height: u64) -> NodeTelemetrySnapshot {
        NodeTelemetrySnapshot {
            release_channel: ReleaseChannel::Development,
            feature_gates: FeatureGates::default(),
            node: NodeStatus {
                address: "addr".into(),
                height,
                last_hash: "hash".into(),
                epoch: 0,
                epoch_nonce: "nonce".into(),
                pending_transactions: 0,
                pending_identities: 0,
                pending_votes: 0,
                pending_uptime_proofs: 0,
                vrf_metrics: VrfSelectionMetrics::default(),
                tip: None,
            },
            consensus: ConsensusStatus {
                height,
                block_hash: None,
                proposer: None,
                round: 0,
                total_power: "0".into(),
                quorum_threshold: "0".into(),
                pre_vote_power: "0".into(),
                pre_commit_power: "0".into(),
                commit_power: "0".into(),
                quorum_reached: false,
                observers: 0,
                epoch: 0,
                epoch_nonce: "nonce".into(),
                pending_votes: 0,
            },
            mempool: MempoolStatus {
                transactions: Vec::new(),
                identities: Vec::new(),
                votes: Vec::new(),
                uptime_proofs: Vec::new(),
            },
            timetoke_params: TimetokeParams::default(),
        }
    }

    async fn spawn_test_server(
        status: StatusCode,
    ) -> (SocketAddr, Arc<AtomicUsize>, oneshot::Sender<()>) {
        let counter = Arc::new(AtomicUsize::new(0));
        let counter_clone = counter.clone();

        let app = Router::new().route(
            "/",
            post(move |_body: axum::body::Bytes| {
                let counter = counter_clone.clone();
                async move {
                    counter.fetch_add(1, Ordering::SeqCst);
                    (status, ())
                }
            }),
        );

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind test listener");
        let addr = listener.local_addr().expect("listener addr");
        let (shutdown_tx, shutdown_rx) = oneshot::channel();

        tokio::spawn(async move {
            axum::serve(listener, app)
                .with_graceful_shutdown(async {
                    let _ = shutdown_rx.await;
                })
                .await
                .expect("serve test telemetry");
        });

        (addr, counter, shutdown_tx)
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
