use std::collections::{BTreeMap, HashMap, VecDeque};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use libp2p::PeerId;
use tokio::sync::mpsc::{unbounded_channel, UnboundedReceiver, UnboundedSender};

use crate::bft_loop::ConsensusMessage;
use crate::evidence::{slash, EvidenceRecord, EvidenceType};
use crate::leader::{elect_leader, Leader, LeaderContext};
use crate::messages::{
    BlockId, Commit, ConsensusCertificate, ConsensusProof, PreCommit, PreVote, Proposal, Signature,
    TalliedVote,
};
use crate::proof_backend::ProofBackend;
use crate::rewards::{distribute_rewards, RewardDistribution};
use crate::validator::{
    select_validators, VRFOutput, Validator, ValidatorId, ValidatorLedgerEntry, ValidatorSet,
};
use crate::{ConsensusError, ConsensusResult};

static MESSAGE_SENDER: OnceLock<Mutex<Option<UnboundedSender<ConsensusMessage>>>> = OnceLock::new();

pub(crate) fn register_message_sender(
    sender: Option<UnboundedSender<ConsensusMessage>>,
) -> Option<UnboundedSender<ConsensusMessage>> {
    let lock = MESSAGE_SENDER.get_or_init(|| Mutex::new(None));
    let mut guard = lock.lock().expect("sender lock poisoned");
    if let Some(sender) = sender {
        *guard = Some(sender);
    }
    guard.clone()
}

#[derive(Clone, Debug)]
pub struct ConsensusConfig {
    pub view_timeout: Duration,
    pub precommit_timeout: Duration,
    pub base_reward: u64,
    pub leader_bonus: f64,
    pub witness_reward: u64,
    pub false_proof_penalty: u64,
    pub censorship_penalty: u64,
}

impl ConsensusConfig {
    pub fn new(
        view_timeout_ms: u64,
        precommit_timeout_ms: u64,
        base_reward: u64,
        leader_bonus: f64,
    ) -> Self {
        Self {
            view_timeout: Duration::from_millis(view_timeout_ms),
            precommit_timeout: Duration::from_millis(precommit_timeout_ms),
            base_reward,
            leader_bonus,
            witness_reward: base_reward.saturating_div(2),
            false_proof_penalty: base_reward,
            censorship_penalty: base_reward.saturating_div(2).max(1),
        }
    }

    pub fn with_witness_params(
        mut self,
        witness_reward: u64,
        false_proof_penalty: u64,
        censorship_penalty: u64,
    ) -> Self {
        self.witness_reward = witness_reward;
        self.false_proof_penalty = false_proof_penalty;
        self.censorship_penalty = censorship_penalty;
        self
    }
}

#[derive(Clone, Debug)]
pub struct GenesisConfig {
    pub epoch: u64,
    pub validator_outputs: Vec<VRFOutput>,
    pub validator_ledger: BTreeMap<ValidatorId, ValidatorLedgerEntry>,
    pub reputation_root: String,
    pub config: ConsensusConfig,
}

impl GenesisConfig {
    pub fn new(
        epoch: u64,
        validator_outputs: Vec<VRFOutput>,
        validator_ledger: BTreeMap<ValidatorId, ValidatorLedgerEntry>,
        reputation_root: String,
        config: ConsensusConfig,
    ) -> Self {
        Self {
            epoch,
            validator_outputs,
            validator_ledger,
            reputation_root,
            config,
        }
    }
}

#[derive(Clone, Debug)]
pub enum VoteRecordOutcome {
    Counted { quorum_reached: bool },
    Duplicate,
    InvalidSignature,
    UnknownValidator,
    Conflict { evidence: EvidenceRecord },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum VotePhase {
    Prevote,
    Precommit,
}

#[derive(Hash, Clone, Debug, PartialEq, Eq)]
struct VoteKey {
    height: u64,
    round: u64,
    phase: VotePhase,
    validator: ValidatorId,
}

impl VoteKey {
    fn new(height: u64, round: u64, phase: VotePhase, validator: ValidatorId) -> Self {
        Self {
            height,
            round,
            phase,
            validator,
        }
    }
}

#[derive(Clone, Debug)]
struct VoteFingerprint {
    block_hash: String,
    peer_id: PeerId,
    signature: Vec<u8>,
}

#[derive(Clone, Debug)]
pub struct VoteReceipt {
    pub peer_id: PeerId,
    pub signature: Vec<u8>,
    pub voting_power: u64,
}

#[derive(Default, Clone, Debug)]
struct VoteTally {
    pub power: u64,
    pub voters: HashMap<ValidatorId, VoteReceipt>,
}

impl VoteTally {
    fn new() -> Self {
        Self {
            power: 0,
            voters: HashMap::new(),
        }
    }

    fn insert(&mut self, validator: &Validator, mut receipt: VoteReceipt, threshold: u64) -> bool {
        receipt.voting_power = validator.voting_power();
        if !self.voters.contains_key(&validator.id) {
            self.power = self.power.saturating_add(receipt.voting_power);
            self.voters.insert(validator.id.clone(), receipt);
        }
        self.power >= threshold
    }

    fn tallied_votes(&self) -> Vec<TalliedVote> {
        self.voters
            .iter()
            .map(|(id, receipt)| TalliedVote {
                validator_id: id.clone(),
                peer_id: receipt.peer_id.clone(),
                signature: receipt.signature.clone(),
                voting_power: receipt.voting_power,
            })
            .collect()
    }
}

pub struct ConsensusState {
    pub config: ConsensusConfig,
    pub block_height: u64,
    pub epoch: u64,
    pub round: u64,
    pub validator_set: ValidatorSet,
    pub current_leader: Option<Validator>,
    pub pending_proposals: VecDeque<Proposal>,
    pending_prevotes: HashMap<String, VoteTally>,
    pending_precommits: HashMap<String, VoteTally>,
    pub pending_prevote_messages: Vec<PreVote>,
    pub pending_precommit_messages: Vec<PreCommit>,
    pub pending_commits: VecDeque<Commit>,
    pub pending_proofs: Vec<ConsensusProof>,
    pub pending_evidence: Vec<EvidenceRecord>,
    pub pending_rewards: Vec<RewardDistribution>,
    pub reputation_root: String,
    message_rx: Option<UnboundedReceiver<ConsensusMessage>>,
    _message_tx: UnboundedSender<ConsensusMessage>,
    pub last_activity: Instant,
    pub halted: bool,
    recorded_votes: HashMap<VoteKey, VoteFingerprint>,
    witness_rewards: BTreeMap<ValidatorId, u64>,
    pub proof_backend: Arc<dyn ProofBackend>,
    latest_certificate: ConsensusCertificate,
    pending_certificate: Option<ConsensusCertificate>,
}

impl ConsensusState {
    pub fn new(
        genesis: GenesisConfig,
        proof_backend: Arc<dyn ProofBackend>,
    ) -> Result<Self, ConsensusError> {
        let validator_set = select_validators(
            genesis.epoch,
            &genesis.validator_outputs,
            &genesis.validator_ledger,
        );
        let (sender, receiver) = unbounded_channel();
        register_message_sender(Some(sender.clone()));

        let mut state = Self {
            config: genesis.config,
            block_height: 0,
            epoch: genesis.epoch,
            round: 0,
            validator_set,
            current_leader: None,
            pending_proposals: VecDeque::new(),
            pending_prevotes: HashMap::new(),
            pending_precommits: HashMap::new(),
            pending_prevote_messages: Vec::new(),
            pending_precommit_messages: Vec::new(),
            pending_commits: VecDeque::new(),
            pending_proofs: Vec::new(),
            pending_evidence: Vec::new(),
            pending_rewards: Vec::new(),
            reputation_root: genesis.reputation_root,
            message_rx: Some(receiver),
            _message_tx: sender,
            last_activity: Instant::now(),
            halted: false,
            recorded_votes: HashMap::new(),
            witness_rewards: BTreeMap::new(),
            proof_backend,
            latest_certificate: ConsensusCertificate::genesis(),
            pending_certificate: None,
        };

        state.update_leader();
        Ok(state)
    }

    pub(crate) fn message_receiver(&mut self) -> &mut UnboundedReceiver<ConsensusMessage> {
        self.message_rx
            .as_mut()
            .expect("consensus receiver not initialized")
    }

    pub fn push_proposal(&mut self, proposal: Proposal) {
        self.pending_proposals.push_back(proposal);
        self.mark_activity();
    }

    pub fn record_prevote(&mut self, vote: PreVote) -> VoteRecordOutcome {
        if vote.signature.is_empty() {
            return VoteRecordOutcome::InvalidSignature;
        }

        let block_hash = vote.block_hash.0.clone();
        let Some(validator) = self.validator_set.get(&vote.validator_id).cloned() else {
            return VoteRecordOutcome::UnknownValidator;
        };

        let key = VoteKey::new(
            vote.height,
            vote.round,
            VotePhase::Prevote,
            vote.validator_id.clone(),
        );

        match self.ensure_unique_vote(&key, &block_hash, &vote.signature, &vote.peer_id) {
            Ok(true) => {
                if !self
                    .pending_prevote_messages
                    .iter()
                    .any(|existing| existing.signature == vote.signature)
                {
                    self.pending_prevote_messages.push(vote.clone());
                }

                let tally = self
                    .pending_prevotes
                    .entry(block_hash)
                    .or_insert_with(VoteTally::new);
                let receipt = VoteReceipt {
                    peer_id: vote.peer_id.clone(),
                    signature: vote.signature.clone(),
                    voting_power: validator.voting_power(),
                };
                let quorum = tally.insert(&validator, receipt, self.validator_set.quorum_threshold);
                self.mark_activity();
                VoteRecordOutcome::Counted {
                    quorum_reached: quorum,
                }
            }
            Ok(false) => VoteRecordOutcome::Duplicate,
            Err(evidence) => VoteRecordOutcome::Conflict { evidence },
        }
    }

    pub fn record_precommit(&mut self, vote: PreCommit) -> VoteRecordOutcome {
        if vote.signature.is_empty() {
            return VoteRecordOutcome::InvalidSignature;
        }

        let block_hash = vote.block_hash.0.clone();
        let Some(validator) = self.validator_set.get(&vote.validator_id).cloned() else {
            return VoteRecordOutcome::UnknownValidator;
        };

        let key = VoteKey::new(
            vote.height,
            vote.round,
            VotePhase::Precommit,
            vote.validator_id.clone(),
        );

        match self.ensure_unique_vote(&key, &block_hash, &vote.signature, &vote.peer_id) {
            Ok(true) => {
                if !self
                    .pending_precommit_messages
                    .iter()
                    .any(|existing| existing.signature == vote.signature)
                {
                    self.pending_precommit_messages.push(vote.clone());
                }

                let tally = self
                    .pending_precommits
                    .entry(block_hash)
                    .or_insert_with(VoteTally::new);
                let receipt = VoteReceipt {
                    peer_id: vote.peer_id.clone(),
                    signature: vote.signature.clone(),
                    voting_power: validator.voting_power(),
                };
                let quorum = tally.insert(&validator, receipt, self.validator_set.quorum_threshold);
                self.mark_activity();
                VoteRecordOutcome::Counted {
                    quorum_reached: quorum,
                }
            }
            Ok(false) => VoteRecordOutcome::Duplicate,
            Err(evidence) => VoteRecordOutcome::Conflict { evidence },
        }
    }

    fn ensure_unique_vote(
        &mut self,
        key: &VoteKey,
        block_hash: &str,
        signature: &[u8],
        peer_id: &PeerId,
    ) -> Result<bool, EvidenceRecord> {
        if let Some(existing) = self.recorded_votes.get(key) {
            if existing.block_hash != block_hash {
                let evidence = EvidenceRecord {
                    reporter: key.validator.clone(),
                    accused: key.validator.clone(),
                    evidence: EvidenceType::DoubleSign { height: key.height },
                };
                return Err(evidence);
            }

            if existing.signature == signature && existing.peer_id == *peer_id {
                return Ok(false);
            }

            return Ok(false);
        }

        self.recorded_votes.insert(
            key.clone(),
            VoteFingerprint {
                block_hash: block_hash.to_string(),
                peer_id: peer_id.clone(),
                signature: signature.to_vec(),
            },
        );

        Ok(true)
    }

    pub fn precommit_signatures(&self, block_hash: &str) -> Vec<Signature> {
        self.pending_precommits
            .get(block_hash)
            .map(|tally| {
                tally
                    .tallied_votes()
                    .into_iter()
                    .map(|vote| Signature {
                        validator_id: vote.validator_id,
                        peer_id: vote.peer_id,
                        signature: vote.signature,
                    })
                    .collect()
            })
            .unwrap_or_default()
    }

    pub fn consensus_certificate(&self) -> &ConsensusCertificate {
        &self.latest_certificate
    }

    pub fn build_certificate(
        &self,
        block_hash: &str,
        height: u64,
        round: u64,
    ) -> ConsensusCertificate {
        let prevote_tally = self
            .pending_prevotes
            .get(block_hash)
            .map(|tally| (tally.power, tally.tallied_votes()))
            .unwrap_or_default();
        let precommit_tally = self
            .pending_precommits
            .get(block_hash)
            .map(|tally| (tally.power, tally.tallied_votes()))
            .unwrap_or_default();

        let (prevote_power, prevotes) = prevote_tally;
        let (precommit_power, precommits) = precommit_tally;

        ConsensusCertificate {
            block_hash: BlockId(block_hash.to_string()),
            height,
            round,
            total_power: self.validator_set.total_voting_power,
            quorum_threshold: self.validator_set.quorum_threshold,
            prevote_power,
            precommit_power,
            commit_power: precommit_power,
            prevotes,
            precommits,
        }
    }

    pub fn stage_certificate(&mut self, certificate: ConsensusCertificate) {
        self.pending_certificate = Some(certificate);
    }

    pub fn queue_commit(&mut self, commit: Commit) {
        self.pending_commits.push_back(commit);
        self.mark_activity();
    }

    pub fn mark_activity(&mut self) {
        self.last_activity = Instant::now();
    }

    pub fn should_timeout(&self, now: Instant) -> bool {
        now.duration_since(self.last_activity) >= self.config.view_timeout
    }

    pub fn next_round(&mut self) {
        self.round = self.round.saturating_add(1);
        self.update_leader();
        self.pending_prevotes.clear();
        self.pending_precommits.clear();
        self.recorded_votes
            .retain(|key, _| key.round >= self.round && key.height >= self.block_height);
        self.mark_activity();
    }

    pub fn update_leader(&mut self) {
        let context = LeaderContext {
            epoch: self.epoch,
            round: self.round,
        };
        self.current_leader =
            elect_leader(&self.validator_set, context).map(|leader| leader.validator);
    }

    pub fn take_commit(&mut self) -> Option<Commit> {
        self.pending_commits.pop_front()
    }

    pub fn record_proof(&mut self, proof: ConsensusProof) {
        self.pending_proofs.push(proof);
    }

    pub fn record_reward(&mut self, reward: RewardDistribution) {
        self.pending_rewards.push(reward);
    }

    pub fn record_evidence(&mut self, evidence: EvidenceRecord) {
        self.apply_witness_evidence(&evidence);
        self.pending_evidence.push(evidence);
    }

    pub fn witness_reward_balance(&self, witness: &ValidatorId) -> u64 {
        self.witness_rewards
            .get(witness)
            .copied()
            .unwrap_or_default()
    }

    pub fn find_proposal(&self, block_hash: &str) -> Option<&Proposal> {
        self.pending_proposals
            .iter()
            .rev()
            .find(|proposal| proposal.block_hash().0 == block_hash)
    }

    pub fn apply_commit(&mut self, commit: Commit) {
        let committed_hash = commit.block.hash();
        self.block_height = commit.block.height;
        if let Some(certificate) = self.pending_certificate.take() {
            self.latest_certificate = certificate;
        } else {
            self.latest_certificate = commit.certificate.clone();
        }
        self.record_proof(commit.proof.clone());
        if let Some(leader) = self.current_leader.clone() {
            let mut rewards = distribute_rewards(
                &self.validator_set,
                &leader,
                self.block_height,
                self.config.base_reward,
                self.config.leader_bonus,
            );
            rewards.witness_rewards = self.drain_witness_rewards();
            self.record_reward(rewards);
        } else {
            self.drain_witness_rewards();
        }
        self.pending_prevotes.clear();
        self.pending_precommits.clear();
        self.pending_proposals.clear();
        self.pending_commits.clear();
        self.pending_prevote_messages
            .retain(|vote| vote.block_hash != committed_hash);
        self.pending_precommit_messages
            .retain(|vote| vote.block_hash != committed_hash);
        self.recorded_votes.clear();
        self.mark_activity();
    }

    pub fn broadcast_pending_messages(&self) -> ConsensusResult<()> {
        for proposal in &self.pending_proposals {
            self._message_tx
                .send(ConsensusMessage::Proposal(proposal.clone()))
                .map_err(|_| ConsensusError::ChannelClosed)?;
        }
        for vote in &self.pending_prevote_messages {
            self._message_tx
                .send(ConsensusMessage::PreVote(vote.clone()))
                .map_err(|_| ConsensusError::ChannelClosed)?;
        }
        for vote in &self.pending_precommit_messages {
            self._message_tx
                .send(ConsensusMessage::PreCommit(vote.clone()))
                .map_err(|_| ConsensusError::ChannelClosed)?;
        }
        Ok(())
    }

    pub fn broadcast_proposal(&self, proposal: &Proposal) -> ConsensusResult<()> {
        self._message_tx
            .send(ConsensusMessage::Proposal(proposal.clone()))
            .map_err(|_| ConsensusError::ChannelClosed)
    }

    pub fn build_current_leader_proposal(&self) -> Option<Proposal> {
        let leader = self.current_leader.clone()?;
        let leader = Leader::new(leader);
        let context = LeaderContext {
            epoch: self.epoch,
            round: self.round,
        };
        leader.build_proposal(self, context)
    }

    pub fn recompute_totals(&mut self) {
        let total: u64 = self
            .validator_set
            .validators
            .iter()
            .map(|v| v.voting_power())
            .sum();
        self.validator_set.total_voting_power = total;
        self.validator_set.quorum_threshold = (total * 2) / 3 + 1;
    }
}

pub fn initialize_state(
    epoch: u64,
    vrf_outputs: Vec<VRFOutput>,
    validator_ledger: BTreeMap<ValidatorId, ValidatorLedgerEntry>,
    reputation_root: String,
    view_timeout_ms: u64,
    precommit_timeout_ms: u64,
    base_reward: u64,
    leader_bonus: f64,
    proof_backend: Arc<dyn ProofBackend>,
) -> Result<ConsensusState, ConsensusError> {
    let config = ConsensusConfig::new(
        view_timeout_ms,
        precommit_timeout_ms,
        base_reward,
        leader_bonus,
    );
    let genesis = GenesisConfig::new(
        epoch,
        vrf_outputs,
        validator_ledger,
        reputation_root,
        config,
    );
    ConsensusState::new(genesis, proof_backend)
}

impl ConsensusState {
    fn drain_witness_rewards(&mut self) -> BTreeMap<ValidatorId, u64> {
        if self.witness_rewards.is_empty() {
            return BTreeMap::new();
        }
        std::mem::take(&mut self.witness_rewards)
    }

    fn apply_witness_evidence(&mut self, record: &EvidenceRecord) {
        if self.config.witness_reward > 0 {
            let entry = self
                .witness_rewards
                .entry(record.reporter.clone())
                .or_insert(0);
            *entry = entry.saturating_add(self.config.witness_reward);
        }

        match record.evidence {
            EvidenceType::DoubleSign { .. } => {
                let penalty = self.config.false_proof_penalty.saturating_mul(2);
                if penalty > 0 {
                    slash(&record.accused, penalty, self);
                }
            }
            EvidenceType::FalseProof { .. } => {
                if self.config.false_proof_penalty > 0 {
                    slash(&record.accused, self.config.false_proof_penalty, self);
                }
            }
            EvidenceType::VoteWithholding { .. } => {
                if self.config.censorship_penalty > 0 {
                    slash(&record.accused, self.config.censorship_penalty, self);
                }
            }
        }
    }
}
