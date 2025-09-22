use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

use tokio::sync::mpsc::{unbounded_channel, UnboundedReceiver, UnboundedSender};

use crate::bft_loop::ConsensusMessage;
use crate::leader::{elect_leader, LeaderContext};
use crate::messages::{Commit, ConsensusProof, PreCommit, PreVote, Proposal};
use crate::rewards::{distribute_rewards, RewardDistribution};
use crate::validator::{select_validators, Validator, ValidatorId, ValidatorSet, VRFOutput};
use crate::ConsensusError;

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
}

impl ConsensusConfig {
    pub fn new(view_timeout_ms: u64, precommit_timeout_ms: u64, base_reward: u64, leader_bonus: f64) -> Self {
        Self {
            view_timeout: Duration::from_millis(view_timeout_ms),
            precommit_timeout: Duration::from_millis(precommit_timeout_ms),
            base_reward,
            leader_bonus,
        }
    }
}

#[derive(Clone, Debug)]
pub struct GenesisConfig {
    pub epoch: u64,
    pub validator_outputs: Vec<VRFOutput>,
    pub reputation_root: String,
    pub config: ConsensusConfig,
}

impl GenesisConfig {
    pub fn new(epoch: u64, validator_outputs: Vec<VRFOutput>, reputation_root: String, config: ConsensusConfig) -> Self {
        Self {
            epoch,
            validator_outputs,
            reputation_root,
            config,
        }
    }
}

#[derive(Default, Clone, Debug)]
struct VoteTally {
    pub power: u64,
    pub voters: HashSet<ValidatorId>,
}

impl VoteTally {
    fn new() -> Self {
        Self {
            power: 0,
            voters: HashSet::new(),
        }
    }

    fn insert(&mut self, validator: &Validator, threshold: u64) -> bool {
        if self.voters.insert(validator.id.clone()) {
            self.power = self.power.saturating_add(validator.voting_power());
        }
        self.power >= threshold
    }

    fn voters(&self) -> Vec<ValidatorId> {
        self.voters.iter().cloned().collect()
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
    pub pending_commits: VecDeque<Commit>,
    pub pending_proofs: Vec<ConsensusProof>,
    pub pending_evidence: Vec<crate::evidence::EvidenceRecord>,
    pub pending_rewards: Vec<RewardDistribution>,
    pub reputation_root: String,
    message_rx: Option<UnboundedReceiver<ConsensusMessage>>,
    _message_tx: UnboundedSender<ConsensusMessage>,
    pub last_activity: Instant,
    pub halted: bool,
}

impl ConsensusState {
    pub fn new(genesis: GenesisConfig) -> Result<Self, ConsensusError> {
        let validator_set = select_validators(genesis.epoch, &genesis.validator_outputs);
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
            pending_commits: VecDeque::new(),
            pending_proofs: Vec::new(),
            pending_evidence: Vec::new(),
            pending_rewards: Vec::new(),
            reputation_root: genesis.reputation_root,
            message_rx: Some(receiver),
            _message_tx: sender,
            last_activity: Instant::now(),
            halted: false,
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

    pub fn record_prevote(&mut self, vote: PreVote) -> bool {
        let block_hash = vote.block_hash.0.clone();
        let validator = match self.validator_set.get(&vote.validator_id) {
            Some(validator) => validator.clone(),
            None => return false,
        };
        let tally = self
            .pending_prevotes
            .entry(block_hash)
            .or_insert_with(VoteTally::new);
        tally.insert(&validator, self.validator_set.quorum_threshold)
    }

    pub fn record_precommit(&mut self, vote: PreCommit) -> bool {
        let block_hash = vote.block_hash.0.clone();
        let validator = match self.validator_set.get(&vote.validator_id) {
            Some(validator) => validator.clone(),
            None => return false,
        };
        let tally = self
            .pending_precommits
            .entry(block_hash)
            .or_insert_with(VoteTally::new);
        tally.insert(&validator, self.validator_set.quorum_threshold)
    }

    pub fn precommit_voters(&self, block_hash: &str) -> Vec<ValidatorId> {
        self.pending_precommits
            .get(block_hash)
            .map(|tally| tally.voters())
            .unwrap_or_default()
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
        self.mark_activity();
    }

    pub fn update_leader(&mut self) {
        let context = LeaderContext {
            epoch: self.epoch,
            round: self.round,
        };
        self.current_leader = elect_leader(&self.validator_set, context).map(|leader| leader.validator);
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

    pub fn record_evidence(&mut self, evidence: crate::evidence::EvidenceRecord) {
        self.pending_evidence.push(evidence);
    }

    pub fn find_proposal(&self, block_hash: &str) -> Option<&Proposal> {
        self.pending_proposals
            .iter()
            .rev()
            .find(|proposal| proposal.block_hash().0 == block_hash)
    }

    pub fn apply_commit(&mut self, commit: Commit) {
        self.block_height = commit.block.height;
        self.record_proof(commit.proof.clone());
        if let Some(leader) = self.current_leader.clone() {
            let rewards = distribute_rewards(
                &self.validator_set,
                &leader,
                self.block_height,
                self.config.base_reward,
                self.config.leader_bonus,
            );
            self.record_reward(rewards);
        }
        self.pending_prevotes.clear();
        self.pending_precommits.clear();
        self.pending_proposals.clear();
        self.pending_commits.clear();
        self.mark_activity();
    }

    pub fn recompute_totals(&mut self) {
        let total: u64 = self.validator_set.validators.iter().map(|v| v.voting_power()).sum();
        self.validator_set.total_voting_power = total;
        self.validator_set.quorum_threshold = (total * 2) / 3 + 1;
    }

}

pub fn initialize_state(
    epoch: u64,
    vrf_outputs: Vec<VRFOutput>,
    reputation_root: String,
    view_timeout_ms: u64,
    precommit_timeout_ms: u64,
    base_reward: u64,
    leader_bonus: f64,
) -> Result<ConsensusState, ConsensusError> {
    let config = ConsensusConfig::new(view_timeout_ms, precommit_timeout_ms, base_reward, leader_bonus);
    let genesis = GenesisConfig::new(epoch, vrf_outputs, reputation_root, config);
    ConsensusState::new(genesis)
}
