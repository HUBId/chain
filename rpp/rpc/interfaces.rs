use std::collections::HashMap;

use malachite::Natural;
use serde::{Deserialize, Serialize};

use crate::consensus::SignedBftVote;
use crate::errors::ChainResult;
use crate::orchestration::PipelineDashboardSnapshot;
use crate::reputation::{ReputationProfile, Tier};
use crate::rpp::TimetokeRecord;
use crate::types::{
    Address, Block, BlockProofBundle, SignedTransaction, TransactionProofBundle, UptimeProof,
};
use crate::vrf::{VrfProof, VrfSubmission};
#[cfg(feature = "wallet-integration")]
use crate::wallet::{
    ConsensusReceipt, HistoryEntry, NodeTabMetrics, ReceiveTabAddress, ScriptStatusMetadata,
    SendPreview, Wallet,
};
#[cfg(all(feature = "wallet-integration", feature = "vendor_electrs"))]
use crate::wallet::{TrackedScriptSnapshot, TrackerSnapshot};

/// Identifier used for epoch-specific consensus state.
pub type EpochId = u64;

/// Identifier used for consensus rounds within an epoch.
pub type RoundId = u64;

/// Snapshot of a validator that is eligible for selection into the committee.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ValidatorProfile {
    pub address: Address,
    pub stake: Natural,
    pub reputation: ReputationProfile,
    pub timetoke: TimetokeRecord,
    pub custom_metadata: HashMap<String, String>,
}

impl ValidatorProfile {
    pub fn new(
        address: Address,
        stake: Natural,
        reputation: ReputationProfile,
        timetoke: TimetokeRecord,
    ) -> Self {
        Self {
            address,
            stake,
            reputation,
            timetoke,
            custom_metadata: HashMap::new(),
        }
    }
}

/// Validator candidate enriched with VRF output data for selection.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ValidatorCandidate {
    pub profile: ValidatorProfile,
    pub vrf_output: Natural,
    pub vrf_proof: VrfProof,
}

/// Witness node metadata communicated during assignments.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WitnessProfile {
    pub address: Address,
    pub tier: Tier,
    pub reliability_score: f64,
}

/// Ordered validator set for an epoch along with dedicated witnesses.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ValidatorSet {
    pub epoch: EpochId,
    pub members: Vec<ValidatorCandidate>,
    pub witnesses: Vec<WitnessProfile>,
}

impl ValidatorSet {
    pub fn top_validator(&self) -> Option<&ValidatorCandidate> {
        self.members.first()
    }
}

/// Leader election result for a specific epoch and round.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LeaderAssignment {
    pub epoch: EpochId,
    pub round: RoundId,
    pub leader: Address,
    pub tier: Tier,
    pub timetoke_hours: u64,
    pub vrf_output: Natural,
    pub witnesses: Vec<WitnessProfile>,
}

/// Structured reward payout emitted by the reward engine.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RewardPayout {
    pub recipient: Address,
    pub role: RewardRole,
    pub amount: Natural,
}

/// Identifies the role a validator or witness played during reward distribution.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum RewardRole {
    Leader,
    Validator,
    Witness,
}

/// Logical broadcast channels used by the consensus overlay network.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum ConsensusChannel {
    Blocks,
    Votes,
    Proofs,
    Snapshots,
    Meta,
}

/// Summary emitted by witness nodes once verification concludes.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WitnessVerdict {
    pub block_hash: String,
    pub accepted: bool,
    pub notes: Option<String>,
}

/// Report generated when a witness observes misbehavior.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WitnessReport {
    pub offender: Address,
    pub category: MisbehaviorCategory,
    pub evidence: String,
}

/// Blueprint-aligned misbehavior categories captured by witnesses.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum MisbehaviorCategory {
    DoubleSign,
    FakeProof,
    Censorship,
    Inactivity,
    Custom(String),
}

/// High-level state returned to lightweight clients querying the network.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ClientStatus {
    pub height: u64,
    pub epoch: EpochId,
    pub leader: Option<Address>,
    pub validator_set_size: usize,
}

/// Trait representing the consensus engine integration points required by the blueprint.
pub trait ConsensusEngine {
    fn current_epoch(&self) -> EpochId;
    fn validator_set(&self, epoch: EpochId) -> ChainResult<ValidatorSet>;
    fn leader_for(&self, epoch: EpochId, round: RoundId) -> ChainResult<LeaderAssignment>;
    fn submit_vrf(&self, submission: VrfSubmission) -> ChainResult<()>;
    fn submit_proposal(&self, block: Block) -> ChainResult<()>;
    fn submit_vote(&self, vote: SignedBftVote) -> ChainResult<()>;
}

/// Abstraction responsible for filtering candidates and building the validator set.
pub trait ValidatorSelector {
    fn select(&self, epoch: EpochId, profiles: Vec<ValidatorProfile>) -> ChainResult<ValidatorSet>;
}

/// Strategy trait for deriving a leader from a validator set.
pub trait LeaderStrategy {
    fn elect(
        &self,
        epoch: EpochId,
        round: RoundId,
        set: &ValidatorSet,
    ) -> ChainResult<LeaderAssignment>;
}

/// Coordinates the assignment and reporting flow for witness nodes.
pub trait WitnessCoordinator {
    fn assign_witnesses(
        &self,
        epoch: EpochId,
        set: &ValidatorSet,
    ) -> ChainResult<Vec<WitnessProfile>>;
    fn record_verdict(&self, verdict: WitnessVerdict) -> ChainResult<()>;
    fn record_report(&self, report: WitnessReport) -> ChainResult<()>;
}

/// Reward distribution engine honouring validator and leader roles.
pub trait RewardDistributor {
    fn calculate_payouts(
        &self,
        assignment: &LeaderAssignment,
        set: &ValidatorSet,
        base_reward: Natural,
    ) -> ChainResult<Vec<RewardPayout>>;

    fn apply(&self, payouts: &[RewardPayout]) -> ChainResult<()>;
}

/// Network abstraction exposing blueprint-defined gossip channels.
pub trait ConsensusNetwork {
    fn broadcast_block(&self, block: &Block) -> ChainResult<()>;
    fn broadcast_vote(&self, vote: &SignedBftVote) -> ChainResult<()>;
    fn broadcast_vrf_submission(&self, submission: &VrfSubmission) -> ChainResult<()>;
    fn broadcast_proof(&self, proof: &BlockProofBundle) -> ChainResult<()>;
    fn broadcast_snapshot(&self, records: &[TimetokeRecord]) -> ChainResult<()>;
    fn broadcast_meta(&self, event: &NetworkMetaEvent) -> ChainResult<()>;
}

/// Metadata messages circulated on the meta channel.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NetworkMetaEvent {
    pub epoch: EpochId,
    pub address: Address,
    pub tier: Tier,
    pub message: String,
}

/// Primary responsibilities of a validator node participating in consensus.
#[cfg(feature = "wallet-integration")]
pub trait ValidatorNode {
    fn wallet(&self) -> &Wallet;
    fn profile(&self) -> ChainResult<ValidatorProfile>;
    fn submit_vrf(&self, submission: VrfSubmission) -> ChainResult<()>;
    fn propose_block(&self, block: Block) -> ChainResult<()>;
    fn cast_vote(&self, vote: SignedBftVote) -> ChainResult<()>;
    fn receive_rewards(&self, payouts: &[RewardPayout]) -> ChainResult<()>;
}

/// Responsibilities for witness nodes that attest to consensus events.
pub trait WitnessNode {
    fn identity(&self) -> Address;
    fn assigned_epoch(&self) -> EpochId;
    fn verify_block(
        &self,
        block: &Block,
        proofs: &BlockProofBundle,
        transactions: &[TransactionProofBundle],
    ) -> ChainResult<WitnessVerdict>;
    fn submit_report(&self, report: WitnessReport) -> ChainResult<()>;
}

/// Lightweight client responsibilities for interacting with the chain.
pub trait ClientNode {
    fn submit_transaction(&self, tx: SignedTransaction) -> ChainResult<()>;
    fn submit_uptime_proof(&self, proof: UptimeProof) -> ChainResult<()>;
    fn status(&self) -> ChainResult<ClientStatus>;
}

/// Standard wallet balance response returned by RPC handlers.
#[cfg(feature = "wallet-integration")]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WalletBalanceResponse {
    pub address: Address,
    pub balance: u128,
    pub nonce: u64,
    #[cfg(all(feature = "wallet-integration", feature = "vendor_electrs"))]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mempool_delta: Option<i64>,
}

/// Script digest metadata captured by the Electrs tracker for tracked scripts.
#[cfg(all(feature = "wallet-integration", feature = "vendor_electrs"))]
#[derive(Clone, Debug, Serialize)]
pub struct WalletTrackedScript {
    pub script_hash: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status_digest: Option<String>,
}

/// Snapshot of tracker state accompanying wallet history responses.
#[cfg(all(feature = "wallet-integration", feature = "vendor_electrs"))]
#[derive(Clone, Debug, Serialize)]
pub struct WalletTrackerSnapshot {
    pub scripts: Vec<WalletTrackedScript>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mempool_fingerprint: Option<String>,
}

/// History payload returned by wallet RPC handlers including tracker metadata.
#[cfg(feature = "wallet-integration")]
#[derive(Clone, Debug, Serialize)]
pub struct WalletHistoryResponse {
    pub entries: Vec<HistoryEntry>,
    #[cfg(all(feature = "wallet-integration", feature = "vendor_electrs"))]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub script_metadata: Option<Vec<ScriptStatusMetadata>>,
    #[cfg(all(feature = "wallet-integration", feature = "vendor_electrs"))]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tracker: Option<WalletTrackerSnapshot>,
}

#[cfg(feature = "wallet-integration")]
pub const WALLET_UI_HISTORY_CONTRACT: &str = "wallet-ui.history.v1";
#[cfg(feature = "wallet-integration")]
pub const WALLET_UI_SEND_CONTRACT: &str = "wallet-ui.send.v1";
#[cfg(feature = "wallet-integration")]
pub const WALLET_UI_RECEIVE_CONTRACT: &str = "wallet-ui.receive.v1";
#[cfg(feature = "wallet-integration")]
pub const WALLET_UI_NODE_CONTRACT: &str = "wallet-ui.node.v1";

/// Versioned contract consumed by the wallet history tab.
#[cfg(feature = "wallet-integration")]
#[derive(Clone, Debug, Serialize)]
pub struct WalletUiHistoryContract {
    pub version: &'static str,
    pub entries: Vec<HistoryEntry>,
    #[cfg(all(feature = "wallet-integration", feature = "vendor_electrs"))]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub script_metadata: Option<Vec<ScriptStatusMetadata>>,
    #[cfg(all(feature = "wallet-integration", feature = "vendor_electrs"))]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tracker: Option<WalletTrackerSnapshot>,
}

/// Versioned contract consumed by the wallet send tab.
#[cfg(feature = "wallet-integration")]
#[derive(Clone, Debug, Serialize)]
pub struct WalletUiSendContract {
    pub version: &'static str,
    pub preview: SendPreview,
}

/// Versioned contract consumed by the wallet receive tab.
#[cfg(feature = "wallet-integration")]
#[derive(Clone, Debug, Serialize)]
pub struct WalletUiReceiveContract {
    pub version: &'static str,
    pub addresses: Vec<ReceiveTabAddress>,
}

/// Versioned contract consumed by the wallet node tab.
#[cfg(feature = "wallet-integration")]
#[derive(Clone, Debug, Serialize)]
pub struct WalletUiNodeContract {
    pub version: &'static str,
    pub metrics: NodeTabMetrics,
    pub consensus: Option<ConsensusReceipt>,
    pub pipeline: Option<PipelineDashboardSnapshot>,
}

#[cfg(all(feature = "wallet-integration", feature = "vendor_electrs"))]
impl From<TrackedScriptSnapshot> for WalletTrackedScript {
    fn from(snapshot: TrackedScriptSnapshot) -> Self {
        Self {
            script_hash: snapshot.script_hash,
            status_digest: snapshot.status_digest.map(|digest| digest.to_string()),
        }
    }
}

#[cfg(all(feature = "wallet-integration", feature = "vendor_electrs"))]
impl From<TrackerSnapshot> for WalletTrackerSnapshot {
    fn from(snapshot: TrackerSnapshot) -> Self {
        Self {
            scripts: snapshot
                .scripts
                .into_iter()
                .map(WalletTrackedScript::from)
                .collect(),
            mempool_fingerprint: snapshot
                .mempool_fingerprint
                .map(|fingerprint| hex::encode(fingerprint)),
        }
    }
}
