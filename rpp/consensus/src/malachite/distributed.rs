use std::sync::Arc;

use tokio::sync::broadcast;

use crate::messages::{Commit, PreCommit, PreVote, Proposal};
use crate::{ConsensusError, ConsensusResult};

const DEFAULT_CHANNEL_DEPTH: usize = 64;

#[derive(Clone)]
pub struct DistributedOrchestrator {
    inner: Arc<Inner>,
}

struct Inner {
    proposals: broadcast::Sender<Proposal>,
    votes: broadcast::Sender<VoteMessage>,
    commits: broadcast::Sender<Commit>,
}

impl DistributedOrchestrator {
    pub fn new(channel_depth: usize) -> Self {
        let (proposals, _guard) = broadcast::channel(channel_depth);
        drop(_guard);
        let (votes, _guard) = broadcast::channel(channel_depth);
        drop(_guard);
        let (commits, _guard) = broadcast::channel(channel_depth);
        drop(_guard);
        Self {
            inner: Arc::new(Inner {
                proposals,
                votes,
                commits,
            }),
        }
    }

    pub fn register_node(&self) -> NodeStreams {
        NodeStreams {
            proposals: self.subscribe_proposals(),
            votes: self.subscribe_votes(),
            commits: self.subscribe_commits(),
        }
    }

    pub fn publish_proposal(&self, proposal: Proposal) -> ConsensusResult<()> {
        self.inner
            .proposals
            .send(proposal)
            .map(|_| ())
            .map_err(|err| {
                let broadcast::error::SendError(_msg) = err;
                ConsensusError::ChannelClosed
            })
    }

    pub fn publish_vote(&self, vote: VoteMessage) -> ConsensusResult<()> {
        self.inner.votes.send(vote).map(|_| ()).map_err(|err| {
            let broadcast::error::SendError(_msg) = err;
            ConsensusError::ChannelClosed
        })
    }

    pub fn publish_commit(&self, commit: Commit) -> ConsensusResult<()> {
        self.inner.commits.send(commit).map(|_| ()).map_err(|err| {
            let broadcast::error::SendError(_msg) = err;
            ConsensusError::ChannelClosed
        })
    }

    pub fn subscribe_proposals(&self) -> ProposalSubscription {
        ProposalSubscription {
            receiver: self.inner.proposals.subscribe(),
        }
    }

    pub fn subscribe_votes(&self) -> VoteSubscription {
        VoteSubscription {
            receiver: self.inner.votes.subscribe(),
        }
    }

    pub fn subscribe_commits(&self) -> CommitSubscription {
        CommitSubscription {
            receiver: self.inner.commits.subscribe(),
        }
    }
}

impl Default for DistributedOrchestrator {
    fn default() -> Self {
        Self::new(DEFAULT_CHANNEL_DEPTH)
    }
}

pub struct NodeStreams {
    pub proposals: ProposalSubscription,
    pub votes: VoteSubscription,
    pub commits: CommitSubscription,
}

pub struct ProposalSubscription {
    receiver: broadcast::Receiver<Proposal>,
}

impl ProposalSubscription {
    pub async fn recv(&mut self) -> ConsensusResult<Proposal> {
        self.receiver.recv().await.map_err(map_recv_error)
    }

    pub fn try_recv(&mut self) -> ConsensusResult<Option<Proposal>> {
        match self.receiver.try_recv() {
            Ok(value) => Ok(Some(value)),
            Err(broadcast::error::TryRecvError::Empty) => Ok(None),
            Err(err) => Err(map_try_error(err)),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.receiver.is_empty()
    }

    pub fn len(&self) -> usize {
        self.receiver.len()
    }
}

pub struct VoteSubscription {
    receiver: broadcast::Receiver<VoteMessage>,
}

impl VoteSubscription {
    pub async fn recv(&mut self) -> ConsensusResult<VoteMessage> {
        self.receiver.recv().await.map_err(map_recv_error)
    }

    pub fn try_recv(&mut self) -> ConsensusResult<Option<VoteMessage>> {
        match self.receiver.try_recv() {
            Ok(value) => Ok(Some(value)),
            Err(broadcast::error::TryRecvError::Empty) => Ok(None),
            Err(err) => Err(map_try_error(err)),
        }
    }
}

pub struct CommitSubscription {
    receiver: broadcast::Receiver<Commit>,
}

impl CommitSubscription {
    pub async fn recv(&mut self) -> ConsensusResult<Commit> {
        self.receiver.recv().await.map_err(map_recv_error)
    }

    pub fn try_recv(&mut self) -> ConsensusResult<Option<Commit>> {
        match self.receiver.try_recv() {
            Ok(value) => Ok(Some(value)),
            Err(broadcast::error::TryRecvError::Empty) => Ok(None),
            Err(err) => Err(map_try_error(err)),
        }
    }
}

#[derive(Clone, Debug)]
pub enum VoteMessage {
    PreVote(PreVote),
    PreCommit(PreCommit),
}

impl VoteMessage {
    pub fn height(&self) -> u64 {
        match self {
            VoteMessage::PreVote(v) => v.height,
            VoteMessage::PreCommit(v) => v.height,
        }
    }

    pub fn round(&self) -> u64 {
        match self {
            VoteMessage::PreVote(v) => v.round,
            VoteMessage::PreCommit(v) => v.round,
        }
    }

    pub fn block_hash(&self) -> &crate::messages::BlockId {
        match self {
            VoteMessage::PreVote(v) => &v.block_hash,
            VoteMessage::PreCommit(v) => &v.block_hash,
        }
    }

    pub fn validator_id(&self) -> &crate::validator::ValidatorId {
        match self {
            VoteMessage::PreVote(v) => &v.validator_id,
            VoteMessage::PreCommit(v) => &v.validator_id,
        }
    }

    pub fn is_prevote(&self) -> bool {
        matches!(self, VoteMessage::PreVote(_))
    }

    pub fn is_precommit(&self) -> bool {
        matches!(self, VoteMessage::PreCommit(_))
    }
}

impl From<PreVote> for VoteMessage {
    fn from(value: PreVote) -> Self {
        VoteMessage::PreVote(value)
    }
}

impl From<PreCommit> for VoteMessage {
    fn from(value: PreCommit) -> Self {
        VoteMessage::PreCommit(value)
    }
}

fn map_recv_error<T>(error: broadcast::error::RecvError) -> ConsensusError {
    match error {
        broadcast::error::RecvError::Closed => ConsensusError::ChannelClosed,
        broadcast::error::RecvError::Lagged(_) => ConsensusError::ChannelClosed,
    }
}

fn map_try_error(error: broadcast::error::TryRecvError) -> ConsensusError {
    match error {
        broadcast::error::TryRecvError::Closed => ConsensusError::ChannelClosed,
        broadcast::error::TryRecvError::Lagged(_) => ConsensusError::ChannelClosed,
        broadcast::error::TryRecvError::Empty => ConsensusError::ChannelNotInitialized,
    }
}
