//! Malachite-specific consensus orchestration primitives.
//!
//! The module currently exposes the distributed stream orchestrator that fanouts
//! proposals, votes, and commits between multiple validator nodes.

pub mod distributed;

pub use distributed::{
    CommitSubscription, DistributedOrchestrator, NodeStreams, ProposalSubscription, VoteMessage,
    VoteSubscription,
};
