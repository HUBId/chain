use std::time::Instant;

use tokio::runtime::Builder;
use tokio::sync::mpsc::UnboundedSender;
use tokio::time::sleep;

use crate::evidence::{slash, EvidenceRecord, EvidenceType};
use crate::messages::{Commit, PreCommit, PreVote, Proposal, Signature};
use crate::state::{register_message_sender, ConsensusState};
use crate::{ConsensusError, ConsensusResult};

#[derive(Clone, Debug)]
pub(crate) enum ConsensusMessage {
    Proposal(Proposal),
    PreVote(PreVote),
    PreCommit(PreCommit),
    Commit(Commit),
    Evidence(EvidenceRecord),
    Shutdown,
}

fn global_sender() -> ConsensusResult<UnboundedSender<ConsensusMessage>> {
    register_message_sender(None).ok_or(ConsensusError::ChannelNotInitialized)
}

pub fn submit_proposal(proposal: Proposal) -> ConsensusResult<()> {
    global_sender()?
        .send(ConsensusMessage::Proposal(proposal))
        .map_err(|_| ConsensusError::ChannelClosed)
}

pub fn submit_prevote(vote: PreVote) -> ConsensusResult<()> {
    global_sender()?
        .send(ConsensusMessage::PreVote(vote))
        .map_err(|_| ConsensusError::ChannelClosed)
}

pub fn submit_precommit(vote: PreCommit) -> ConsensusResult<()> {
    global_sender()?
        .send(ConsensusMessage::PreCommit(vote))
        .map_err(|_| ConsensusError::ChannelClosed)
}

pub fn finalize_block(commit: Commit) -> ConsensusResult<()> {
    global_sender()?
        .send(ConsensusMessage::Commit(commit))
        .map_err(|_| ConsensusError::ChannelClosed)
}

pub fn shutdown() -> ConsensusResult<()> {
    global_sender()?
        .send(ConsensusMessage::Shutdown)
        .map_err(|_| ConsensusError::ChannelClosed)
}

pub fn run_bft_loop(state: &mut ConsensusState) {
    let runtime = Builder::new_current_thread()
        .enable_time()
        .build()
        .expect("failed to build consensus runtime");
    runtime.block_on(async { run_loop(state).await });
}

async fn run_loop(state: &mut ConsensusState) {
    loop {
        tokio::select! {
            _ = sleep(state.config.view_timeout) => {
                handle_timeout(state).await;
            }
            message = state.message_receiver().recv() => {
                match message {
                    Some(message) => {
                        if handle_message(state, message).await {
                            break;
                        }
                    }
                    None => break,
                }
            }
        }
        if state.halted {
            break;
        }
    }
}

async fn handle_timeout(state: &mut ConsensusState) {
    if state.should_timeout(Instant::now()) {
        let _ = state.broadcast_pending_messages();
        state.next_round();
        if let Some(proposal) = state.build_current_leader_proposal() {
            let _ = state.broadcast_proposal(&proposal);
        }
    }
}

async fn handle_message(state: &mut ConsensusState, message: ConsensusMessage) -> bool {
    match message {
        ConsensusMessage::Proposal(proposal) => {
            handle_proposal(state, proposal);
        }
        ConsensusMessage::PreVote(vote) => {
            handle_prevote(state, vote);
        }
        ConsensusMessage::PreCommit(vote) => {
            handle_precommit(state, vote);
        }
        ConsensusMessage::Commit(commit) => {
            handle_commit(state, commit);
        }
        ConsensusMessage::Evidence(evidence) => {
            state.record_evidence(evidence);
        }
        ConsensusMessage::Shutdown => {
            state.halted = true;
            return true;
        }
    }
    false
}

fn handle_proposal(state: &mut ConsensusState, proposal: Proposal) {
    if !proposal.proof.verify() {
        let evidence = EvidenceRecord {
            reporter: proposal.leader_id.clone(),
            accused: proposal.leader_id.clone(),
            evidence: EvidenceType::FalseProof {
                block_hash: proposal.block_hash().0,
            },
        };
        state.record_evidence(evidence.clone());
        slash(&proposal.leader_id, 1, state);
        return;
    }

    if let Some(leader) = &state.current_leader {
        if leader.id != proposal.leader_id {
            // Leader mismatch triggers a view change
            state.next_round();
            return;
        }
    }

    state.push_proposal(proposal);
}

fn handle_prevote(state: &mut ConsensusState, vote: PreVote) {
    let valid_proof = state
        .find_proposal(&vote.block_hash.0)
        .map(|proposal| proposal.proof.verify())
        .unwrap_or(false);

    if vote.proof_valid != valid_proof {
        let evidence = EvidenceRecord {
            reporter: vote.validator_id.clone(),
            accused: vote.validator_id.clone(),
            evidence: EvidenceType::FalseProof {
                block_hash: vote.block_hash.0.clone(),
            },
        };
        state.record_evidence(evidence.clone());
        slash(&vote.validator_id, 1, state);
        return;
    }

    if state.record_prevote(vote.clone()) {
        // Once quorum of prevotes reached, validators are expected to precommit.
        if let Some(proposal) = state.find_proposal(&vote.block_hash.0).cloned() {
            for validator in &state.validator_set.validators {
                let precommit = PreCommit {
                    block_hash: proposal.block_hash(),
                    validator_id: validator.id.clone(),
                    round: state.round,
                };
                let _ = submit_precommit(precommit);
            }
        }
    }
}

fn handle_precommit(state: &mut ConsensusState, vote: PreCommit) {
    if !state.validator_set.contains(&vote.validator_id) {
        return;
    }

    if state.record_precommit(vote.clone()) {
        if let Some(proposal) = state.find_proposal(&vote.block_hash.0).cloned() {
            let signatures = state
                .precommit_voters(&vote.block_hash.0)
                .into_iter()
                .map(|validator_id| Signature {
                    validator_id: validator_id.clone(),
                    signature: format!("sig-{}", validator_id),
                })
                .collect();
            let commit = Commit {
                block: proposal.block,
                proof: proposal.proof,
                signatures,
            };
            let _ = finalize_block(commit);
        }
    }
}

fn handle_commit(state: &mut ConsensusState, commit: Commit) {
    state.apply_commit(commit);
}
