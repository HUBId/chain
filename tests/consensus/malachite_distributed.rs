use libp2p::PeerId;
use rpp_consensus::malachite::distributed::{DistributedOrchestrator, NodeStreams, VoteMessage};
use rpp_consensus::messages::{
    Block, BlockId, Commit, ConsensusCertificate, ConsensusProof, PreCommit, PreVote, Proposal,
    Signature,
};
use rpp_consensus::network::topics::{ConsensusStream, TopicRouter};
use rpp_consensus::proof_backend::{
    ConsensusCircuitDef, ConsensusPublicInputs, ProofBytes, VerifyingKey,
};
use rpp_p2p::GossipTopic;
use serde_json::json;
use tokio::runtime::Builder;

fn sample_block(height: u64, round: u64) -> Block {
    Block {
        height,
        epoch: round,
        payload: json!({ "height": height, "round": round }),
        timestamp: 1_700_000_000 + height,
    }
}

fn sample_proof(round: u64) -> ConsensusProof {
    let mut block_hash = [0u8; 32];
    block_hash[0] = (round % 255) as u8;
    let mut leader_proposal = [1u8; 32];
    leader_proposal[0] = (round % 255) as u8;
    ConsensusProof::new(
        ProofBytes(vec![0xAA, round as u8]),
        VerifyingKey(vec![0xBB, round as u8]),
        ConsensusCircuitDef::new(format!("consensus-stream-{round}")),
        ConsensusPublicInputs {
            block_hash,
            round,
            leader_proposal,
            quorum_threshold: 67,
        },
    )
}

fn sample_certificate(block_hash: BlockId, height: u64, round: u64) -> ConsensusCertificate {
    ConsensusCertificate {
        block_hash,
        height,
        round,
        total_power: 100,
        quorum_threshold: 67,
        prevote_power: 67,
        precommit_power: 67,
        commit_power: 100,
        prevotes: Vec::new(),
        precommits: Vec::new(),
    }
}

fn sample_proposal(height: u64, round: u64, leader: &str) -> Proposal {
    let block = sample_block(height, round);
    let block_hash = block.hash();
    Proposal {
        block,
        proof: sample_proof(round),
        certificate: sample_certificate(block_hash, height, round),
        leader_id: leader.to_string(),
    }
}

fn sample_prevote(proposal: &Proposal, validator: &str, round: u64) -> PreVote {
    PreVote {
        block_hash: proposal.block_hash(),
        proof_valid: true,
        validator_id: validator.to_string(),
        peer_id: PeerId::random(),
        signature: vec![validator.len() as u8, round as u8],
        height: proposal.block.height,
        round,
    }
}

fn sample_precommit(proposal: &Proposal, validator: &str, round: u64) -> PreCommit {
    PreCommit {
        block_hash: proposal.block_hash(),
        validator_id: validator.to_string(),
        peer_id: PeerId::random(),
        signature: vec![0xCC, round as u8],
        height: proposal.block.height,
        round,
    }
}

fn sample_commit(proposal: &Proposal, round: u64) -> Commit {
    Commit {
        block: proposal.block.clone(),
        proof: proposal.proof.clone(),
        certificate: sample_certificate(proposal.block_hash(), proposal.block.height, round),
        signatures: vec![Signature {
            validator_id: proposal.leader_id.clone(),
            peer_id: PeerId::random(),
            signature: vec![0xDD, round as u8],
        }],
    }
}

#[test]
fn distributed_streams_propagate_across_nodes() {
    let runtime = Builder::new_current_thread().enable_all().build().expect("runtime");
    runtime.block_on(async {
        let orchestrator = DistributedOrchestrator::default();
        let NodeStreams {
            proposals: mut mut_a_proposals,
            votes: mut mut_a_votes,
            commits: mut mut_a_commits,
        } = orchestrator.register_node();
        let NodeStreams {
            proposals: mut mut_b_proposals,
            votes: mut mut_b_votes,
            commits: mut mut_b_commits,
        } = orchestrator.register_node();

        let proposal = sample_proposal(42, 3, "validator-a");
        orchestrator
            .publish_proposal(proposal.clone())
            .expect("proposal propagated");

        let (recv_a, recv_b) = tokio::join!(mut_a_proposals.recv(), mut_b_proposals.recv());
        let received_a = recv_a.expect("node A receives proposal");
        let received_b = recv_b.expect("node B receives proposal");
        assert_eq!(received_a.block.height, proposal.block.height);
        assert_eq!(received_b.leader_id, proposal.leader_id);
        assert!(mut_a_proposals.is_empty());
        assert!(mut_b_proposals.is_empty());

        let prevote = sample_prevote(&proposal, "validator-a", 3);
        orchestrator
            .publish_vote(prevote.clone().into())
            .expect("prevote propagated");
        match mut_b_votes.recv().await.expect("node B receives prevote") {
            VoteMessage::PreVote(vote) => {
                assert_eq!(vote.block_hash, prevote.block_hash);
                assert_eq!(vote.round, prevote.round);
            }
            other => panic!("unexpected vote: {other:?}"),
        }
        assert!(mut_b_votes.try_recv().expect("try_recv works").is_none());

        let precommit = sample_precommit(&proposal, "validator-a", 3);
        orchestrator
            .publish_vote(precommit.clone().into())
            .expect("precommit propagated");
        match mut_b_votes
            .recv()
            .await
            .expect("node B receives precommit")
        {
            VoteMessage::PreCommit(vote) => {
                assert_eq!(vote.validator_id, precommit.validator_id);
                assert_eq!(vote.round, precommit.round);
            }
            other => panic!("unexpected vote: {other:?}"),
        }

        let commit = sample_commit(&proposal, 3);
        orchestrator
            .publish_commit(commit.clone())
            .expect("commit propagated");
        let received_commit = mut_b_commits
            .recv()
            .await
            .expect("node B receives commit");
        assert_eq!(received_commit.block.height, commit.block.height);
        assert!(mut_b_commits.try_recv().expect("commit drained").is_none());

        // Node A should still be able to drain the remaining vote and commit traffic.
        mut_a_votes
            .recv()
            .await
            .expect("node A backfills prevote");
        mut_a_votes
            .recv()
            .await
            .expect("node A backfills precommit");
        mut_a_commits
            .recv()
            .await
            .expect("node A backfills commit");
    });
}

#[test]
fn topic_router_fans_out_commits_to_witnesses() {
    let router = TopicRouter::default();
    let commit_route = router.route(ConsensusStream::Commits);
    assert_eq!(commit_route.primary(), GossipTopic::Proofs);
    assert!(commit_route.contains(GossipTopic::WitnessProofs));
    assert!(commit_route.contains(GossipTopic::WitnessMeta));

    let witness_disabled = TopicRouter::new().with_witness_enabled(false);
    let disabled_route = witness_disabled.route(ConsensusStream::Commits);
    assert!(!disabled_route.contains(GossipTopic::WitnessProofs));
    assert!(!disabled_route.contains(GossipTopic::WitnessMeta));
    assert!(disabled_route.contains(GossipTopic::Meta));
}

