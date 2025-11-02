use libp2p::PeerId;
use rpp_consensus::malachite::distributed::{DistributedOrchestrator, NodeStreams, VoteMessage};
use rpp_consensus::messages::{
    compute_consensus_bindings, Block, BlockId, Commit, ConsensusCertificate, ConsensusProof,
    ConsensusProofMetadata, PreCommit, PreVote, Proposal, Signature,
};
use rpp_consensus::network::topics::{ConsensusStream, TopicRouter};
use rpp_consensus::proof_backend::{
    ConsensusCircuitDef, ConsensusPublicInputs, ProofBytes, VerifyingKey,
};
use rpp_crypto_vrf::VRF_PROOF_LENGTH;
use rpp_p2p::GossipTopic;
use serde_json::json;
use tokio::runtime::Builder;

fn sample_metadata(round: u64) -> ConsensusProofMetadata {
    let digest = |seed: u8| hex::encode([seed; 32]);
    let seed = seed_from_round(round);
    let proof = hex::encode(vec![seed; VRF_PROOF_LENGTH]);
    ConsensusProofMetadata {
        vrf_outputs: vec![digest(seed)],
        vrf_proofs: vec![proof],
        witness_commitments: vec![digest(seed.wrapping_add(1))],
        reputation_roots: vec![digest(seed.wrapping_add(2))],
        epoch: round,
        slot: round,
        quorum_bitmap_root: digest(seed.wrapping_add(3)),
        quorum_signature_root: digest(seed.wrapping_add(4)),
    }
}

fn seed_from_round(round: u64) -> u8 {
    (round as u8).wrapping_add(1)
}

fn decode_digest(hex_value: &str) -> [u8; 32] {
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&hex::decode(hex_value).expect("decode digest"));
    bytes
}

fn sample_public_inputs(
    block_hash: &BlockId,
    round: u64,
    metadata: &ConsensusProofMetadata,
) -> ConsensusPublicInputs {
    let block_hash_bytes = decode_digest(&block_hash.0);
    let quorum_bitmap_root = decode_digest(&metadata.quorum_bitmap_root);
    let quorum_signature_root = decode_digest(&metadata.quorum_signature_root);
    let vrf_outputs: Vec<[u8; 32]> = metadata
        .vrf_outputs
        .iter()
        .map(|value| decode_digest(value))
        .collect();
    let vrf_proofs: Vec<Vec<u8>> = metadata
        .vrf_proofs
        .iter()
        .map(|value| hex::decode(value).expect("decode vrf proof"))
        .collect();
    let witness_commitments: Vec<[u8; 32]> = metadata
        .witness_commitments
        .iter()
        .map(|value| decode_digest(value))
        .collect();
    let reputation_roots: Vec<[u8; 32]> = metadata
        .reputation_roots
        .iter()
        .map(|value| decode_digest(value))
        .collect();

    let bindings = compute_consensus_bindings(
        &block_hash_bytes,
        &vrf_outputs,
        &vrf_proofs,
        &witness_commitments,
        &reputation_roots,
        &quorum_bitmap_root,
        &quorum_signature_root,
    );

    ConsensusPublicInputs {
        block_hash: block_hash_bytes,
        round,
        leader_proposal: block_hash_bytes,
        epoch: metadata.epoch,
        slot: metadata.slot,
        quorum_threshold: 67,
        quorum_bitmap_root,
        quorum_signature_root,
        vrf_outputs,
        vrf_proofs,
        witness_commitments,
        reputation_roots,
        vrf_output_binding: bindings.vrf_output,
        vrf_proof_binding: bindings.vrf_proof,
        witness_commitment_binding: bindings.witness_commitment,
        reputation_root_binding: bindings.reputation_root,
        quorum_bitmap_binding: bindings.quorum_bitmap,
        quorum_signature_binding: bindings.quorum_signature,
    }
}

fn sample_block(height: u64, round: u64) -> Block {
    Block {
        height,
        epoch: round,
        payload: json!({ "height": height, "round": round }),
        timestamp: 1_700_000_000 + height,
    }
}

fn sample_proof(
    block_hash: &BlockId,
    round: u64,
    metadata: &ConsensusProofMetadata,
) -> ConsensusProof {
    ConsensusProof::new(
        ProofBytes(vec![0xAA, round as u8]),
        VerifyingKey(vec![0xBB, round as u8]),
        ConsensusCircuitDef::new(format!("consensus-stream-{round}")),
        sample_public_inputs(block_hash, round, metadata),
    )
}

fn sample_certificate(
    block_hash: BlockId,
    height: u64,
    round: u64,
    metadata: ConsensusProofMetadata,
) -> ConsensusCertificate {
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
        metadata,
    }
}

fn sample_proposal(height: u64, round: u64, leader: &str) -> Proposal {
    let block = sample_block(height, round);
    let block_hash = block.hash();
    let metadata = sample_metadata(round);
    Proposal {
        block,
        proof: sample_proof(&block_hash, round, &metadata),
        certificate: sample_certificate(block_hash, height, round, metadata),
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
    let runtime = Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime");
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
        match mut_b_votes.recv().await.expect("node B receives precommit") {
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
        let received_commit = mut_b_commits.recv().await.expect("node B receives commit");
        assert_eq!(received_commit.block.height, commit.block.height);
        assert!(mut_b_commits.try_recv().expect("commit drained").is_none());

        // Node A should still be able to drain the remaining vote and commit traffic.
        mut_a_votes.recv().await.expect("node A backfills prevote");
        mut_a_votes
            .recv()
            .await
            .expect("node A backfills precommit");
        mut_a_commits.recv().await.expect("node A backfills commit");
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
