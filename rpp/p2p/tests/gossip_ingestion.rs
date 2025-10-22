use std::sync::Arc;

// NOTE: Vendored libp2p types must be used to avoid pulling upstream crates
// directly into the test harness.
use rpp_p2p::vendor::PeerId;
use rpp_p2p::{
    ConsensusPipeline, GossipTopic, JsonProofValidator, PipelineError, ProofMempool, ProofRecord,
    ProofStorage, VoteOutcome,
};

#[derive(Debug, Default)]
struct EphemeralProofStorage;

impl ProofStorage for EphemeralProofStorage {
    fn persist(&self, _record: &ProofRecord) -> Result<(), PipelineError> {
        Ok(())
    }
}

#[test]
fn proof_ingestion_deduplicates_across_peers() {
    let validator = Arc::new(JsonProofValidator::default());
    let storage = Arc::new(EphemeralProofStorage::default());
    let mut mempool = ProofMempool::new(validator, storage).expect("proof mempool");

    let payload = serde_json::json!({
        "transaction": "tx-hash",
        "proof": {
            "stwo": {
                "commitment": "aa".repeat(32)
            }
        }
    });
    let bytes = serde_json::to_vec(&payload).expect("encode proof payload");

    let peer_one = PeerId::random();
    let peer_two = PeerId::random();

    assert!(mempool
        .ingest(peer_one, GossipTopic::Proofs, bytes.clone())
        .expect("first ingest"));
    let err = mempool
        .ingest(peer_two, GossipTopic::Proofs, bytes)
        .expect_err("duplicate proof should be rejected");
    assert!(matches!(err, PipelineError::Duplicate));
}

#[test]
fn votes_from_multiple_peers_reach_quorum() {
    let mut pipeline = ConsensusPipeline::new();
    let peers: Vec<_> = (0..3).map(|_| PeerId::random()).collect();
    for peer in &peers {
        pipeline.register_voter(*peer, 1.0);
    }

    let block_id = b"proposal".to_vec();
    pipeline
        .ingest_proposal(block_id.clone(), peers[0], b"block".to_vec())
        .expect("proposal accepted");

    let outcome = pipeline
        .ingest_vote(&block_id, peers[0], 0, b"vote-one".to_vec())
        .expect("first vote accepted");
    assert!(matches!(
        outcome,
        VoteOutcome::Recorded {
            reached_quorum: false,
            ..
        }
    ));

    let outcome = pipeline
        .ingest_vote(&block_id, peers[1], 0, b"vote-two".to_vec())
        .expect("second vote accepted");
    match outcome {
        VoteOutcome::Recorded {
            reached_quorum,
            power,
        } => {
            assert!(reached_quorum, "second vote should cross quorum");
            assert!(power >= (2.0 / 3.0) * 3.0);
        }
        other => panic!("unexpected outcome: {other:?}"),
    }

    let duplicate = pipeline
        .ingest_vote(&block_id, peers[1], 0, b"vote-two".to_vec())
        .expect("duplicate vote handled");
    assert!(matches!(duplicate, VoteOutcome::Duplicate));
}

#[test]
fn quorum_requires_majority_of_weighted_voters() {
    let mut pipeline = ConsensusPipeline::new();
    pipeline.set_threshold_factor(0.75);
    let peers: Vec<_> = (0..4).map(|_| PeerId::random()).collect();
    for peer in &peers {
        pipeline.register_voter(*peer, 1.0);
    }

    let block_id = b"proposal-weighted".to_vec();
    pipeline
        .ingest_proposal(block_id.clone(), peers[0], b"block".to_vec())
        .expect("proposal accepted");

    let first = pipeline
        .ingest_vote(&block_id, peers[0], 0, b"vote-0".to_vec())
        .expect("first vote accepted");
    assert!(matches!(
        first,
        VoteOutcome::Recorded {
            reached_quorum: false,
            ..
        }
    ));

    let second = pipeline
        .ingest_vote(&block_id, peers[1], 0, b"vote-1".to_vec())
        .expect("second vote accepted");
    assert!(matches!(
        second,
        VoteOutcome::Recorded {
            reached_quorum: false,
            ..
        }
    ));

    let third = pipeline
        .ingest_vote(&block_id, peers[2], 0, b"vote-2".to_vec())
        .expect("third vote accepted");
    match third {
        VoteOutcome::Recorded {
            reached_quorum,
            power,
        } => {
            assert!(reached_quorum, "expected quorum after three voters");
            assert!(power >= 3.0);
        }
        other => panic!("unexpected outcome: {other:?}"),
    }
}

#[test]
fn tier_weighted_votes_cross_quorum_and_deduplicate() {
    let mut pipeline = ConsensusPipeline::new();
    let high = PeerId::random();
    let mid = PeerId::random();
    let low = PeerId::random();

    pipeline.register_voter(high, 3.0);
    pipeline.register_voter(mid, 2.0);
    pipeline.register_voter(low, 1.0);

    let block_id = b"tier-weighted".to_vec();
    pipeline
        .ingest_proposal(block_id.clone(), high, b"block".to_vec())
        .expect("proposal accepted");

    let first = pipeline
        .ingest_vote(&block_id, high, 0, b"vote-high".to_vec())
        .expect("high tier vote accepted");
    assert!(matches!(
        first,
        VoteOutcome::Recorded {
            reached_quorum: false,
            ..
        }
    ));

    let second = pipeline
        .ingest_vote(&block_id, mid, 0, b"vote-mid".to_vec())
        .expect("mid tier vote accepted");
    match second {
        VoteOutcome::Recorded {
            reached_quorum,
            power,
        } => {
            assert!(reached_quorum, "expected quorum after high + mid tiers");
            assert!(power >= (2.0 / 3.0) * 6.0);
        }
        other => panic!("unexpected outcome: {other:?}"),
    }

    let duplicate = pipeline
        .ingest_vote(&block_id, mid, 0, b"vote-mid-dup".to_vec())
        .expect("duplicate mid tier vote handled");
    assert!(matches!(duplicate, VoteOutcome::Duplicate));

    let third = pipeline
        .ingest_vote(&block_id, low, 0, b"vote-low".to_vec())
        .expect("low tier vote accepted");
    match third {
        VoteOutcome::Recorded {
            reached_quorum,
            power,
        } => {
            assert!(
                reached_quorum,
                "quorum remains satisfied after low tier vote"
            );
            assert!(power >= 6.0);
        }
        other => panic!("unexpected outcome: {other:?}"),
    }
}
