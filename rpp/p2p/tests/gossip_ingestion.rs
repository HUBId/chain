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
