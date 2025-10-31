use rpp_consensus::{
    TimetokeRecord, TimetokeReplayError, TimetokeReplayValidator, TimetokeSnapshotConsumer,
    TimetokeSnapshotError, TimetokeSnapshotProducer,
};
use rpp_p2p::{
    NetworkPruningCommitment, NetworkPruningEnvelope, NetworkPruningSegment,
    NetworkPruningSnapshot, NetworkTaggedDigestHex,
};
use rpp_pruning::{
    DomainTag, COMMITMENT_TAG, DIGEST_LENGTH, DOMAIN_TAG_LENGTH, ENVELOPE_TAG, PROOF_SEGMENT_TAG,
    SNAPSHOT_STATE_TAG,
};

fn encode_tagged_hex(tag: DomainTag, digest: [u8; DIGEST_LENGTH]) -> NetworkTaggedDigestHex {
    let mut bytes = [0u8; DOMAIN_TAG_LENGTH + DIGEST_LENGTH];
    bytes[..DOMAIN_TAG_LENGTH].copy_from_slice(&tag.as_bytes());
    bytes[DOMAIN_TAG_LENGTH..].copy_from_slice(&digest);
    NetworkTaggedDigestHex(hex::encode(bytes))
}

fn sample_pruning_envelope(global_root: [u8; DIGEST_LENGTH]) -> NetworkPruningEnvelope {
    NetworkPruningEnvelope {
        schema_version: 1,
        parameter_version: 0,
        snapshot: NetworkPruningSnapshot {
            schema_version: 1,
            parameter_version: 0,
            block_height: 42,
            state_commitment: encode_tagged_hex(SNAPSHOT_STATE_TAG, global_root),
        },
        segments: vec![NetworkPruningSegment {
            schema_version: 1,
            parameter_version: 0,
            segment_index: 0,
            start_height: 0,
            end_height: 42,
            segment_commitment: encode_tagged_hex(PROOF_SEGMENT_TAG, [0x11; DIGEST_LENGTH]),
        }],
        commitment: NetworkPruningCommitment {
            schema_version: 1,
            parameter_version: 0,
            aggregate_commitment: encode_tagged_hex(COMMITMENT_TAG, [0x22; DIGEST_LENGTH]),
        },
        binding_digest: encode_tagged_hex(ENVELOPE_TAG, [0x33; DIGEST_LENGTH]),
    }
}

#[test]
fn timetoke_snapshot_roundtrip() {
    let records = vec![
        TimetokeRecord {
            identity: "validator-1".into(),
            balance: 32,
            epoch_accrual: 0,
            decay_rate: 1.0,
            last_update: 1,
            last_sync: 1,
            last_decay: 1,
        },
        TimetokeRecord {
            identity: "validator-2".into(),
            balance: 64,
            epoch_accrual: 0,
            decay_rate: 1.0,
            last_update: 2,
            last_sync: 2,
            last_decay: 2,
        },
    ];
    let timetoke_root = [0xAB; 32];
    let mut producer = TimetokeSnapshotProducer::new(16);
    let handle = producer
        .publish(records.clone(), timetoke_root)
        .expect("publish");

    assert_eq!(handle.record_count, records.len());
    assert!(producer.has_snapshot(&handle.root));

    let mut consumer = TimetokeSnapshotConsumer::new(handle.root);
    let mut snapshot = None;
    let mut last_chunk = None;
    for index in 0..handle.total_chunks {
        let chunk = producer.chunk(&handle.root, index).expect("chunk");
        last_chunk = Some(chunk.clone());
        snapshot = consumer.ingest_chunk(chunk).expect("ingest");
        if index + 1 < handle.total_chunks {
            assert!(snapshot.is_none());
        }
    }
    let snapshot = snapshot.expect("snapshot complete");
    assert_eq!(snapshot.records, records);
    assert_eq!(snapshot.timetoke_root, hex::encode(timetoke_root));
    assert!(consumer.is_finished());

    let err = consumer
        .ingest_chunk(last_chunk.expect("have last chunk"))
        .expect_err("reject duplicate chunk");
    assert!(matches!(err, TimetokeSnapshotError::UnexpectedChunk(_)));
}

#[test]
fn timetoke_replay_validation_guards_roots_and_tags() {
    let ledger_timetoke_root = [0x44; 32];
    let ledger_global_root = [0x55; 32];

    let mut producer = TimetokeSnapshotProducer::new(8);
    let handle = producer
        .publish(Vec::new(), ledger_timetoke_root)
        .expect("publish snapshot");
    let mut consumer = TimetokeSnapshotConsumer::new(handle.root);
    let mut snapshot = None;
    for index in 0..handle.total_chunks {
        let chunk = producer.chunk(&handle.root, index).expect("chunk");
        snapshot = consumer.ingest_chunk(chunk).expect("ingest");
    }
    let snapshot = snapshot.expect("snapshot available");

    let pruning = sample_pruning_envelope(ledger_global_root);
    TimetokeReplayValidator::validate(
        &snapshot,
        &pruning,
        ledger_timetoke_root,
        ledger_global_root,
    )
    .expect("valid pruning envelope");

    let mut stale_snapshot = snapshot.clone();
    stale_snapshot.timetoke_root = hex::encode([0x99; 32]);
    let err = TimetokeReplayValidator::validate(
        &stale_snapshot,
        &pruning,
        ledger_timetoke_root,
        ledger_global_root,
    )
    .expect_err("detect stale timetoke root");
    assert!(matches!(
        err,
        TimetokeReplayError::SnapshotRootMismatch { .. }
    ));

    let mut mismatched_pruning = pruning.clone();
    mismatched_pruning.snapshot.state_commitment =
        encode_tagged_hex(SNAPSHOT_STATE_TAG, [0xAA; DIGEST_LENGTH]);
    let err = TimetokeReplayValidator::validate(
        &snapshot,
        &mismatched_pruning,
        ledger_timetoke_root,
        ledger_global_root,
    )
    .expect_err("detect mismatched pruning digest");
    assert!(matches!(
        err,
        TimetokeReplayError::PruningDigestMismatch {
            field: "pruning.snapshot.state_commitment",
            ..
        }
    ));

    let mut invalid_binding = pruning.clone();
    invalid_binding.binding_digest = encode_tagged_hex(PROOF_SEGMENT_TAG, [0x33; DIGEST_LENGTH]);
    let err = TimetokeReplayValidator::validate(
        &snapshot,
        &invalid_binding,
        ledger_timetoke_root,
        ledger_global_root,
    )
    .expect_err("detect invalid binding tag");
    assert!(matches!(err, TimetokeReplayError::DomainTagMismatch { .. }));
}
