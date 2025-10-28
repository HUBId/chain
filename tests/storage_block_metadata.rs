mod support;

use rpp_chain::errors::ChainError;
use rpp_chain::storage::Storage;
use rpp_chain::types::{Block, BlockMetadata};
use storage_firewood::kv::FirewoodKv;
use tempfile::tempdir;

use support::make_dummy_block;

#[test]
fn storage_persists_extended_block_metadata() {
    let temp_dir = tempdir().expect("tempdir");
    let storage = Storage::open(temp_dir.path()).expect("open storage");
    let genesis = make_dummy_block(0, None);
    let metadata = BlockMetadata::from(&genesis);
    storage
        .store_block(&genesis, &metadata)
        .expect("store genesis");
    drop(storage);

    let reopened = Storage::open(temp_dir.path()).expect("reopen storage");
    let persisted = reopened
        .read_block_metadata(genesis.header.height)
        .expect("read metadata")
        .expect("metadata present");
    assert_eq!(persisted.proof_hash, genesis.header.proof_root);
    assert_eq!(
        persisted.pruning_binding_digest,
        genesis
            .pruning_proof
            .binding_digest()
            .prefixed_bytes()
    );
    let expected_segments: Vec<_> = genesis
        .pruning_proof
        .segments()
        .iter()
        .map(|segment| segment.segment_commitment().prefixed_bytes())
        .collect();
    assert_eq!(persisted.pruning_segment_commitments, expected_segments);
    assert_eq!(
        persisted.pruning_binding_digest,
        metadata.pruning_binding_digest
    );
    assert_eq!(
        persisted.pruning_segment_commitments,
        metadata.pruning_segment_commitments
    );
    assert_eq!(persisted.previous_state_root, metadata.previous_state_root);
    assert_eq!(persisted.new_state_root, metadata.new_state_root);
    let persisted_pruning = persisted
        .pruning_metadata()
        .expect("persisted pruning metadata");
    let expected_pruning = metadata
        .pruning_metadata()
        .expect("expected pruning metadata");
    assert_eq!(
        persisted_pruning
            .snapshot
            .state_commitment
            .as_str(),
        expected_pruning
            .snapshot
            .state_commitment
            .as_str()
    );
    assert_eq!(
        persisted_pruning
            .segments
            .get(0)
            .map(|segment| segment.segment_commitment.as_str()),
        expected_pruning
            .segments
            .get(0)
            .map(|segment| segment.segment_commitment.as_str()),
    );
    let expected_segment_hex: Vec<_> = genesis
        .pruning_proof
        .segments()
        .iter()
        .map(|segment| hex::encode(segment.segment_commitment().prefixed_bytes()))
        .collect();
    assert_eq!(persisted_pruning.segments.len(), expected_segment_hex.len());
    for (segment, expected_hex) in persisted_pruning
        .segments
        .iter()
        .zip(expected_segment_hex.iter())
    {
        assert_eq!(segment.segment_commitment.as_str(), expected_hex);
    }
    assert_eq!(
        persisted_pruning.schema_digest,
        expected_pruning.schema_digest
    );
    assert_eq!(
        persisted_pruning.parameter_digest,
        expected_pruning.parameter_digest
    );
    assert_eq!(
        persisted_pruning.binding_digest.as_str(),
        expected_pruning.binding_digest.as_str()
    );
    assert_eq!(
        persisted_pruning
            .commitment
            .aggregate_commitment
            .as_str(),
        expected_pruning
            .commitment
            .aggregate_commitment
            .as_str()
    );
    let expected_binding =
        hex::encode(genesis.pruning_proof.binding_digest().prefixed_bytes());
    assert_eq!(persisted_pruning.binding_digest.as_str(), expected_binding);
    let expected_commitment = hex::encode(
        genesis
            .pruning_proof
            .aggregate_commitment()
            .prefixed_bytes()
    );
    assert_eq!(
        persisted_pruning
            .commitment
            .aggregate_commitment
            .as_str(),
        expected_commitment
    );
}

#[test]
fn storage_rejects_corrupted_block_metadata() {
    let temp_dir = tempdir().expect("tempdir");
    let storage = Storage::open(temp_dir.path()).expect("open storage");
    let genesis = make_dummy_block(0, None);
    let metadata = BlockMetadata::from(&genesis);
    storage
        .store_block(&genesis, &metadata)
        .expect("store genesis");
    drop(storage);

    let mut kv = FirewoodKv::open(temp_dir.path()).expect("open kv");
    let mut suffix = Vec::from(b"block_metadata/".as_slice());
    suffix.extend_from_slice(&genesis.header.height.to_be_bytes());
    let mut key = Vec::with_capacity(1 + suffix.len());
    key.push(b'm');
    key.extend_from_slice(&suffix);
    kv.put(key, vec![0xFF]);
    kv.commit().expect("commit corruption");
    drop(kv);

    let reopened = Storage::open(temp_dir.path()).expect("reopen storage");
    let err = reopened
        .read_block_metadata(genesis.header.height)
        .expect_err("corrupted metadata should fail");
    assert!(matches!(err, ChainError::Serialization(_)));
}
