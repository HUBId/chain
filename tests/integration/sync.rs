#![cfg(feature = "prover-stwo")]

use rpp_chain::errors::ChainResult;
use rpp_chain::runtime::sync::ReconstructionEngine;
use rpp_chain::storage::Storage;

use super::support::{
    collect_state_sync_artifacts, install_pruned_chain, make_dummy_block, InMemoryPayloadProvider,
};

#[test]
fn state_sync_plan_exports_consistent_artifacts() -> ChainResult<()> {
    let dir = tempfile::tempdir().expect("temporary directory");
    let storage = Storage::open(dir.path())?;

    let mut blocks = Vec::new();
    let mut previous = None;
    for height in 1..=3u64 {
        let block = make_dummy_block(height, previous.as_ref());
        previous = Some(block.clone());
        blocks.push(block);
    }

    let payloads = install_pruned_chain(&storage, &blocks)?;
    let engine = ReconstructionEngine::new(storage.clone());
    let artifacts = collect_state_sync_artifacts(&engine, 2)?;

    assert_eq!(
        artifacts.plan.chunks.len(),
        artifacts.chunk_messages.len(),
        "each chunk should map to an exported message",
    );
    assert!(
        !artifacts.plan.light_client_updates.is_empty(),
        "state sync should emit light client updates",
    );

    let provider = InMemoryPayloadProvider::new(payloads);
    for request in artifacts.requests() {
        provider
            .fetch_payload(request)
            .expect("payload provider should serve requested heights");
    }

    Ok(())
}
