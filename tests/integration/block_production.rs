use anyhow::Result;
use tempfile::tempdir;

use rpp_chain::runtime::sync::ReconstructionEngine;
use rpp_chain::storage::Storage;

#[path = "../support/mod.rs"]
mod support;

use support::sync::{
    collect_state_sync_artifacts, install_pruned_chain, make_dummy_block, InMemoryPayloadProvider,
};

#[test]
fn orchestrates_block_production_roundtrip() -> Result<()> {
    let dir = tempdir()?;
    let storage = Storage::open(dir.path())?;

    let mut blocks = Vec::new();
    let mut previous = None;
    for height in 1..=3 {
        let block = make_dummy_block(height, previous.as_ref());
        previous = Some(block.clone());
        blocks.push(block);
    }

    let payloads = install_pruned_chain(&storage, &blocks)?;
    let engine = ReconstructionEngine::new(storage.clone());
    let artifacts = collect_state_sync_artifacts(&engine, 2)?;

    assert_eq!(artifacts.plan.chunks.len(), 2);
    assert_eq!(artifacts.network_plan.chunks.len(), 2);

    let provider = InMemoryPayloadProvider::from_blocks(&blocks);
    for request in artifacts.requests() {
        let payload = provider.fetch_payload(request)?;
        assert!(payloads.contains_key(&request.height));
        assert!(payload.transactions.is_empty());
    }

    Ok(())
}
