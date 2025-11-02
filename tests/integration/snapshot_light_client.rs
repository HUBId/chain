use anyhow::Result;
use tempfile::tempdir;

use rpp_chain::runtime::sync::ReconstructionEngine;
use rpp_chain::storage::Storage;

#[path = "../support/mod.rs"]
mod support;

use support::sync::{collect_state_sync_artifacts, install_pruned_chain, make_dummy_block};

#[test]
fn light_client_updates_chain_commitments() -> Result<()> {
    let dir = tempdir()?;
    let storage = Storage::open(dir.path())?;

    let mut blocks = Vec::new();
    let mut previous = None;
    for height in 1..=4 {
        let block = make_dummy_block(height, previous.as_ref());
        previous = Some(block.clone());
        blocks.push(block);
    }

    install_pruned_chain(&storage, &blocks)?;
    let engine = ReconstructionEngine::new(storage.clone());
    let artifacts = collect_state_sync_artifacts(&engine, 1)?;

    assert!(artifacts.updates.len() >= 1);

    let mut expected_previous = Some(artifacts.network_plan.snapshot.chain_commitment.clone());
    for update in &artifacts.updates {
        assert_eq!(update.previous_commitment, expected_previous);
        expected_previous = Some(update.proof_commitment.clone());
    }

    Ok(())
}
