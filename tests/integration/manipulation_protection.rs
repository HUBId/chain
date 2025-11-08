use std::sync::Arc;

use anyhow::Result;
use rpp_chain::runtime::sync::{ReconstructionEngine, RuntimeRecursiveProofVerifier};
use rpp_chain::storage::Storage;
use rpp_p2p::{LightClientSync, PipelineError};
use serde::Serialize;
use serde_json::to_vec;
use tempfile::TempDir;

#[path = "../support/mod.rs"]
mod support;

use support::sync::{
    collect_state_sync_artifacts, corrupt_chunk_commitment, corrupt_chunk_proof,
    corrupt_light_client_commitment, install_pruned_chain, make_dummy_block, StateSyncArtifacts,
};

struct StateSyncFixture {
    _dir: TempDir,
    artifacts: StateSyncArtifacts,
}

impl StateSyncFixture {
    fn new() -> Result<Self> {
        let dir = tempfile::tempdir()?;
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
        let artifacts = collect_state_sync_artifacts(&engine, 2)?;

        Ok(Self {
            _dir: dir,
            artifacts,
        })
    }

    fn new_light_client(&self) -> LightClientSync {
        LightClientSync::new(Arc::new(RuntimeRecursiveProofVerifier::default()), None)
    }

    fn encode<T>(&self, value: &T) -> Result<Vec<u8>>
    where
        T: Serialize,
    {
        Ok(to_vec(value)?)
    }
}

#[test]
fn tampered_chunk_commitment_is_rejected() -> Result<()> {
    let fixture = StateSyncFixture::new()?;
    let mut light_client = fixture.new_light_client();
    light_client.ingest_plan(&fixture.encode(&fixture.artifacts.network_plan)?)?;

    let chunk = fixture
        .artifacts
        .chunk_messages
        .first()
        .expect("fixture provides chunk");
    let tampered = corrupt_chunk_commitment(chunk);
    let error = light_client
        .ingest_chunk(&fixture.encode(&tampered)?)
        .expect_err("tampered commitment must be rejected");

    match error {
        PipelineError::SnapshotVerification(message) => {
            assert!(
                message.contains("commitment mismatch"),
                "unexpected error message: {message}"
            );
        }
        other => panic!("unexpected error variant: {other:?}"),
    }

    Ok(())
}

#[test]
fn tampered_chunk_proof_is_rejected() -> Result<()> {
    let fixture = StateSyncFixture::new()?;
    let mut light_client = fixture.new_light_client();
    light_client.ingest_plan(&fixture.encode(&fixture.artifacts.network_plan)?)?;

    let chunk = fixture
        .artifacts
        .chunk_messages
        .first()
        .expect("fixture provides chunk");
    let tampered = corrupt_chunk_proof(chunk);
    let error = light_client
        .ingest_chunk(&fixture.encode(&tampered)?)
        .expect_err("tampered proof must be rejected");

    match error {
        PipelineError::SnapshotVerification(message) => {
            assert!(
                message.contains("root mismatch") || message.contains("commitment mismatch"),
                "unexpected error message: {message}"
            );
        }
        other => panic!("unexpected error variant: {other:?}"),
    }

    Ok(())
}

#[test]
fn tampered_light_client_commitment_is_rejected() -> Result<()> {
    let fixture = StateSyncFixture::new()?;
    let mut light_client = fixture.new_light_client();
    light_client.ingest_plan(&fixture.encode(&fixture.artifacts.network_plan)?)?;

    // Provide a valid chunk to ensure the plan is initialised.
    for chunk in &fixture.artifacts.chunk_messages {
        light_client.ingest_chunk(&fixture.encode(chunk)?)?;
    }

    let update = fixture
        .artifacts
        .updates
        .first()
        .expect("fixture provides update");
    let tampered = corrupt_light_client_commitment(update);
    let error = light_client
        .ingest_light_client_update(&fixture.encode(&tampered)?)
        .expect_err("tampered commitment must be rejected");

    match error {
        PipelineError::SnapshotVerification(message) => {
            assert!(
                message.contains("commitment mismatch"),
                "unexpected error message: {message}"
            );
        }
        other => panic!("unexpected error variant: {other:?}"),
    }

    Ok(())
}
