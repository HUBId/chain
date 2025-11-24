use std::fs::{self, OpenOptions};
use std::io::{Seek, SeekFrom, Write};

use rpp_chain::config::{NodeConfig, DEFAULT_PRUNING_RETENTION_DEPTH};
use rpp_chain::node::Node;
use rpp_chain::runtime::sync::ReconstructionEngine;
use rpp_chain::runtime::types::Block;
use rpp_chain::runtime::RuntimeMetrics;
use serde_json::Value;
use storage_firewood::wal::{FileWal, WalError};
use tempfile::TempDir;

#[path = "mempool/helpers.rs"]
mod mempool_helpers;
mod support;

use mempool_helpers::{
    backend_for_index, enabled_backends, sample_node_config, sample_transaction_bundle,
};
use support::{
    collect_state_sync_artifacts, install_pruned_chain, make_dummy_block, InMemoryPayloadProvider,
};

fn prepare_config(base: &TempDir, use_rpp_stark: bool) -> NodeConfig {
    let mut config = sample_node_config(base.path(), 8);
    config.rollout.feature_gates.pruning = true;
    config.rollout.feature_gates.reconstruction = true;
    config.rollout.feature_gates.recursive_proofs = use_rpp_stark;
    config.rollout.feature_gates.malachite_consensus = use_rpp_stark;
    config
}

fn build_chain(handle: &rpp_chain::node::NodeHandle, length: u64) -> Vec<Block> {
    let genesis = handle
        .latest_block()
        .expect("latest block")
        .expect("genesis block");
    let mut blocks = Vec::new();
    blocks.push(genesis.clone());
    let mut previous = Some(genesis);
    for height in 1..=length {
        let block = make_dummy_block(height, previous.as_ref());
        previous = Some(block.clone());
        blocks.push(block);
    }
    blocks
}

fn run_pruning_checkpoint_flow(use_rpp_stark: bool) {
    let temp = TempDir::new().expect("temp dir");
    let config = prepare_config(&temp, use_rpp_stark);
    let restart_config = config.clone();
    let wal_dir = temp.path().join("mempool-wal");
    fs::create_dir_all(&wal_dir).expect("wal dir");

    let node = Node::new(config, RuntimeMetrics::noop()).expect("node");
    let handle = node.handle();
    let storage = handle.storage();

    let blocks = build_chain(&handle, 5);
    let payloads = install_pruned_chain(&storage, &blocks).expect("install pruned chain");

    let pruning_status = handle
        .run_pruning_cycle(3, DEFAULT_PRUNING_RETENTION_DEPTH)
        .expect("pruning cycle")
        .expect("pruning status");
    let checkpoint_path = temp.path().join(format!(
        "checkpoint-{}.json",
        pruning_status.plan.tip.height
    ));
    fs::write(
        &checkpoint_path,
        serde_json::to_vec(&pruning_status.plan).expect("encode plan"),
    )
    .expect("persist checkpoint plan");
    let pruning_tip = pruning_status.plan.tip.height;

    let engine = ReconstructionEngine::new(storage.clone());
    let artifacts = collect_state_sync_artifacts(&engine, 2).expect("state sync artifacts");
    assert_eq!(
        artifacts.plan.tip.height, pruning_tip,
        "checkpoint height should track pruning plan tip",
    );

    let provider = InMemoryPayloadProvider::new(payloads.clone());
    for request in artifacts.requests() {
        let rebuilt = engine
            .reconstruct_block(request.height, &provider)
            .expect("reconstruct block");
        let original = blocks
            .iter()
            .find(|block| block.header.height == request.height)
            .expect("original block");
        assert_eq!(
            rebuilt.hash, original.hash,
            "state hash should survive pruning"
        );
        let previous = blocks
            .iter()
            .find(|block| block.header.height + 1 == request.height)
            .cloned();
        rebuilt
            .verify_pruning(previous.as_ref())
            .expect("pruning proof should verify after reconstruction");
    }

    let mut wal = FileWal::open(&wal_dir).expect("open mempool wal");
    let recipient = handle.address().to_string();
    let backends = enabled_backends();
    for index in 0..3u64 {
        let backend = backend_for_index(&backends, index as usize);
        let bundle = sample_transaction_bundle(&recipient, index, 25 + index, backend);
        handle
            .submit_transaction(bundle.clone())
            .expect("enqueue transaction for mempool replay");
        let bytes = serde_json::to_vec(&bundle).expect("serialize mempool bundle");
        wal.append(&bytes).expect("append bundle to wal");
    }
    wal.sync().expect("sync mempool wal");
    let wal_path = wal_dir.join("firewood.wal");
    let baseline_len = fs::metadata(&wal_path).expect("wal metadata").len();

    {
        let mut wal_file = OpenOptions::new()
            .write(true)
            .open(&wal_path)
            .expect("open wal for crash simulation");
        wal_file
            .seek(SeekFrom::End(0))
            .expect("seek to wal end for crash simulation");
        wal_file
            .write_all(&128u32.to_le_bytes())
            .expect("write partial record length");
        wal_file.flush().expect("flush partial wal record");
        wal_file.sync_data().expect("sync crash payload");
    }

    drop(wal);
    drop(handle);
    drop(node);

    match FileWal::open(&wal_dir) {
        Err(WalError::Corrupt) => {}
        other => panic!("expected WalError::Corrupt after crash, got {other:?}"),
    }

    let mut wal_file = OpenOptions::new()
        .write(true)
        .open(&wal_path)
        .expect("open wal for truncation");
    wal_file
        .set_len(baseline_len)
        .expect("truncate wal after crash");
    wal_file.sync_data().expect("sync wal truncation");

    let wal = FileWal::open(&wal_dir).expect("reopen wal after crash");
    let replayed = wal.replay_from(0).expect("replay wal after crash");
    assert_eq!(replayed.len(), 3, "should recover queued transactions");
    let recovered: Vec<_> = replayed
        .into_iter()
        .map(|(_, payload)| {
            serde_json::from_slice(&payload).expect("decode recovered transaction bundle")
        })
        .collect();

    let node = Node::new(restart_config, RuntimeMetrics::noop()).expect("restart node");
    let handle = node.handle();
    for bundle in &recovered {
        handle
            .submit_transaction(bundle.clone())
            .expect("replay recovered transaction into mempool");
    }

    let mempool_status = handle
        .mempool_status()
        .expect("mempool status after recovery");
    assert_eq!(
        mempool_status.transactions.len(),
        recovered.len(),
        "mempool should replay recovered transactions",
    );

    let reloaded_plan: Value =
        serde_json::from_slice(&fs::read(&checkpoint_path).expect("read checkpoint plan"))
            .expect("decode checkpoint json");
    assert_eq!(
        reloaded_plan
            .get("tip")
            .and_then(|tip| tip.get("height"))
            .and_then(|height| height.as_u64()),
        Some(pruning_tip),
        "checkpoint should reflect reconstructed tip height",
    );
}

#[test]
fn pruning_checkpoint_round_trip_default_backend() {
    run_pruning_checkpoint_flow(false);
}

#[cfg(feature = "backend-rpp-stark")]
#[test]
fn pruning_checkpoint_round_trip_rpp_stark_backend() {
    run_pruning_checkpoint_flow(true);
}
