#![cfg(feature = "wallet-integration")]

use std::collections::BTreeMap;
use std::fs;

use rpp_chain::config::NodeConfig;
use rpp_chain::node::Node;
use rpp_chain::runtime::metrics::RuntimeMetrics;
use rpp_chain::runtime::sync::ReconstructionEngine;
use rpp_chain::runtime::types::{Account, Block, Stake};
use rpp_wallet::config::wallet::WalletProverBackend;
use tempfile::TempDir;

#[path = "support/mod.rs"]
mod support;

use support::{
    collect_state_sync_artifacts, install_pruned_chain, make_dummy_block, InMemoryPayloadProvider,
};

fn wallet_backends() -> Vec<WalletProverBackend> {
    let mut backends = vec![WalletProverBackend::Mock];
    #[cfg(any(feature = "prover-stwo", feature = "backend-rpp-stark"))]
    {
        backends.push(WalletProverBackend::Stwo);
    }
    backends
}

fn prepare_node_config(temp: &TempDir) -> NodeConfig {
    let mut config = NodeConfig::default();
    let data_dir = temp.path().join("data");
    let keys_dir = temp.path().join("keys");
    fs::create_dir_all(&data_dir).expect("data dir");
    fs::create_dir_all(&keys_dir).expect("keys dir");
    config.data_dir = data_dir.clone();
    config.snapshot_dir = data_dir.join("snapshots");
    config.proof_cache_dir = data_dir.join("proofs");
    config.network.p2p.peerstore_path = data_dir.join("p2p/peerstore.json");
    config.network.p2p.gossip_path = Some(data_dir.join("p2p/gossip.json"));
    config.key_path = keys_dir.join("node.toml");
    config.p2p_key_path = keys_dir.join("p2p.toml");
    config.vrf_key_path = keys_dir.join("vrf.toml");
    config.timetoke_snapshot_key_path = keys_dir.join("timetoke_snapshot.toml");
    config.network.rpc.listen = "127.0.0.1:0".parse().expect("rpc listen");
    config
}

fn build_chain(genesis: &Block, length: u64) -> Vec<Block> {
    let mut blocks = Vec::with_capacity((length + 1) as usize);
    blocks.push(genesis.clone());
    let mut previous = Some(genesis.clone());
    for height in 1..=length {
        let block = make_dummy_block(height, previous.as_ref());
        previous = Some(block.clone());
        blocks.push(block);
    }
    blocks
}

fn seed_accounts(storage: &rpp_chain::storage::Storage) -> BTreeMap<String, (u128, u64)> {
    let mut expected = BTreeMap::new();
    for index in 0..3u64 {
        let mut account = Account::new(
            format!("wallet-state-{index}"),
            50_000 * (index as u128 + 1),
            Stake::from_u128(1_000 + index as u128),
        );
        account.nonce = index + 1;
        storage
            .persist_account(&account)
            .expect("persist deterministic account");
        expected.insert(account.address.clone(), (account.balance, account.nonce));
    }
    expected
}

#[test]
fn wallet_state_sync_replays_accounts_across_backends() {
    let temp = TempDir::new().expect("temp dir");
    let config = prepare_node_config(&temp);
    let node = Node::new(config, RuntimeMetrics::noop()).expect("node");
    let handle = node.handle();
    let storage = handle.storage();

    let genesis = handle
        .latest_block()
        .expect("latest block")
        .expect("genesis block");
    let blocks = build_chain(&genesis, 4);
    let payloads = install_pruned_chain(&storage, &blocks).expect("install pruned chain");

    let expected_accounts = seed_accounts(&storage);

    let engine = ReconstructionEngine::new(storage.clone());
    let artifacts = collect_state_sync_artifacts(&engine, 2).expect("state sync artifacts");

    assert!(
        !artifacts.plan.chunks.is_empty(),
        "state sync plan should include at least one chunk"
    );

    for backend in wallet_backends() {
        println!("running wallet state sync assertions for backend: {}", backend.as_str());
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
                "backend {} reconstructed hash should match original",
                backend.as_str()
            );
        }

        let scanned: BTreeMap<String, (u128, u64)> = storage
            .load_accounts()
            .expect("load accounts after state sync")
            .into_iter()
            .map(|account| (account.address.clone(), (account.balance, account.nonce)))
            .collect();

        assert_eq!(
            scanned, expected_accounts,
            "backend {} produced divergent wallet balances or nonces",
            backend.as_str()
        );
    }
}
