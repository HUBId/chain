use std::fs;
use std::path::Path;

use anyhow::Result;
use tempfile::tempdir;

use rpp_chain::config::NodeConfig;
use rpp_chain::crypto::{address_from_public_key, generate_keypair, sign_message};
use rpp_chain::errors::ChainError;
use rpp_chain::node::Node;
#[cfg(feature = "prover-stwo")]
use rpp_chain::proof_system::ProofProver;
use rpp_chain::proof_system::ProofVerifierRegistry;
use rpp_chain::storage::Storage;
#[cfg(feature = "prover-stwo")]
use rpp_chain::stwo::prover::WalletProver;
use rpp_chain::types::{
    Account, ChainProof, ProofPayload, ReputationWeights, SignedTransaction, Stake, Tier,
    Transaction, TransactionProofBundle, TransactionWitness,
};

fn sample_node_config(base: &Path, mempool_limit: usize) -> NodeConfig {
    let data_dir = base.join("data");
    let keys_dir = base.join("keys");
    fs::create_dir_all(&data_dir).expect("node data dir");
    fs::create_dir_all(&keys_dir).expect("node key dir");

    let mut config = NodeConfig::default();
    config.data_dir = data_dir.clone();
    config.snapshot_dir = data_dir.join("snapshots");
    config.proof_cache_dir = data_dir.join("proofs");
    config.p2p.peerstore_path = data_dir.join("p2p/peerstore.json");
    config.p2p.gossip_path = Some(data_dir.join("p2p/gossip.json"));
    config.key_path = keys_dir.join("node.toml");
    config.p2p_key_path = keys_dir.join("p2p.toml");
    config.vrf_key_path = keys_dir.join("vrf.toml");
    config.block_time_ms = 200;
    config.mempool_limit = mempool_limit;
    config.rollout.feature_gates.pruning = false;
    config.rollout.feature_gates.recursive_proofs = false;
    config.rollout.feature_gates.reconstruction = false;
    config.rollout.feature_gates.consensus_enforcement = false;
    config
}

#[cfg(feature = "prover-stwo")]
fn sample_transaction_bundle(storage: &Storage, to: &str, nonce: u64) -> TransactionProofBundle {
    let keypair = generate_keypair();
    let from = address_from_public_key(&keypair.public);
    let tx_nonce = nonce.checked_add(1).expect("nonce overflow");
    let tx = Transaction::new(from.clone(), to.to_string(), 42, 1, tx_nonce, None);
    let signature = sign_message(&keypair, &tx.canonical_bytes());
    let signed_tx = SignedTransaction::new(tx, signature, &keypair.public);

    let mut sender = Account::new(from.clone(), 1_000_000, Stake::from_u128(1_000));
    sender.nonce = nonce;

    let receiver = Account::new(to.to_string(), 0, Stake::default());

    let witness = TransactionWitness {
        signed_tx: signed_tx.clone(),
        sender_account: sender,
        receiver_account: Some(receiver),
        required_tier: Tier::Tl0,
        reputation_weights: ReputationWeights::default(),
    };

    let prover = WalletProver::new(storage);
    let proof = prover
        .prove_transaction(witness.clone())
        .expect("generate transaction proof");
    let proof_payload = match &proof {
        ChainProof::Stwo(stark) => Some(stark.payload.clone()),
        #[cfg(feature = "backend-plonky3")]
        ChainProof::Plonky3(_) => None,
        #[cfg(feature = "backend-rpp-stark")]
        ChainProof::RppStark(_) => None,
    };

    TransactionProofBundle::new(signed_tx, proof, Some(witness), proof_payload)
}

#[cfg(not(feature = "prover-stwo"))]
fn sample_transaction_bundle(_: &Storage, _: &str, _: u64) -> TransactionProofBundle {
    unreachable!("transaction proving requires the `prover-stwo` feature");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mempool_rejects_overflow_and_recovers_after_restart() -> Result<()> {
    if !cfg!(feature = "prover-stwo") {
        eprintln!("skipping mempool overflow test: prover-stwo feature disabled");
        return Ok(());
    }

    let tempdir = tempdir()?;
    let mempool_limit = 4usize;
    let overflow = 2usize;

    let config = sample_node_config(tempdir.path(), mempool_limit);
    let node = tokio::task::spawn_blocking({
        let config = config.clone();
        move || Node::new(config)
    })
    .await
    .expect("spawn blocking")
    .expect("node init");
    let handle = node.handle();
    let recipient = handle.address().to_string();

    let storage = handle.storage();
    let verifiers = ProofVerifierRegistry::default();
    let mut accepted_hashes = Vec::with_capacity(mempool_limit);
    for nonce in 0..mempool_limit as u64 {
        let bundle = sample_transaction_bundle(&storage, &recipient, nonce);
        verifiers
            .verify_transaction(&bundle.proof)
            .expect("bundle should verify");
        let hash = handle
            .submit_transaction(bundle)
            .expect("transaction accepted");
        accepted_hashes.push(hash);
    }

    for nonce in mempool_limit as u64..(mempool_limit + overflow) as u64 {
        let bundle = sample_transaction_bundle(&storage, &recipient, nonce);
        verifiers
            .verify_transaction(&bundle.proof)
            .expect("bundle should verify");
        match handle.submit_transaction(bundle) {
            Err(ChainError::Transaction(message)) => {
                assert_eq!(message, "mempool full");
            }
            Err(other) => panic!("unexpected error: {other:?}"),
            Ok(hash) => panic!("unexpectedly accepted overflow transaction {hash}"),
        }
    }

    let status = handle.mempool_status().expect("mempool status");
    let queued_hashes: Vec<_> = status
        .transactions
        .iter()
        .map(|tx| tx.hash.clone())
        .collect();
    assert_eq!(
        queued_hashes, accepted_hashes,
        "mempool should retain initial submissions"
    );
    for tx in &status.transactions {
        assert!(
            tx.witness.is_some(),
            "pending transaction missing witness metadata"
        );
        assert!(
            tx.proof.is_some(),
            "pending transaction missing proof artifact"
        );
        assert!(
            tx.proof_payload.is_some(),
            "pending transaction missing proof payload metadata"
        );
    }

    drop(storage);
    drop(handle);
    drop(node);

    let restarted = tokio::task::spawn_blocking({
        let config = config.clone();
        move || Node::new(config)
    })
    .await
    .expect("spawn blocking")
    .expect("node init after restart");
    let restarted_handle = restarted.handle();

    let restarted_status = restarted_handle
        .mempool_status()
        .expect("mempool status after restart");
    assert!(
        restarted_status.transactions.is_empty(),
        "mempool should be empty after restart"
    );

    Ok(())
}
