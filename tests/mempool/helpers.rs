use std::fs;
use std::path::Path;

use rpp_chain::config::{NodeConfig, QueueWeightsConfig};
use rpp_chain::crypto::{address_from_public_key, generate_keypair, sign_message};
use rpp_chain::types::{
    Account, ChainProof, ExecutionTrace, PendingTransactionSummary, ProofKind, ProofPayload,
    ReputationWeights, SignedTransaction, Stake, StarkProof, Tier, Transaction,
    TransactionProofBundle, TransactionWitness,
};
use rpp_p2p::GossipTopic;
use serde_json;
use tokio::sync::broadcast;
use tokio::time::{timeout, Duration};

pub(super) fn sample_node_config(base: &Path, mempool_limit: usize) -> NodeConfig {
    let data_dir = base.join("data");
    let keys_dir = base.join("keys");
    fs::create_dir_all(&data_dir).expect("create node data directory for mempool tests");
    fs::create_dir_all(&keys_dir).expect("create node key directory for mempool tests");

    let mut config = NodeConfig::default();
    config.data_dir = data_dir.clone();
    config.snapshot_dir = data_dir.join("snapshots");
    config.proof_cache_dir = data_dir.join("proofs");
    config.network.p2p.peerstore_path = data_dir.join("p2p/peerstore.json");
    config.network.p2p.gossip_path = Some(data_dir.join("p2p/gossip.json"));
    config.key_path = keys_dir.join("node.toml");
    config.p2p_key_path = keys_dir.join("p2p.toml");
    config.vrf_key_path = keys_dir.join("vrf.toml");
    config.block_time_ms = 200;
    config.mempool_limit = mempool_limit;
    config.queue_weights = QueueWeightsConfig {
        priority: 0.55,
        fee: 0.45,
    };
    config.rollout.feature_gates.pruning = false;
    config.rollout.feature_gates.recursive_proofs = false;
    config.rollout.feature_gates.reconstruction = false;
    config.rollout.feature_gates.consensus_enforcement = false;
    config
}

pub(super) fn sample_transaction_bundle(to: &str, nonce: u64, fee: u64) -> TransactionProofBundle {
    let keypair = generate_keypair();
    let from = address_from_public_key(&keypair.public);
    let tx = Transaction::new(from.clone(), to.to_string(), 42, fee, nonce, None);
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

    let payload = ProofPayload::Transaction(witness.clone());
    let proof = StarkProof {
        kind: ProofKind::Transaction,
        commitment: String::new(),
        public_inputs: Vec::new(),
        payload: payload.clone(),
        trace: ExecutionTrace {
            segments: Vec::new(),
        },
        commitment_proof: Default::default(),
        fri_proof: Default::default(),
    };

    TransactionProofBundle::new(
        signed_tx,
        ChainProof::Stwo(proof),
        Some(witness),
        Some(payload),
    )
}

pub(super) async fn recv_witness_transaction(
    receiver: &mut broadcast::Receiver<Vec<u8>>,
) -> Option<PendingTransactionSummary> {
    match timeout(Duration::from_secs(1), receiver.recv()).await {
        Ok(Ok(payload)) => serde_json::from_slice(&payload).ok(),
        _ => None,
    }
}

pub(super) fn drain_witness_channel(receiver: &mut broadcast::Receiver<Vec<u8>>) {
    loop {
        match receiver.try_recv() {
            Ok(_) => continue,
            Err(broadcast::error::TryRecvError::Empty) => break,
            Err(broadcast::error::TryRecvError::Closed) => break,
            Err(broadcast::error::TryRecvError::Lagged(_)) => continue,
        }
    }
}

pub(super) fn witness_topic() -> GossipTopic {
    GossipTopic::WitnessProofs
}

pub(super) fn sort_bundles_by_fee_desc(
    bundles: impl IntoIterator<Item = TransactionProofBundle>,
) -> Vec<TransactionProofBundle> {
    let mut bundles: Vec<_> = bundles.into_iter().collect();
    bundles.sort_by(|lhs, rhs| {
        rhs.transaction
            .payload
            .fee
            .cmp(&lhs.transaction.payload.fee)
            .then(
                lhs.transaction
                    .payload
                    .nonce
                    .cmp(&rhs.transaction.payload.nonce),
            )
    });
    bundles
}
