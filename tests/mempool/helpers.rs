use std::fs;
use std::path::Path;

use std::collections::BTreeSet;

use rpp_chain::config::{NodeConfig, QueueWeightsConfig};
use rpp_chain::consensus::{BftVote, BftVoteKind, SignedBftVote};
use rpp_chain::crypto::{address_from_public_key, generate_keypair, sign_message};
#[cfg(feature = "backend-rpp-stark")]
use rpp_chain::types::RppStarkProof;
use rpp_chain::types::{
    Account, ChainProof, ExecutionTrace, PendingTransactionSummary, ProofKind, ProofPayload,
    ReputationWeights, SignedTransaction, Stake, StarkProof, Tier, Transaction,
    TransactionProofBundle, TransactionWitness,
};
use rpp_p2p::GossipTopic;
use serde_json;
use serde_json::json;
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

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(super) enum ProofBackend {
    Stwo,
    #[cfg(feature = "backend-plonky3")]
    Plonky3,
    #[cfg(feature = "backend-rpp-stark")]
    RppStark,
}

pub(super) fn enabled_backends() -> Vec<ProofBackend> {
    let mut backends = vec![ProofBackend::Stwo];
    #[cfg(feature = "backend-plonky3")]
    {
        backends.push(ProofBackend::Plonky3);
    }
    #[cfg(feature = "backend-rpp-stark")]
    {
        backends.push(ProofBackend::RppStark);
    }
    backends
}

pub(super) fn backend_for_index(backends: &[ProofBackend], index: usize) -> ProofBackend {
    assert!(
        !backends.is_empty(),
        "at least one proof backend must be enabled to run mempool probes",
    );
    let rotated = index % backends.len();
    backends[rotated]
}

pub(super) fn observed_backends(
    transactions: &[PendingTransactionSummary],
) -> BTreeSet<ProofBackend> {
    let mut observed = BTreeSet::new();
    for tx in transactions {
        let Some(proof) = &tx.proof else { continue };
        match proof {
            ChainProof::Stwo(_) => {
                observed.insert(ProofBackend::Stwo);
            }
            #[cfg(feature = "backend-plonky3")]
            ChainProof::Plonky3(_) => {
                observed.insert(ProofBackend::Plonky3);
            }
            #[cfg(feature = "backend-rpp-stark")]
            ChainProof::RppStark(_) => {
                observed.insert(ProofBackend::RppStark);
            }
        }
    }
    observed
}

pub(super) fn sample_transaction_bundle(
    to: &str,
    nonce: u64,
    fee: u64,
    backend: ProofBackend,
) -> TransactionProofBundle {
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
    let proof = match backend {
        ProofBackend::Stwo => ChainProof::Stwo(StarkProof {
            kind: ProofKind::Transaction,
            commitment: String::new(),
            public_inputs: Vec::new(),
            payload: payload.clone(),
            trace: ExecutionTrace {
                segments: Vec::new(),
            },
            commitment_proof: Default::default(),
            fri_proof: Default::default(),
        }),
        #[cfg(feature = "backend-plonky3")]
        ProofBackend::Plonky3 => {
            let payload_hint = json!({
                "nonce": nonce,
                "fee": fee,
                "backend": "plonky3",
            });
            ChainProof::Plonky3(payload_hint)
        }
        #[cfg(feature = "backend-rpp-stark")]
        ProofBackend::RppStark => {
            let params = vec![0xAA, 0x10, (nonce % 0xff) as u8, (fee % 0xff) as u8];
            let public_inputs = format!("nonce-{nonce}-fee-{fee}").into_bytes();
            let proof_bytes = vec![0xBB, 0x20, (nonce % 0xff) as u8, (fee % 0xff) as u8];
            ChainProof::RppStark(RppStarkProof::new(params, public_inputs, proof_bytes))
        }
    };

    TransactionProofBundle::new(signed_tx, proof, Some(witness), Some(payload))
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

pub(super) fn sample_vote(height: u64, round: u64) -> SignedBftVote {
    let keypair = generate_keypair();
    let voter = address_from_public_key(&keypair.public);
    let vote = BftVote {
        round,
        height,
        block_hash: format!("block-{height:08x}-{round:04x}"),
        voter: voter.clone(),
        kind: if round % 2 == 0 {
            BftVoteKind::PreVote
        } else {
            BftVoteKind::PreCommit
        },
    };
    let signature = sign_message(&keypair, &vote.message_bytes());

    SignedBftVote {
        vote,
        public_key: hex::encode(keypair.public.to_bytes()),
        signature: hex::encode(signature.to_bytes()),
    }
}
