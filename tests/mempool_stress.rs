use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Result;
use ed25519_dalek::Signer;
use futures::future::join_all;
use tempfile::tempdir;

type ChainResult<T> = rpp_chain::errors::ChainResult<T>;

use rpp_chain::config::NodeConfig;
use rpp_chain::consensus::{BftVote, BftVoteKind, SignedBftVote};
use rpp_chain::crypto::{
    address_from_public_key, generate_keypair, generate_vrf_keypair, sign_message,
    vrf_public_key_to_hex,
};
use rpp_chain::errors::ChainError;
use rpp_chain::ledger::Ledger;
use rpp_chain::node::Node;
use rpp_chain::proof_backend::Blake2sHasher;
use rpp_chain::runtime::RuntimeMetrics;
use rpp_chain::stwo::circuit::identity::{IdentityCircuit, IdentityWitness};
use rpp_chain::stwo::circuit::{string_to_field, StarkCircuit};
use rpp_chain::stwo::fri::FriProver;
use rpp_chain::stwo::params::StarkParameters;
use rpp_chain::stwo::proof::{ProofKind, ProofPayload, StarkProof};
use rpp_chain::types::{
    Account, AttestedIdentityRequest, ChainProof, IdentityDeclaration, IdentityGenesis,
    IdentityProof, ReputationWeights, SignedTransaction, Stake, Tier, Transaction,
    TransactionProofBundle, TransactionWitness, IDENTITY_ATTESTATION_GOSSIP_MIN,
    IDENTITY_ATTESTATION_QUORUM,
};

#[derive(Clone, Debug)]
struct SubmissionReport {
    latency: Duration,
}

fn sample_node_config(base: &Path, mempool_limit: usize) -> NodeConfig {
    use std::fs;

    let data_dir = base.join("data");
    let keys_dir = base.join("keys");
    fs::create_dir_all(&data_dir).expect("node data dir");
    fs::create_dir_all(&keys_dir).expect("node key dir");

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
    config.rollout.feature_gates.pruning = false;
    config.rollout.feature_gates.recursive_proofs = false;
    config.rollout.feature_gates.reconstruction = false;
    config.rollout.feature_gates.consensus_enforcement = false;
    config
}

fn sample_transaction_bundle(to: &str, nonce: u64) -> TransactionProofBundle {
    let keypair = generate_keypair();
    let from = address_from_public_key(&keypair.public);
    let tx = Transaction::new(from.clone(), to.to_string(), 42, nonce, 1, None);
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

    let proof_payload = ProofPayload::Transaction(witness.clone());
    let proof = StarkProof {
        kind: ProofKind::Transaction,
        commitment: String::new(),
        public_inputs: Vec::new(),
        payload: proof_payload.clone(),
        trace: rpp_chain::types::ExecutionTrace {
            segments: Vec::new(),
        },
        commitment_proof: Default::default(),
        fri_proof: Default::default(),
    };

    TransactionProofBundle::new(
        signed_tx,
        ChainProof::Stwo(proof),
        Some(witness),
        Some(proof_payload),
    )
}

fn seeded_keypair(seed: u8) -> ed25519_dalek::Keypair {
    use ed25519_dalek::{Keypair, PublicKey, SecretKey};

    let secret = SecretKey::from_bytes(&[seed; 32]).expect("secret");
    let public = PublicKey::from(&secret);
    Keypair { secret, public }
}

fn sign_identity_vote(keypair: &ed25519_dalek::Keypair, height: u64, hash: &str) -> SignedBftVote {
    let voter = address_from_public_key(&keypair.public);
    let vote = BftVote {
        round: 0,
        height,
        block_hash: hash.to_string(),
        voter: voter.clone(),
        kind: BftVoteKind::PreCommit,
    };
    let signature = keypair.sign(&vote.message_bytes());
    SignedBftVote {
        vote,
        public_key: hex::encode(keypair.public.to_bytes()),
        signature: hex::encode(signature.to_bytes()),
    }
}

fn sample_identity_declaration(ledger: &Ledger, wallet_seed: u8) -> IdentityDeclaration {
    ledger.sync_epoch_for_height(1);
    let pk_bytes = vec![wallet_seed; 32];
    let wallet_pk = hex::encode(&pk_bytes);
    let wallet_addr = hex::encode::<[u8; 32]>(Blake2sHasher::hash(&pk_bytes).into());
    let epoch_nonce_bytes = ledger.current_epoch_nonce();
    let vrf_keypair = generate_vrf_keypair().expect("generate vrf keypair");
    let vrf = rpp_chain::consensus::evaluate_vrf(
        &epoch_nonce_bytes,
        0,
        &wallet_addr,
        0,
        Some(&vrf_keypair.secret),
    )
    .expect("evaluate vrf");
    let commitment_proof = ledger.identity_commitment_proof(&wallet_addr);
    let genesis = IdentityGenesis {
        wallet_pk,
        wallet_addr,
        vrf_public_key: vrf_public_key_to_hex(&vrf_keypair.public),
        vrf_proof: vrf.clone(),
        epoch_nonce: hex::encode(epoch_nonce_bytes),
        state_root: hex::encode(ledger.state_root()),
        identity_root: hex::encode(ledger.identity_root()),
        initial_reputation: 0,
        commitment_proof: commitment_proof.clone(),
    };

    let parameters = StarkParameters::blueprint_default();
    let expected_commitment = genesis.expected_commitment().expect("commitment");
    let witness = IdentityWitness {
        wallet_pk: genesis.wallet_pk.clone(),
        wallet_addr: genesis.wallet_addr.clone(),
        vrf_tag: genesis.vrf_tag().to_string(),
        epoch_nonce: genesis.epoch_nonce.clone(),
        state_root: genesis.state_root.clone(),
        identity_root: genesis.identity_root.clone(),
        initial_reputation: genesis.initial_reputation,
        commitment: expected_commitment.clone(),
        identity_leaf: commitment_proof.leaf.clone(),
        identity_path: commitment_proof.siblings.clone(),
    };

    let circuit = IdentityCircuit::new(witness.clone());
    circuit
        .evaluate_constraints()
        .expect("identity constraints");
    let trace = circuit.generate_trace(&parameters).expect("identity trace");
    circuit
        .verify_air(&parameters, &trace)
        .expect("identity air");
    let inputs = vec![
        string_to_field(&parameters, &witness.wallet_addr),
        string_to_field(&parameters, &witness.vrf_tag),
        string_to_field(&parameters, &witness.identity_root),
        string_to_field(&parameters, &witness.state_root),
    ];
    let hasher = parameters.poseidon_hasher();
    let fri_prover = FriProver::new(&parameters);
    let air = circuit
        .define_air(&parameters, &trace)
        .expect("identity air definition");
    let fri_output = fri_prover.prove(&air, &trace, &inputs);
    let proof = StarkProof::new(
        ProofKind::Identity,
        ProofPayload::Identity(witness),
        inputs,
        trace,
        fri_output.commitment_proof,
        fri_output.fri_proof,
        &hasher,
    );

    IdentityDeclaration {
        genesis,
        proof: IdentityProof {
            commitment: expected_commitment,
            zk_proof: ChainProof::Stwo(proof),
        },
    }
}

fn attested_identity_request(
    ledger: &Ledger,
    height: u64,
    wallet_seed: u8,
) -> AttestedIdentityRequest {
    let declaration = sample_identity_declaration(ledger, wallet_seed);
    let identity_hash = hex::encode(declaration.hash().expect("identity hash"));
    let voters: Vec<ed25519_dalek::Keypair> = (0..IDENTITY_ATTESTATION_QUORUM)
        .map(|idx| seeded_keypair(wallet_seed.wrapping_add(idx as u8 + 1)))
        .collect();
    let attested_votes = voters
        .iter()
        .map(|kp| sign_identity_vote(kp, height, &identity_hash))
        .collect();
    let gossip_confirmations = voters
        .iter()
        .take(IDENTITY_ATTESTATION_GOSSIP_MIN)
        .map(|kp| address_from_public_key(&kp.public))
        .collect();

    AttestedIdentityRequest {
        declaration,
        attested_votes,
        gossip_confirmations,
    }
}

fn sample_vote(height: u64, seed: u8) -> SignedBftVote {
    let keypair = seeded_keypair(150u8.wrapping_add(seed));
    let voter = address_from_public_key(&keypair.public);
    let vote = BftVote {
        round: 0,
        height,
        block_hash: format!("{:064x}", seed),
        voter,
        kind: BftVoteKind::PreCommit,
    };
    let signature = keypair.sign(&vote.message_bytes());
    SignedBftVote {
        vote,
        public_key: hex::encode(keypair.public.to_bytes()),
        signature: hex::encode(signature.to_bytes()),
    }
}

async fn collect_transaction_results(
    handle: Arc<rpp_chain::node::NodeHandle>,
    bundles: Vec<TransactionProofBundle>,
) -> Vec<(usize, SubmissionReport, ChainResult<String>)> {
    let mut tasks = Vec::with_capacity(bundles.len());
    for (index, bundle) in bundles.into_iter().enumerate() {
        let handle = handle.clone();
        tasks.push(tokio::spawn(async move {
            let start = Instant::now();
            let result = handle.submit_transaction(bundle);
            let latency = start.elapsed();
            (index, SubmissionReport { latency }, result)
        }));
    }
    let mut results = join_all(tasks).await;
    results.sort_by_key(|item| {
        item.as_ref()
            .map(|(index, _, _)| *index)
            .unwrap_or_default()
    });
    results
        .into_iter()
        .map(|join_res| {
            let (index, report, result) = join_res.expect("transaction task join");
            (index, report, result)
        })
        .collect()
}

async fn collect_identity_results(
    handle: Arc<rpp_chain::node::NodeHandle>,
    requests: Vec<AttestedIdentityRequest>,
) -> Vec<(usize, SubmissionReport, ChainResult<String>)> {
    let mut tasks = Vec::with_capacity(requests.len());
    for (index, request) in requests.into_iter().enumerate() {
        let handle = handle.clone();
        tasks.push(tokio::spawn(async move {
            let start = Instant::now();
            let result = handle.submit_identity(request);
            let latency = start.elapsed();
            (index, SubmissionReport { latency }, result)
        }));
    }
    let mut results = join_all(tasks).await;
    results.sort_by_key(|item| {
        item.as_ref()
            .map(|(index, _, _)| *index)
            .unwrap_or_default()
    });
    results
        .into_iter()
        .map(|join_res| {
            let (index, report, result) = join_res.expect("identity task join");
            (index, report, result)
        })
        .collect()
}

async fn collect_vote_results(
    handle: Arc<rpp_chain::node::NodeHandle>,
    votes: Vec<SignedBftVote>,
) -> Vec<(usize, SubmissionReport, ChainResult<String>)> {
    let mut tasks = Vec::with_capacity(votes.len());
    for (index, vote) in votes.into_iter().enumerate() {
        let handle = handle.clone();
        tasks.push(tokio::spawn(async move {
            let start = Instant::now();
            let result = handle.submit_vote(vote);
            let latency = start.elapsed();
            (index, SubmissionReport { latency }, result)
        }));
    }
    let mut results = join_all(tasks).await;
    results.sort_by_key(|item| {
        item.as_ref()
            .map(|(index, _, _)| *index)
            .unwrap_or_default()
    });
    results
        .into_iter()
        .map(|join_res| {
            let (index, report, result) = join_res.expect("vote task join");
            (index, report, result)
        })
        .collect()
}

fn assert_latency_captured(reports: &[SubmissionReport]) {
    assert!(
        reports
            .iter()
            .any(|report| report.latency > Duration::from_micros(0)),
        "expected at least one non-zero latency measurement",
    );
}

fn load_ledger(handle: &rpp_chain::node::NodeHandle, config: &NodeConfig) -> Ledger {
    let storage = handle.storage();
    let accounts = storage.load_accounts().expect("load accounts");
    let utxo_snapshot = storage
        .load_utxo_snapshot()
        .expect("load utxo snapshot")
        .unwrap_or_default();
    let mut ledger = Ledger::load(accounts, utxo_snapshot, config.epoch_length);
    ledger.set_reputation_params(config.reputation_params());
    ledger.set_timetoke_params(config.timetoke_params());
    ledger
}

async fn transaction_overflow_scenario(mempool_limit: usize) -> Result<()> {
    let tempdir = tempdir()?;
    let config = sample_node_config(tempdir.path(), mempool_limit);
    let node = tokio::task::spawn_blocking({
        let config = config.clone();
        move || Node::new(config, RuntimeMetrics::noop())
    })
    .await??;
    let handle = Arc::new(node.handle());
    let recipient = handle.address().to_string();

    let overflow = mempool_limit.max(1) + 2;
    let bundles: Vec<_> = (0..(mempool_limit + overflow) as u64)
        .map(|nonce| sample_transaction_bundle(&recipient, nonce))
        .collect();

    let results = collect_transaction_results(handle.clone(), bundles).await;
    let reports: Vec<_> = results
        .iter()
        .map(|(_, report, _)| report.clone())
        .collect();
    assert_latency_captured(&reports);

    for (index, _report, result) in results.into_iter() {
        if index < mempool_limit {
            result.expect("transaction accepted");
        } else {
            match result {
                Err(ChainError::Transaction(message)) => {
                    assert_eq!(message, "mempool full");
                }
                Err(other) => panic!("unexpected transaction error: {other:?}"),
                Ok(hash) => panic!("unexpectedly accepted overflow transaction {hash}"),
            }
        }
    }

    Ok(())
}

async fn transaction_duplicate_scenario(mempool_limit: usize) -> Result<()> {
    let tempdir = tempdir()?;
    let config = sample_node_config(tempdir.path(), mempool_limit);
    let node = tokio::task::spawn_blocking({
        let config = config.clone();
        move || Node::new(config, RuntimeMetrics::noop())
    })
    .await??;
    let handle = Arc::new(node.handle());
    let recipient = handle.address().to_string();

    let base = sample_transaction_bundle(&recipient, 0);
    handle
        .submit_transaction(base.clone())
        .expect("initial transaction accepted");

    let attempts = mempool_limit + 2;
    let mut tasks = Vec::with_capacity(attempts);
    for _ in 0..attempts {
        let handle = handle.clone();
        let bundle = base.clone();
        tasks.push(tokio::spawn(async move {
            let start = Instant::now();
            let result = handle.submit_transaction(bundle);
            let latency = start.elapsed();
            (SubmissionReport { latency }, result)
        }));
    }

    let joined = join_all(tasks).await;
    let mut reports = Vec::new();
    for join_res in joined {
        let (report, result) = match join_res {
            Ok(pair) => pair,
            Err(err) => panic!("transaction duplicate task join error: {err}"),
        };
        reports.push(report);
        match result {
            Err(ChainError::Transaction(message)) => {
                assert_eq!(message, "transaction already queued");
            }
            Err(other) => panic!("unexpected duplicate error: {other:?}"),
            Ok(hash) => panic!("unexpectedly accepted duplicate transaction {hash}"),
        }
    }
    assert_latency_captured(&reports);

    Ok(())
}

async fn identity_overflow_scenario(mempool_limit: usize) -> Result<()> {
    let tempdir = tempdir()?;
    let config = sample_node_config(tempdir.path(), mempool_limit);
    let node = tokio::task::spawn_blocking({
        let config = config.clone();
        move || Node::new(config, RuntimeMetrics::noop())
    })
    .await??;
    let handle = Arc::new(node.handle());
    let mut ledger = load_ledger(&handle, &config);
    let status = handle.node_status().expect("node status");
    let height = status.height + 1;

    let overflow = mempool_limit.max(1) + 1;
    let requests: Vec<_> = (0..(mempool_limit + overflow) as u8)
        .map(|seed| attested_identity_request(&ledger, height, seed.wrapping_add(1)))
        .collect();

    let results = collect_identity_results(handle, requests).await;
    let reports: Vec<_> = results
        .iter()
        .map(|(_, report, _)| report.clone())
        .collect();
    assert_latency_captured(&reports);

    for (index, _report, result) in results.into_iter() {
        if index < mempool_limit {
            result.expect("identity accepted");
        } else {
            match result {
                Err(ChainError::Transaction(message)) => {
                    assert_eq!(message, "identity mempool full");
                }
                Err(other) => panic!("unexpected identity error: {other:?}"),
                Ok(hash) => panic!("unexpectedly accepted overflow identity {hash}"),
            }
        }
    }

    Ok(())
}

async fn identity_duplicate_scenario(mempool_limit: usize) -> Result<()> {
    let tempdir = tempdir()?;
    let config = sample_node_config(tempdir.path(), mempool_limit);
    let node = tokio::task::spawn_blocking({
        let config = config.clone();
        move || Node::new(config, RuntimeMetrics::noop())
    })
    .await??;
    let handle = Arc::new(node.handle());
    let ledger = load_ledger(&handle, &config);
    let status = handle.node_status().expect("node status");
    let height = status.height + 1;

    let base = attested_identity_request(&ledger, height, 42);
    handle
        .submit_identity(base.clone())
        .expect("initial identity accepted");

    let attempts = mempool_limit + 2;
    let mut tasks = Vec::with_capacity(attempts);
    for _ in 0..attempts {
        let handle = handle.clone();
        let request = base.clone();
        tasks.push(tokio::spawn(async move {
            let start = Instant::now();
            let result = handle.submit_identity(request);
            let latency = start.elapsed();
            (SubmissionReport { latency }, result)
        }));
    }

    let joined = join_all(tasks).await;
    let mut reports = Vec::new();
    for join_res in joined {
        let (report, result) = match join_res {
            Ok(tuple) => tuple,
            Err(err) => panic!("identity duplicate task join error: {err}"),
        };
        reports.push(report);
        match result {
            Err(ChainError::Transaction(message)) => {
                assert_eq!(message, "identity for this wallet already queued");
            }
            Err(other) => panic!("unexpected identity duplicate error: {other:?}"),
            Ok(hash) => panic!("unexpectedly accepted duplicate identity {hash}"),
        }
    }
    assert_latency_captured(&reports);

    Ok(())
}

async fn vote_overflow_scenario(mempool_limit: usize) -> Result<()> {
    let tempdir = tempdir()?;
    let config = sample_node_config(tempdir.path(), mempool_limit);
    let node = tokio::task::spawn_blocking({
        let config = config.clone();
        move || Node::new(config, RuntimeMetrics::noop())
    })
    .await??;
    let handle = Arc::new(node.handle());
    let status = handle.node_status().expect("node status");
    let height = status.height + 1;

    let overflow = mempool_limit.max(1) + 1;
    let votes: Vec<_> = (0..(mempool_limit + overflow) as u8)
        .map(|seed| sample_vote(height, seed))
        .collect();

    let results = collect_vote_results(handle, votes).await;
    let reports: Vec<_> = results
        .iter()
        .map(|(_, report, _)| report.clone())
        .collect();
    assert_latency_captured(&reports);

    for (index, _report, result) in results.into_iter() {
        if index < mempool_limit {
            result.expect("vote accepted");
        } else {
            match result {
                Err(ChainError::Transaction(message)) => {
                    assert_eq!(message, "vote mempool full");
                }
                Err(other) => panic!("unexpected vote error: {other:?}"),
                Ok(hash) => panic!("unexpectedly accepted overflow vote {hash}"),
            }
        }
    }

    Ok(())
}

async fn vote_duplicate_scenario(mempool_limit: usize) -> Result<()> {
    let tempdir = tempdir()?;
    let config = sample_node_config(tempdir.path(), mempool_limit);
    let node = tokio::task::spawn_blocking({
        let config = config.clone();
        move || Node::new(config, RuntimeMetrics::noop())
    })
    .await??;
    let handle = Arc::new(node.handle());
    let status = handle.node_status().expect("node status");
    let height = status.height + 1;

    let base = sample_vote(height, 200);
    handle
        .submit_vote(base.clone())
        .expect("initial vote accepted");

    let attempts = mempool_limit + 2;
    let mut tasks = Vec::with_capacity(attempts);
    for _ in 0..attempts {
        let handle = handle.clone();
        let vote = base.clone();
        tasks.push(tokio::spawn(async move {
            let start = Instant::now();
            let result = handle.submit_vote(vote);
            let latency = start.elapsed();
            (SubmissionReport { latency }, result)
        }));
    }

    let joined = join_all(tasks).await;
    let mut reports = Vec::new();
    for join_res in joined {
        let (report, result) = match join_res {
            Ok(tuple) => tuple,
            Err(err) => panic!("vote duplicate task join error: {err}"),
        };
        reports.push(report);
        match result {
            Err(ChainError::Transaction(message)) => {
                assert_eq!(message, "vote already queued");
            }
            Err(other) => panic!("unexpected vote duplicate error: {other:?}"),
            Ok(hash) => panic!("unexpectedly accepted duplicate vote {hash}"),
        }
    }
    assert_latency_captured(&reports);

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn mempool_stress_harness_validates_throttling_and_duplicates() -> Result<()> {
    let mempool_limit = 3usize;

    transaction_overflow_scenario(mempool_limit).await?;
    transaction_duplicate_scenario(mempool_limit).await?;

    identity_overflow_scenario(mempool_limit).await?;
    identity_duplicate_scenario(mempool_limit).await?;

    vote_overflow_scenario(mempool_limit).await?;
    vote_duplicate_scenario(mempool_limit).await?;

    Ok(())
}
