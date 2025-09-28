use std::sync::{Mutex, OnceLock};
use std::thread;
use std::time::Duration;

use super::bft_loop::{run_bft_loop, shutdown, submit_prevote, submit_proposal};
use super::messages::{Block, ConsensusProof, PreVote, Proposal};
use super::state::{ConsensusConfig, GenesisConfig};
use std::collections::BTreeMap;

use super::validator::{select_leader, select_validators, VRFOutput, ValidatorLedgerEntry};

fn sample_public_key(id: &str) -> Vec<u8> {
    format!("pk-{id}").into_bytes()
}

fn sample_seed(id: &str) -> [u8; 32] {
    let mut seed = [0u8; 32];
    let id_bytes = id.as_bytes();
    let len = id_bytes.len().min(32);
    seed[..len].copy_from_slice(&id_bytes[..len]);
    seed
}

fn make_proof(
    epoch: u64,
    id: &str,
    seed: [u8; 32],
    public_key: &[u8],
    output: [u8; 32],
) -> Vec<u8> {
    let mut hasher = blake3::Hasher::new();
    hasher.update(&seed);
    hasher.update(&epoch.to_be_bytes());
    hasher.update(id.as_bytes());
    hasher.update(public_key);
    hasher.update(&output);
    hasher.finalize().as_bytes().to_vec()
}

fn build_vrf_output(
    epoch: u64,
    id: &str,
    output: [u8; 32],
    tier: u8,
    score: f64,
    timetoken: u64,
) -> VRFOutput {
    let seed = sample_seed(id);
    let public_key = sample_public_key(id);
    let proof = make_proof(epoch, id, seed, &public_key, output);
    VRFOutput {
        validator_id: id.to_string(),
        output,
        proof,
        reputation_tier: tier,
        reputation_score: score,
        timetoken_balance: timetoken,
        seed,
        public_key,
    }
}

fn build_ledger(entries: &[(&str, u64, u8, f64)]) -> BTreeMap<String, ValidatorLedgerEntry> {
    entries
        .iter()
        .map(|(id, stake, tier, score)| {
            (
                (*id).to_string(),
                ValidatorLedgerEntry {
                    stake: *stake,
                    reputation_tier: *tier,
                    reputation_score: *score,
                },
            )
        })
        .collect()
}

fn acquire_test_lock() -> std::sync::MutexGuard<'static, ()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
        .lock()
        .expect("lock poisoned")
}

#[test]
fn bft_flow_reaches_commit() {
    let _guard = acquire_test_lock();
    let vrf_outputs = vec![
        build_vrf_output(0, "validator-1", [1; 32], 4, 1.5, 2_000_000),
        build_vrf_output(0, "validator-2", [2; 32], 3, 1.2, 1_500_000),
        build_vrf_output(0, "validator-3", [3; 32], 3, 1.1, 1_300_000),
    ];
    let ledger = build_ledger(&[
        ("validator-1", 10, 4, 1.5),
        ("validator-2", 8, 3, 1.2),
        ("validator-3", 6, 3, 1.1),
    ]);

    let config = ConsensusConfig::new(50, 50, 10, 0.1);
    let genesis = GenesisConfig::new(
        0,
        vrf_outputs.clone(),
        ledger.clone(),
        "root".into(),
        config,
    );
    let state = super::state::ConsensusState::new(genesis).expect("state init");

    let handle = thread::spawn(move || {
        let mut state = state;
        run_bft_loop(&mut state);
        state
    });

    thread::sleep(Duration::from_millis(25));

    let validator_set = select_validators(0, &vrf_outputs, &ledger);
    let leader = select_leader(&validator_set).expect("leader");
    let proposal = Proposal {
        block: Block {
            height: 1,
            epoch: 0,
            payload: serde_json::json!({"tx": []}),
            timestamp: 0,
        },
        proof: ConsensusProof {
            commitment: "commitment-1".into(),
            witness_hash: "witness-1".into(),
            recursion_depth: 0,
            valid: true,
        },
        leader_id: leader.id.clone(),
    };

    submit_proposal(proposal.clone()).expect("proposal");
    thread::sleep(Duration::from_millis(25));

    for validator in &validator_set.validators {
        let vote = PreVote {
            block_hash: proposal.block_hash(),
            proof_valid: true,
            validator_id: validator.id.clone(),
            round: 0,
        };
        submit_prevote(vote).expect("prevote");
    }

    thread::sleep(Duration::from_millis(100));

    shutdown().expect("shutdown");
    let final_state = handle.join().expect("join");

    assert_eq!(final_state.block_height, 1);
    assert!(final_state.pending_rewards.len() >= 1);
    assert!(final_state.pending_proofs.len() >= 1);
}

#[test]
fn timeout_triggers_new_proposal_flow() {
    let _guard = acquire_test_lock();
    let vrf_outputs = vec![
        build_vrf_output(0, "validator-1", [1; 32], 4, 1.5, 2_000_000),
        build_vrf_output(0, "validator-2", [2; 32], 3, 1.2, 1_500_000),
        build_vrf_output(0, "validator-3", [3; 32], 3, 1.1, 1_300_000),
    ];
    let ledger = build_ledger(&[
        ("validator-1", 10, 4, 1.5),
        ("validator-2", 8, 3, 1.2),
        ("validator-3", 6, 3, 1.1),
    ]);

    let config = ConsensusConfig::new(30, 30, 10, 0.1);
    let genesis = GenesisConfig::new(
        0,
        vrf_outputs.clone(),
        ledger.clone(),
        "root".into(),
        config,
    );
    let state = super::state::ConsensusState::new(genesis).expect("state init");

    let handle = thread::spawn(move || {
        let mut state = state;
        run_bft_loop(&mut state);
        state
    });

    thread::sleep(Duration::from_millis(10));

    let validator_set = select_validators(0, &vrf_outputs, &ledger);
    let leader = select_leader(&validator_set).expect("leader");

    let manual_proposal = Proposal {
        block: Block {
            height: 1,
            epoch: 0,
            payload: serde_json::json!({"tx": []}),
            timestamp: 0,
        },
        proof: ConsensusProof {
            commitment: "manual-commitment".into(),
            witness_hash: "manual-witness".into(),
            recursion_depth: 0,
            valid: true,
        },
        leader_id: leader.id.clone(),
    };
    let manual_hash = manual_proposal.block_hash();

    submit_proposal(manual_proposal).expect("manual proposal");
    thread::sleep(Duration::from_millis(10));

    let prevote = PreVote {
        block_hash: manual_hash.clone(),
        proof_valid: true,
        validator_id: leader.id.clone(),
        round: 0,
    };
    submit_prevote(prevote).expect("prevote");

    thread::sleep(Duration::from_millis(120));

    shutdown().expect("shutdown");
    let final_state = handle.join().expect("join");

    assert!(final_state.round >= 1, "timeout should advance the round");
    assert!(
        final_state
            .pending_proposals
            .iter()
            .any(|proposal| proposal.proof.commitment.starts_with("stwo-commitment-")),
        "expected timeout to trigger a new leader proposal",
    );
    if !final_state
        .pending_prevote_messages
        .iter()
        .any(|vote| vote.validator_id == leader.id && vote.block_hash == manual_hash)
    {
        assert!(
            final_state.pending_prevote_messages.is_empty(),
            "expected either manual prevote to remain or queue to be drained after timeout",
        );
    }
}

#[test]
fn select_validators_rejects_manipulated_proof() {
    let epoch = 0;
    let valid = build_vrf_output(epoch, "validator-1", [9; 32], 3, 1.2, 1_000_000);
    let mut tampered = build_vrf_output(epoch, "validator-2", [7; 32], 3, 1.2, 1_000_000);
    tampered.proof[0] ^= 0xFF;

    let outputs = vec![valid.clone(), tampered.clone()];
    let ledger = build_ledger(&[("validator-1", 5, 3, 1.2), ("validator-2", 5, 3, 1.2)]);

    let set = select_validators(epoch, &outputs, &ledger);
    assert_eq!(set.validators.len(), 1);
    assert_eq!(set.validators[0].id, "validator-1");
}

#[test]
fn select_validators_applies_stake_weights() {
    let epoch = 1;
    let a = build_vrf_output(epoch, "validator-a", [4; 32], 3, 1.0, 1_000_000);
    let b = build_vrf_output(epoch, "validator-b", [5; 32], 3, 1.0, 1_000_000);
    let outputs = vec![a, b];
    let ledger = build_ledger(&[("validator-a", 5, 3, 1.0), ("validator-b", 10, 3, 1.0)]);

    let set = select_validators(epoch, &outputs, &ledger);
    assert_eq!(set.validators.len(), 2);

    let weight_a = set.voting_power(&"validator-a".to_string());
    let weight_b = set.voting_power(&"validator-b".to_string());
    assert!(weight_b > weight_a);
    assert_eq!(weight_b, weight_a * 2);
}
