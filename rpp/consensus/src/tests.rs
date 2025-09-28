use std::collections::{BTreeMap, HashMap};
use std::sync::{Mutex, OnceLock};
use std::thread;
use std::time::Duration;

use libp2p::PeerId;

use super::bft_loop::{run_bft_loop, shutdown, submit_precommit, submit_prevote, submit_proposal};
use super::evidence::EvidenceType;
use super::messages::{
    Block, BlockId, ConsensusProof, PreCommit, PreVote, ProofVerificationError, Proposal,
};
use super::state::{ConsensusConfig, GenesisConfig};

use super::validator::{
    select_leader, select_validators, StakeInfo, VRFOutput, Validator, ValidatorLedgerEntry,
};

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

fn make_vote_signature(
    peer: &PeerId,
    block_hash: &BlockId,
    round: u64,
    height: u64,
    phase: &str,
) -> Vec<u8> {
    let mut hasher = blake3::Hasher::new();
    hasher.update(&peer.to_bytes());
    hasher.update(block_hash.0.as_bytes());
    hasher.update(&round.to_le_bytes());
    hasher.update(&height.to_le_bytes());
    hasher.update(phase.as_bytes());
    hasher.finalize().as_bytes().to_vec()
}

fn build_prevote(
    validator: &Validator,
    peer: &PeerId,
    block_hash: &BlockId,
    round: u64,
    height: u64,
    proof_valid: bool,
) -> PreVote {
    PreVote {
        block_hash: block_hash.clone(),
        proof_valid,
        validator_id: validator.id.clone(),
        peer_id: peer.clone(),
        signature: make_vote_signature(peer, block_hash, round, height, "prevote"),
        height,
        round,
    }
}

fn build_precommit(
    validator: &Validator,
    peer: &PeerId,
    block_hash: &BlockId,
    round: u64,
    height: u64,
) -> PreCommit {
    PreCommit {
        block_hash: block_hash.clone(),
        validator_id: validator.id.clone(),
        peer_id: peer.clone(),
        signature: make_vote_signature(peer, block_hash, round, height, "precommit"),
        height,
        round,
    }
}

fn build_consensus_proof(label: &str) -> ConsensusProof {
    let commitments = vec![
        format!("{label}-validator-a"),
        format!("{label}-validator-b"),
    ];
    ConsensusProof::new(
        format!("commitment-{label}"),
        format!("witness-{label}"),
        commitments.len() as u32,
        commitments,
    )
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
        proof: build_consensus_proof("bft-1"),
        leader_id: leader.id.clone(),
    };

    submit_proposal(proposal.clone()).expect("proposal");
    thread::sleep(Duration::from_millis(25));

    let mut peers: HashMap<_, _> = HashMap::new();
    for validator in &validator_set.validators {
        peers.insert(validator.id.clone(), PeerId::random());
    }

    for validator in &validator_set.validators {
        let peer = peers.get(&validator.id).expect("peer id");
        let block_hash = proposal.block_hash();
        let height = proposal.block.height;
        let prevote = build_prevote(validator, peer, &block_hash, 0, height, true);
        submit_prevote(prevote).expect("prevote");
        let precommit = build_precommit(validator, peer, &block_hash, 0, height);
        submit_precommit(precommit).expect("precommit");
    }

    thread::sleep(Duration::from_millis(150));

    shutdown().expect("shutdown");
    let final_state = handle.join().expect("join");

    assert_eq!(final_state.block_height, 1);
    assert!(final_state.pending_rewards.len() >= 1);
    assert!(final_state.pending_proofs.len() >= 1);
}

#[test]
fn detects_conflicting_prevotes_triggers_slash() {
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

    let config = ConsensusConfig::new(60, 60, 10, 0.1);
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

    thread::sleep(Duration::from_millis(20));

    let validator_set = select_validators(0, &vrf_outputs, &ledger);
    let leader = select_leader(&validator_set).expect("leader");
    let conflicting = validator_set
        .validators
        .iter()
        .find(|validator| validator.id == "validator-1")
        .expect("validator-1 present")
        .clone();

    let mut peers: HashMap<_, _> = HashMap::new();
    for validator in &validator_set.validators {
        peers.insert(validator.id.clone(), PeerId::random());
    }

    let proposal_a = Proposal {
        block: Block {
            height: 1,
            epoch: 0,
            payload: serde_json::json!({"tx": [1]}),
            timestamp: 10,
        },
        proof: build_consensus_proof("double-a"),
        leader_id: leader.id.clone(),
    };

    let proposal_b = Proposal {
        block: Block {
            height: 1,
            epoch: 0,
            payload: serde_json::json!({"tx": [2]}),
            timestamp: 20,
        },
        proof: build_consensus_proof("double-b"),
        leader_id: leader.id.clone(),
    };

    submit_proposal(proposal_a.clone()).expect("proposal a");
    submit_proposal(proposal_b.clone()).expect("proposal b");

    thread::sleep(Duration::from_millis(25));

    let peer = peers.get(&conflicting.id).expect("peer id");
    let height = proposal_a.block.height;
    let hash_a = proposal_a.block_hash();
    let hash_b = proposal_b.block_hash();

    let prevote_a = build_prevote(&conflicting, peer, &hash_a, 0, height, true);
    submit_prevote(prevote_a).expect("prevote a");

    thread::sleep(Duration::from_millis(10));

    let prevote_b = build_prevote(&conflicting, peer, &hash_b, 0, height, true);
    submit_prevote(prevote_b).expect("prevote b");

    thread::sleep(Duration::from_millis(80));

    shutdown().expect("shutdown");
    let final_state = handle.join().expect("join");

    let evidence = final_state
        .pending_evidence
        .iter()
        .find(|record| {
            record.accused == conflicting.id
                && matches!(record.evidence, EvidenceType::DoubleSign { .. })
        })
        .expect("double-sign evidence recorded");

    if let EvidenceType::DoubleSign {
        height: evidence_height,
    } = evidence.evidence
    {
        assert_eq!(evidence_height, 1);
    }

    let punished = final_state
        .validator_set
        .validators
        .iter()
        .find(|validator| validator.id == conflicting.id)
        .expect("validator still present");

    assert_eq!(
        punished.timetoken_balance,
        conflicting.timetoken_balance - 1
    );
    assert_eq!(punished.reputation_tier, conflicting.reputation_tier - 1);
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
        proof: build_consensus_proof("manual"),
        leader_id: leader.id.clone(),
    };
    let manual_hash = manual_proposal.block_hash();

    submit_proposal(manual_proposal.clone()).expect("manual proposal");
    thread::sleep(Duration::from_millis(10));

    let leader_peer = PeerId::random();
    let height = manual_proposal.block.height;
    let prevote = build_prevote(&leader, &leader_peer, &manual_hash, 0, height, true);
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
fn consensus_proof_rejects_tampered_commitment() {
    let mut proof = build_consensus_proof("tamper");
    proof.commitments[0].push('x');

    assert_eq!(
        proof.verify(),
        Err(ProofVerificationError::InvalidAggregationSignature)
    );
}

#[test]
fn consensus_proof_rejects_tampered_signature() {
    let mut proof = build_consensus_proof("tamper-sig");
    proof.aggregated_signature[0] ^= 0xFF;

    assert_eq!(
        proof.verify(),
        Err(ProofVerificationError::InvalidAggregationSignature)
    );
}

#[test]
fn consensus_proof_rejects_tampered_hmac() {
    let mut proof = build_consensus_proof("tamper-mac");
    proof.hmac[0] ^= 0xFF;

    assert_eq!(proof.verify(), Err(ProofVerificationError::InvalidMac));
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

#[test]
fn validator_weight_saturates_for_extreme_stake() {
    let mut validator = Validator {
        id: "validator-heavy".into(),
        reputation_tier: u8::MAX,
        reputation_score: 10_000_000.0,
        stake: 0,
        timetoken_balance: u64::MAX,
        vrf_output: [0; 32],
        weight: 0,
    };

    validator.update_weight(StakeInfo::new(u64::MAX));
    assert_eq!(validator.weight, u64::MAX);
}

#[test]
fn validator_weight_handles_zero_stake() {
    let mut validator = Validator {
        id: "validator-zero".into(),
        reputation_tier: 3,
        reputation_score: 1.5,
        stake: 0,
        timetoken_balance: 500_000,
        vrf_output: [0; 32],
        weight: 0,
    };

    validator.update_weight(StakeInfo::new(0));
    assert_eq!(validator.weight, 0);
}

#[test]
fn validator_weight_reputation_edge_behaviour() {
    let mut validator = Validator {
        id: "validator-edge".into(),
        reputation_tier: 0,
        reputation_score: 0.0,
        stake: 0,
        timetoken_balance: 0,
        vrf_output: [0; 32],
        weight: 0,
    };

    validator.update_weight(StakeInfo::new(5));
    let baseline = validator.weight;
    assert_eq!(baseline, 500);

    validator.reputation_score = 0.999;
    validator.update_weight(StakeInfo::new(5));
    assert!(validator.weight >= baseline);

    validator.reputation_tier = 1;
    validator.reputation_score = 1.0;
    validator.update_weight(StakeInfo::new(5));
    assert!(validator.weight > baseline);
}
