use std::thread;
use std::time::Duration;

use super::bft_loop::{run_bft_loop, shutdown, submit_prevote, submit_proposal};
use super::messages::{Block, ConsensusProof, PreVote, Proposal};
use super::state::{ConsensusConfig, GenesisConfig};
use super::validator::{select_leader, select_validators, VRFOutput};

#[test]
fn bft_flow_reaches_commit() {
    let vrf_outputs = vec![
        VRFOutput {
            validator_id: "validator-1".into(),
            output: [1; 32],
            proof: vec![],
            reputation_tier: 4,
            reputation_score: 1.5,
            timetoken_balance: 2_000_000,
        },
        VRFOutput {
            validator_id: "validator-2".into(),
            output: [2; 32],
            proof: vec![],
            reputation_tier: 3,
            reputation_score: 1.2,
            timetoken_balance: 1_500_000,
        },
        VRFOutput {
            validator_id: "validator-3".into(),
            output: [3; 32],
            proof: vec![],
            reputation_tier: 3,
            reputation_score: 1.1,
            timetoken_balance: 1_300_000,
        },
    ];

    let config = ConsensusConfig::new(50, 50, 10, 0.1);
    let genesis = GenesisConfig::new(0, vrf_outputs.clone(), "root".into(), config);
    let state = super::state::ConsensusState::new(genesis).expect("state init");

    let handle = thread::spawn(move || {
        let mut state = state;
        run_bft_loop(&mut state);
        state
    });

    thread::sleep(Duration::from_millis(25));

    let validator_set = select_validators(0, &vrf_outputs);
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
