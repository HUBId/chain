use std::collections::BTreeMap;
use std::sync::Arc;

use rpp_chain::consensus::evidence::{EvidenceRecord, EvidenceType};
use rpp_chain::consensus::state::{ConsensusConfig, ConsensusState, GenesisConfig};
use rpp_chain::consensus::validator::{VRFOutput, ValidatorLedgerEntry};
use rpp_chain::consensus::proof_backend::{
    BackendError, BackendResult, ConsensusCircuitDef, ProofBackend, ProofBytes, VerifyingKey,
};

#[derive(Default)]
struct FixtureBackend;

impl ProofBackend for FixtureBackend {
    fn name(&self) -> &'static str {
        "fixture-consensus"
    }

    fn verify_consensus(
        &self,
        vk: &VerifyingKey,
        proof: &ProofBytes,
        circuit: &ConsensusCircuitDef,
    ) -> BackendResult<()> {
        if vk.as_slice().is_empty() || proof.as_slice().is_empty() {
            return Err(BackendError::Failure("empty consensus artifacts".into()));
        }
        if circuit.identifier.trim().is_empty() {
            return Err(BackendError::Failure("empty circuit identifier".into()));
        }
        Ok(())
    }
}

fn consensus_backend() -> Arc<dyn ProofBackend> {
    Arc::new(FixtureBackend::default())
}

fn sample_vrf_output(id: &str, output_byte: u8, tier: u8, score: f64, timetoken: u64) -> VRFOutput {
    VRFOutput {
        validator_id: id.to_string(),
        output: [output_byte; 32],
        proof: vec![output_byte; 32],
        reputation_tier: tier,
        reputation_score: score,
        timetoken_balance: timetoken,
        seed: [output_byte; 32],
        public_key: format!("pk-{id}").into_bytes(),
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

#[test]
fn witness_rewards_and_slashing_follow_blueprint() {
    let vrf_outputs = vec![
        sample_vrf_output("validator-a", 1, 4, 1.2, 10),
        sample_vrf_output("validator-b", 2, 3, 1.1, 10),
    ];
    let ledger = build_ledger(&[("validator-a", 10, 4, 1.2), ("validator-b", 8, 3, 1.1)]);
    let config = ConsensusConfig::new(50, 50, 10, 0.1).with_witness_params(4, 3, 2);
    let genesis = GenesisConfig::new(0, vrf_outputs, ledger, "root".into(), config.clone());
    let mut state = ConsensusState::new(genesis, consensus_backend()).expect("state init");

    let accused = "validator-a".to_string();
    let reporter = "witness-1".to_string();
    let initial = state
        .validator_set
        .get(&accused)
        .cloned()
        .expect("validator present");

    let false_proof = EvidenceRecord {
        reporter: reporter.clone(),
        accused: accused.clone(),
        evidence: EvidenceType::FalseProof {
            block_hash: "deadbeef".into(),
        },
    };
    state.record_evidence(false_proof);

    assert_eq!(
        state.witness_reward_balance(&reporter),
        config.witness_reward
    );
    let after_false = state
        .validator_set
        .get(&accused)
        .cloned()
        .expect("validator after false proof");
    assert_eq!(
        after_false.timetoken_balance,
        initial
            .timetoken_balance
            .saturating_sub(config.false_proof_penalty),
    );
    assert_eq!(
        after_false.reputation_tier,
        initial.reputation_tier.saturating_sub(1),
    );

    let censorship = EvidenceRecord {
        reporter: reporter.clone(),
        accused: accused.clone(),
        evidence: EvidenceType::VoteWithholding { round: 7 },
    };
    state.record_evidence(censorship);

    let final_validator = state
        .validator_set
        .get(&accused)
        .cloned()
        .expect("validator after censorship");
    assert_eq!(state.pending_evidence.len(), 2);
    assert_eq!(
        state.witness_reward_balance(&reporter),
        config.witness_reward * 2,
    );
    assert_eq!(
        final_validator.timetoken_balance,
        initial
            .timetoken_balance
            .saturating_sub(config.false_proof_penalty + config.censorship_penalty),
    );
    assert_eq!(
        final_validator.reputation_tier,
        initial.reputation_tier.saturating_sub(2),
    );
}
