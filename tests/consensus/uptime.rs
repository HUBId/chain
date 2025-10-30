use std::collections::BTreeMap;
use std::sync::Arc;

use blake3::Hasher;
use rpp_consensus::proof_backend::{
    BackendError, BackendResult, ConsensusCircuitDef, ConsensusPublicInputs, ProofBackend, ProofBytes,
    VerifyingKey,
};
use rpp_consensus::reputation::{MalachiteReputationManager, UptimeObservation};
use rpp_consensus::state::{ConsensusConfig, ConsensusState, GenesisConfig};
use rpp_consensus::validator::{VRFOutput, ValidatorLedgerEntry};

#[derive(Default)]
struct FixtureBackend;

impl ProofBackend for FixtureBackend {
    fn name(&self) -> &'static str {
        "uptime-fixture"
    }

    fn verify_consensus(
        &self,
        vk: &VerifyingKey,
        proof: &ProofBytes,
        circuit: &ConsensusCircuitDef,
        _public_inputs: &ConsensusPublicInputs,
    ) -> BackendResult<()> {
        if vk.as_slice().is_empty() || proof.as_slice().is_empty() {
            return Err(BackendError::Failure("empty consensus artifacts".into()));
        }
        if circuit.identifier.trim().is_empty() {
            return Err(BackendError::Failure("empty circuit identifier".into()));
        }
        Ok(())
    }

    fn prove_consensus(
        &self,
        witness: &prover_backend_interface::WitnessBytes,
    ) -> BackendResult<(ProofBytes, VerifyingKey, ConsensusCircuitDef)> {
        let mut hasher = Hasher::new();
        hasher.update(witness.as_slice());
        let digest = hasher.finalize();
        let identifier = format!("uptime.consensus.{}", digest.to_hex());
        let circuit = ConsensusCircuitDef::new(identifier.clone());
        let header = prover_backend_interface::ProofHeader::new(
            prover_backend_interface::ProofSystemKind::Mock,
            identifier.clone(),
        );
        let proof = ProofBytes::encode(&header, witness.as_slice())?;
        let verifying_key = VerifyingKey(identifier.into_bytes());
        Ok((proof, verifying_key, circuit))
    }
}

fn consensus_backend() -> Arc<dyn ProofBackend> {
    Arc::new(FixtureBackend::default())
}

fn sample_vrf_output(id: &str, output_byte: u8, tier: u8, score: f64, timetoken: u64) -> VRFOutput {
    VRFOutput {
        validator_id: id.to_string(),
        output: [output_byte; 32],
        preoutput: vec![output_byte; 32],
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
fn uptime_manager_credits_observations() {
    let validator = "validator-a".to_string();
    let ledger = build_ledger(&[(validator.as_str(), 10, 3, 0.4)]);
    let mut manager = MalachiteReputationManager::new(ledger);

    let outcome = manager.ingest_observation(UptimeObservation::new(
        validator.clone(),
        0,
        6 * 3_600,
    ));

    assert_eq!(outcome.credited_hours, Some(6));
    assert!(outcome.slashing_trigger.is_none());

    let credited = manager.uptime_hours_of(&validator).expect("hours tracked");
    assert_eq!(credited, 72 + 6);

    let ledger_entry = manager
        .ledger()
        .get(&validator)
        .expect("ledger entry present");
    let expected_score = (credited as f64) / 720.0;
    assert!((ledger_entry.reputation_score - expected_score).abs() < 1e-9);
}

#[test]
fn uptime_manager_rejects_overlapping_windows() {
    let validator = "validator-b".to_string();
    let ledger = build_ledger(&[(validator.as_str(), 15, 2, 0.2)]);
    let mut manager = MalachiteReputationManager::new(ledger);

    let first = manager.ingest_observation(UptimeObservation::new(
        validator.clone(),
        0,
        3_600,
    ));
    assert_eq!(first.credited_hours, Some(1));
    assert!(first.slashing_trigger.is_none());

    let second = manager.ingest_observation(UptimeObservation::new(
        validator.clone(),
        1_800,
        5_400,
    ));
    assert!(second.slashing_trigger.is_some());

    let triggers = manager.take_slashing_triggers();
    assert_eq!(triggers.len(), 1);
    assert_eq!(triggers[0].validator, validator);
}

#[test]
fn consensus_state_applies_uptime_observations() {
    let validator = "validator-c".to_string();
    let vrf_outputs = vec![sample_vrf_output(&validator, 7, 3, 0.4, 10)];
    let ledger = build_ledger(&[(validator.as_str(), 20, 3, 0.4)]);
    let config = ConsensusConfig::new(50, 50, 10, 0.1);
    let genesis = GenesisConfig::new(0, vrf_outputs, ledger, "root".into(), config);
    let backend = consensus_backend();
    let mut state = ConsensusState::new(genesis, backend).expect("state init");

    let outcome = state.ingest_uptime_observation(UptimeObservation::new(
        validator.clone(),
        0,
        12 * 3_600,
    ));

    assert_eq!(outcome.credited_hours, Some(12));
    assert!(outcome.slashing_trigger.is_none());

    let validator_entry = state
        .validator_set
        .get(&validator)
        .expect("validator exists");
    assert_eq!(
        validator_entry.reputation_score,
        outcome.new_score.expect("score updated"),
    );
    assert!(state.validator_set.total_voting_power > 0);
    assert!(state.take_slashing_triggers().is_empty());
}

#[test]
fn consensus_state_tracks_slashing_triggers() {
    let validator = "validator-d".to_string();
    let vrf_outputs = vec![sample_vrf_output(&validator, 11, 4, 0.6, 18)];
    let ledger = build_ledger(&[(validator.as_str(), 30, 4, 0.6)]);
    let config = ConsensusConfig::new(50, 50, 10, 0.1);
    let genesis = GenesisConfig::new(0, vrf_outputs, ledger, "root".into(), config);
    let backend = consensus_backend();
    let mut state = ConsensusState::new(genesis, backend).expect("state init");

    let first = state.ingest_uptime_observation(UptimeObservation::new(
        validator.clone(),
        0,
        3_600,
    ));
    assert_eq!(first.credited_hours, Some(1));

    let second = state.ingest_uptime_observation(UptimeObservation::new(
        validator.clone(),
        1_800,
        5_400,
    ));
    assert!(second.slashing_trigger.is_some());

    let triggers = state.take_slashing_triggers();
    assert_eq!(triggers.len(), 1);
    assert_eq!(triggers[0].validator, validator);
}
