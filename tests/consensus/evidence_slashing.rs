use std::collections::BTreeMap;
use std::sync::Arc;

use rpp_consensus::evidence::{EvidenceKind, EvidencePipeline, EvidenceRecord, EvidenceType};
use rpp_consensus::proof_backend::{
    BackendError, BackendResult, ConsensusCircuitDef, ConsensusPublicInputs, ProofBackend,
    ProofBytes, VerifyingKey,
};
use rpp_consensus::reputation::{SlashingKind, UptimeObservation};
use rpp_consensus::state::{ConsensusConfig, ConsensusState, GenesisConfig};
use rpp_consensus::validator::{VRFOutput, ValidatorLedgerEntry};

#[derive(Default)]
struct FixtureBackend;

impl ProofBackend for FixtureBackend {
    fn name(&self) -> &'static str {
        "slashing-fixture"
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
        let digest = blake3::hash(witness.as_slice());
        let identifier = format!("slashing.consensus.{}", digest.to_hex());
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

fn build_state() -> ConsensusState {
    let vrf_outputs = vec![
        sample_vrf_output("validator-a", 1, 4, 1.0, 10),
        sample_vrf_output("validator-b", 2, 3, 0.8, 8),
    ];
    let ledger = build_ledger(&[("validator-a", 10, 4, 1.0), ("validator-b", 8, 3, 0.8)]);
    let config = ConsensusConfig::new(40, 40, 10, 0.1).with_witness_params(4, 3, 2);
    let genesis = GenesisConfig::new(0, vrf_outputs, ledger, "root".into(), config);
    ConsensusState::new(genesis, consensus_backend()).expect("consensus state")
}

#[test]
fn evidence_pipeline_orders_records_by_priority() {
    let reporter = "reporter".to_string();
    let accused = "validator".to_string();

    let mut pipeline = EvidencePipeline::default();
    pipeline.push(EvidenceRecord {
        reporter: reporter.clone(),
        accused: accused.clone(),
        evidence: EvidenceType::VoteWithholding { round: 3 },
    });
    pipeline.push(EvidenceRecord {
        reporter: reporter.clone(),
        accused: accused.clone(),
        evidence: EvidenceType::FalseProof {
            block_hash: "0xabc".into(),
        },
    });
    pipeline.push(EvidenceRecord {
        reporter: reporter.clone(),
        accused: accused.clone(),
        evidence: EvidenceType::DoubleSign { height: 7 },
    });

    assert_eq!(pipeline.len(), 3);
    assert_eq!(pipeline.counts(), (1, 1, 1));

    let kinds: Vec<EvidenceKind> = pipeline
        .iter()
        .map(|record| record.evidence.kind())
        .collect();
    assert_eq!(
        kinds,
        vec![
            EvidenceKind::DoubleSign,
            EvidenceKind::Availability,
            EvidenceKind::Witness,
        ]
    );

    let drained: Vec<EvidenceKind> = pipeline
        .drain()
        .into_iter()
        .map(|record| record.evidence.kind())
        .collect();
    assert_eq!(
        drained,
        vec![
            EvidenceKind::DoubleSign,
            EvidenceKind::Availability,
            EvidenceKind::Witness,
        ]
    );
}

#[test]
fn consensus_state_updates_slashing_heuristics_and_pipeline() {
    let mut state = build_state();
    let accused = "validator-a".to_string();
    let reporter = "witness-1".to_string();

    // enqueue in reverse priority order to assert prioritisation
    let witness = EvidenceRecord {
        reporter: reporter.clone(),
        accused: accused.clone(),
        evidence: EvidenceType::VoteWithholding { round: 11 },
    };
    let availability = EvidenceRecord {
        reporter: reporter.clone(),
        accused: accused.clone(),
        evidence: EvidenceType::FalseProof {
            block_hash: "0xdeadbeef".into(),
        },
    };
    let double_sign = EvidenceRecord {
        reporter: reporter.clone(),
        accused: accused.clone(),
        evidence: EvidenceType::DoubleSign { height: 5 },
    };

    state.record_evidence(witness);
    state.record_evidence(availability);
    state.record_evidence(double_sign);

    let ordered: Vec<EvidenceKind> = state
        .pending_evidence
        .iter()
        .map(|record| record.evidence.kind())
        .collect();
    assert_eq!(
        ordered,
        vec![
            EvidenceKind::DoubleSign,
            EvidenceKind::Availability,
            EvidenceKind::Witness,
        ]
    );

    let snapshot = state.slashing_heuristics.snapshot();
    assert_eq!(snapshot.double_signs, 1);
    assert_eq!(snapshot.availability_failures, 1);
    assert_eq!(snapshot.witness_reports, 1);

    // uptime observation overlap triggers an additional witness slashing event
    let validator = accused.clone();
    let first =
        state.ingest_uptime_observation(UptimeObservation::new(validator.clone(), 0, 3_600));
    assert!(first.slashing_trigger.is_none());

    let second =
        state.ingest_uptime_observation(UptimeObservation::new(validator.clone(), 1_800, 4_200));
    assert!(second.slashing_trigger.is_some());

    let updated = state.slashing_heuristics.snapshot();
    assert_eq!(updated.double_signs, 1);
    assert_eq!(updated.availability_failures, 1);
    assert_eq!(updated.witness_reports, 2);

    let recent_kinds: Vec<SlashingKind> = state
        .slashing_heuristics
        .drain_recent()
        .into_iter()
        .map(|event| event.kind())
        .collect();
    assert_eq!(recent_kinds.len(), 4);
    assert_eq!(recent_kinds[0], SlashingKind::DoubleSign);
    assert_eq!(recent_kinds[1], SlashingKind::Availability);
    assert_eq!(recent_kinds[2], SlashingKind::Witness);
    assert_eq!(recent_kinds[3], SlashingKind::Witness);
}
