use std::collections::BTreeMap;
use std::sync::Arc;

use blake3::Hasher;
use proptest::prelude::*;
use tokio::sync::mpsc::unbounded_channel;

use rpp_consensus::evidence::{slash, submit_evidence, EvidenceRecord, EvidenceType};
use rpp_consensus::proof_backend::{
    BackendError, BackendResult, ConsensusCircuitDef, ConsensusPublicInputs, ProofBackend,
    ProofBytes, ProofHeader, ProofSystemKind, VerifyingKey, WitnessBytes,
};
use rpp_consensus::rewards::distribute_rewards;
use rpp_consensus::state::{
    register_message_sender, ConsensusConfig, ConsensusState, GenesisConfig, TreasuryAccounts,
    WitnessPoolWeights,
};
use rpp_consensus::validator::{
    VRFOutput, Validator, ValidatorId, ValidatorLedgerEntry, ValidatorSet,
};

use rpp_crypto_vrf::{derive_tier_seed, generate_vrf, PoseidonVrfInput, VrfKeypair, VrfSecretKey};

#[derive(Clone, Debug)]
struct ValidatorFixture {
    id: String,
    stake: u64,
    reputation_tier: u8,
    reputation_score: f64,
    timetoken_balance: u64,
}

impl ValidatorFixture {
    fn ledger_entry(&self) -> (ValidatorId, ValidatorLedgerEntry) {
        (
            self.id.clone(),
            ValidatorLedgerEntry {
                stake: self.stake,
                reputation_tier: self.reputation_tier,
                reputation_score: self.reputation_score,
            },
        )
    }
}

fn arb_validator_fixtures() -> impl Strategy<Value = Vec<ValidatorFixture>> {
    prop::collection::btree_set(
        (
            0u32..1_000_000,
            1u64..=1_000_000,
            3u8..=5u8,
            any::<f64>(),
            0u64..=2_000_000,
        ),
        1..5,
    )
    .prop_map(|set| {
        set.into_iter()
            .enumerate()
            .map(|(offset, (idx, stake, tier, raw_score, timetoken))| {
                let mut score = raw_score.abs();
                if !score.is_finite() || score == 0.0 {
                    score = 1.0;
                }
                if score > 10_000.0 {
                    score = 10_000.0;
                }
                ValidatorFixture {
                    id: format!("0x{:08x}{:08x}", idx, offset as u32),
                    stake,
                    reputation_tier: tier,
                    reputation_score: score,
                    timetoken_balance: timetoken,
                }
            })
            .collect::<Vec<_>>()
    })
}

fn arb_evidence_record() -> impl Strategy<Value = EvidenceRecord> {
    (
        arb_validator_id(),
        arb_validator_id(),
        any::<u64>(),
        any::<u64>(),
        prop::sample::select(vec![
            EvidenceType::DoubleSign { height: 0 },
            EvidenceType::FalseProof {
                block_hash: String::from("deadbeef"),
            },
            EvidenceType::VoteWithholding { round: 0 },
        ]),
    )
        .prop_map(
            |(reporter, accused, height, round, template)| match template {
                EvidenceType::DoubleSign { .. } => EvidenceRecord {
                    reporter,
                    accused,
                    evidence: EvidenceType::DoubleSign { height },
                },
                EvidenceType::FalseProof { .. } => EvidenceRecord {
                    reporter,
                    accused,
                    evidence: EvidenceType::FalseProof {
                        block_hash: format!("{:x}", height ^ round),
                    },
                },
                EvidenceType::VoteWithholding { .. } => EvidenceRecord {
                    reporter,
                    accused,
                    evidence: EvidenceType::VoteWithholding { round },
                },
            },
        )
}

fn arb_validator_id() -> impl Strategy<Value = ValidatorId> {
    any::<u64>().prop_map(|value| format!("0x{:040x}", value))
}

fn sample_seed(id: &str) -> [u8; 32] {
    let mut seed = [0u8; 32];
    let bytes = id.as_bytes();
    let len = bytes.len().min(32);
    seed[..len].copy_from_slice(&bytes[..len]);
    seed
}

fn deterministic_keypair(id: &str) -> VrfKeypair {
    let mut hash = Hasher::new();
    hash.update(id.as_bytes());
    let mut bytes = hash.finalize().as_bytes().to_vec();
    bytes.resize(32, 0);
    let mut tweak = 0u8;
    loop {
        let mut candidate = [0u8; 32];
        candidate.copy_from_slice(&bytes);
        candidate[0] ^= tweak;
        if let Ok(secret) = VrfSecretKey::try_from(candidate) {
            let public = secret.derive_public();
            return VrfKeypair { public, secret };
        }
        tweak = tweak.wrapping_add(1);
        if tweak == 0 {
            panic!("failed to derive deterministic VRF keypair");
        }
    }
}

fn build_vrf_output(epoch: u64, fixture: &ValidatorFixture) -> VRFOutput {
    let seed = sample_seed(&fixture.id);
    let tier_seed = derive_tier_seed(&fixture.id, fixture.timetoken_balance);
    let keypair = deterministic_keypair(&fixture.id);
    let input = PoseidonVrfInput::new(seed, epoch, tier_seed);
    let vrf_output = generate_vrf(&input, &keypair.secret).expect("generate vrf output");
    VRFOutput {
        validator_id: fixture.id.clone(),
        output: vrf_output.randomness,
        preoutput: vrf_output.preoutput.to_vec(),
        proof: vrf_output.proof.to_vec(),
        reputation_tier: fixture.reputation_tier,
        reputation_score: fixture.reputation_score,
        timetoken_balance: fixture.timetoken_balance,
        seed,
        public_key: keypair.public.to_bytes().to_vec(),
    }
}

fn build_validator_set(fixtures: &[ValidatorFixture]) -> ValidatorSet {
    let validators: Vec<Validator> = fixtures
        .iter()
        .map(|fixture| Validator {
            id: fixture.id.clone(),
            reputation_tier: fixture.reputation_tier,
            reputation_score: fixture.reputation_score,
            stake: fixture.stake,
            timetoken_balance: fixture.timetoken_balance,
            vrf_output: sample_seed(&fixture.id),
            weight: 0,
        })
        .collect();
    ValidatorSet::new(validators)
}

#[derive(Clone, Default)]
struct ProptestBackend;

impl ProofBackend for ProptestBackend {
    fn name(&self) -> &'static str {
        "consensus-proptest"
    }

    fn verify_consensus(
        &self,
        vk: &VerifyingKey,
        proof: &ProofBytes,
        circuit: &ConsensusCircuitDef,
        _public_inputs: &ConsensusPublicInputs,
    ) -> BackendResult<()> {
        if vk.as_slice().is_empty() {
            return Err(BackendError::Failure("verifying key empty".into()));
        }
        if proof.as_slice().is_empty() {
            return Err(BackendError::Failure("proof bytes empty".into()));
        }
        if circuit.identifier.trim().is_empty() {
            return Err(BackendError::Failure("circuit identifier empty".into()));
        }
        Ok(())
    }

    fn prove_consensus(
        &self,
        witness: &WitnessBytes,
    ) -> BackendResult<(ProofBytes, VerifyingKey, ConsensusCircuitDef)> {
        let digest = blake3::hash(witness.as_slice());
        let identifier = format!("proptest.consensus.{}", digest.to_hex());
        let circuit = ConsensusCircuitDef::new(identifier.clone());
        let header = ProofHeader::new(ProofSystemKind::Mock, identifier.clone());
        let proof = ProofBytes::encode(&header, witness.as_slice())?;
        let verifying_key = VerifyingKey(identifier.into_bytes());
        Ok((proof, verifying_key, circuit))
    }
}

fn build_consensus_state(
    epoch: u64,
    fixtures: &[ValidatorFixture],
    base_reward: u64,
    leader_bonus: f64,
) -> ConsensusState {
    let config = ConsensusConfig::new(1_000, 2_000, base_reward, leader_bonus);
    let validator_outputs: Vec<VRFOutput> = fixtures
        .iter()
        .map(|fixture| build_vrf_output(epoch, fixture))
        .collect();
    let ledger: BTreeMap<ValidatorId, ValidatorLedgerEntry> = fixtures
        .iter()
        .map(|fixture| fixture.ledger_entry())
        .collect();
    let genesis = GenesisConfig::new(
        epoch,
        validator_outputs,
        ledger,
        format!("reputation-root-{epoch}"),
        config,
    );
    ConsensusState::new(genesis, Arc::new(ProptestBackend)).expect("state initialization")
}

proptest! {
    #[test]
    fn reward_distribution_totals(
        fixtures in arb_validator_fixtures(),
        base_reward in 1u64..=1_000,
        leader_bonus in 0.0f64..=2.0,
        leader_selector in any::<usize>(),
    ) {
        let validator_set = build_validator_set(&fixtures);
        let count = validator_set.validators.len();
        let leader_index = leader_selector % count;
        let leader = validator_set.validators[leader_index].clone();
        let accounts = TreasuryAccounts::new(
            "treasury-validator".into(),
            "treasury-witness".into(),
            "treasury-fees".into(),
        );
        let weights = WitnessPoolWeights::new(0.7, 0.3);
        let distribution = distribute_rewards(
            &validator_set,
            &leader,
            42,
            base_reward,
            leader_bonus,
            &accounts,
            &weights,
        );

        let leader_extra = ((base_reward as f64) * leader_bonus).round() as u64;
        let expected_total = base_reward * count as u64 + leader_extra;
        prop_assert_eq!(distribution.total_reward, expected_total);
        prop_assert_eq!(distribution.leader_bonus, leader_extra);

        let sum_rewards: u64 = distribution.rewards.values().copied().sum();
        prop_assert_eq!(sum_rewards, expected_total);

        let leader_reward = distribution.reward_for(&leader.id);
        prop_assert_eq!(leader_reward, base_reward + leader_extra);

        for validator in &validator_set.validators {
            let reward = distribution.reward_for(&validator.id);
            if validator.id == leader.id {
                prop_assert!(reward >= base_reward);
            } else {
                prop_assert_eq!(reward, base_reward);
            }
        }

        prop_assert!(distribution.witness_rewards.is_empty());
    }
}

proptest! {
    #[test]
    fn submit_evidence_sends_message(record in arb_evidence_record()) {
        let (tx, mut rx) = unbounded_channel();
        register_message_sender(Some(tx));
        submit_evidence(record.clone()).expect("evidence submission succeeds");
        let received = rx.try_recv().expect("message delivered");
        let expected = format!("{:?}", record);
        let actual = format!("{:?}", received);
        prop_assert!(actual.contains(&expected));
    }
}

proptest! {
    #[test]
    fn slash_determinism(
        fixtures in arb_validator_fixtures(),
        epoch in 0u64..1_000,
        base_reward in 1u64..=1_000,
        leader_bonus in 0.0f64..=2.0,
        slash_amount in 0u64..=5_000_000,
        selector in any::<usize>(),
    ) {
        let mut state = build_consensus_state(epoch, &fixtures, base_reward, leader_bonus);
        let mut mirror = build_consensus_state(epoch, &fixtures, base_reward, leader_bonus);

        let validator_ids: Vec<_> = fixtures.iter().map(|fixture| fixture.id.clone()).collect();
        let target_index = selector % validator_ids.len();
        let target_id = &validator_ids[target_index];
        let original = fixtures.iter().find(|fixture| &fixture.id == target_id).unwrap();
        let amount = slash_amount;

        slash(target_id, amount, &mut state);
        slash(target_id, amount, &mut mirror);

        let expected_balance = original
            .timetoken_balance
            .saturating_sub(amount);
        let expected_tier = original.reputation_tier.saturating_sub(1);

        let validator = state
            .validator_set
            .get(target_id)
            .expect("validator present");
        prop_assert_eq!(validator.timetoken_balance, expected_balance);
        prop_assert_eq!(validator.reputation_tier, expected_tier);
        prop_assert!((validator.reputation_score - original.reputation_score).abs() < f64::EPSILON);

        let total_power: u64 = state
            .validator_set
            .validators
            .iter()
            .map(|v| v.voting_power())
            .sum();
        prop_assert_eq!(state.validator_set.total_voting_power, total_power);

        let quorum = (total_power * 2) / 3 + 1;
        prop_assert_eq!(state.validator_set.quorum_threshold, quorum);

        let pairs: Vec<_> = state
            .validator_set
            .validators
            .iter()
            .zip(mirror.validator_set.validators.iter())
            .collect();
        for (left, right) in pairs {
            prop_assert_eq!(left.id, right.id);
            prop_assert_eq!(left.timetoken_balance, right.timetoken_balance);
            prop_assert_eq!(left.reputation_tier, right.reputation_tier);
            prop_assert_eq!(left.reputation_score, right.reputation_score);
            prop_assert_eq!(left.voting_power(), right.voting_power());
        }
    }
}
