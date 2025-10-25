use std::collections::BTreeSet;

use blake3::Hasher;
use malachite::Natural;
use malachite::base::num::arithmetic::traits::DivRem;
use proptest::prelude::*;

use rpp_chain::consensus::{ConsensusRound, ObserverProfile, ValidatorCandidate};
use rpp_chain::reputation::Tier;
use rpp_chain::types::Stake;
use rpp_chain::vrf::{
    self, PoseidonVrfInput, VrfKeypair, VrfProof, VrfSecretKey, VrfSubmission, VrfSubmissionPool,
};

#[derive(Clone, Debug)]
struct CandidateFixture {
    address: String,
    stake: u128,
    reputation_score: f64,
    tier: Tier,
    timetoke_hours: u64,
}

fn arb_candidate_fixtures() -> impl Strategy<Value = Vec<CandidateFixture>> {
    prop::collection::btree_set(
        (
            0u32..500_000,
            1u128..=1_000_000,
            prop::sample::select(vec![Tier::Tl3, Tier::Tl4, Tier::Tl5]),
            any::<f64>(),
            0u64..=(24 * 30),
        ),
        1..5,
    )
    .prop_map(|set| {
        set.into_iter()
            .enumerate()
            .map(|(offset, (idx, stake, tier, raw_score, timetoke_hours))| {
                let mut score = raw_score.abs();
                if !score.is_finite() || score == 0.0 {
                    score = 1.0;
                }
                if score > 10_000.0 {
                    score = 10_000.0;
                }
                CandidateFixture {
                    address: format!("0x{:08x}{:08x}", idx, offset as u32),
                    stake,
                    reputation_score: score,
                    tier,
                    timetoke_hours,
                }
            })
            .collect::<Vec<_>>()
    })
}

fn arb_observers() -> impl Strategy<Value = Vec<ObserverProfile>> {
    prop::collection::vec(
        (
            0u32..250_000,
            prop::sample::select(vec![Tier::Tl1, Tier::Tl2]),
        ),
        0..3,
    )
    .prop_map(|entries| {
        entries
            .into_iter()
            .enumerate()
            .map(|(offset, (idx, tier))| ObserverProfile {
                address: format!("0xobs{:06x}{:06x}", idx, offset as u32),
                tier,
            })
            .collect()
    })
}

#[derive(Clone, Debug)]
struct RoundInput {
    height: u64,
    round: u64,
    seed: [u8; 32],
    target: usize,
    candidates: Vec<ValidatorCandidate>,
    observers: Vec<ObserverProfile>,
    pool: VrfSubmissionPool,
}

fn arb_round_input() -> impl Strategy<Value = RoundInput> {
    (
        0u64..1_000,
        0u64..1_000,
        prop::array::uniform32(any::<u8>()),
        arb_candidate_fixtures(),
        arb_observers(),
        0u64..1_000,
        1usize..5,
    )
        .prop_map(
            |(height, round, seed, fixtures, observers, epoch, target_hint)| {
                let target = ((target_hint % (fixtures.len() + 1)).max(1)).min(fixtures.len());
                let candidates: Vec<ValidatorCandidate> = fixtures
                    .iter()
                    .map(|fixture| ValidatorCandidate {
                        address: fixture.address.clone(),
                        stake: Stake::from_u128(fixture.stake),
                        reputation_score: fixture.reputation_score,
                        tier: fixture.tier.clone(),
                        timetoke_hours: fixture.timetoke_hours,
                    })
                    .collect();

                let mut pool = VrfSubmissionPool::new();
                for fixture in fixtures.iter() {
                    let keypair = deterministic_keypair(&fixture.address);
                    let tier_seed = vrf::derive_tier_seed(&fixture.address, fixture.timetoke_hours);
                    let input = PoseidonVrfInput::new(seed, epoch, tier_seed);
                    let output = vrf::generate_vrf(&input, &keypair.secret).expect("generate vrf");
                    let proof = VrfProof::from_output(&output);
                    let submission = VrfSubmission {
                        address: fixture.address.clone(),
                        public_key: Some(keypair.public.clone()),
                        input,
                        proof,
                        tier: fixture.tier.clone(),
                        timetoke_hours: fixture.timetoke_hours,
                    };
                    pool.insert(submission);
                }

                RoundInput {
                    height,
                    round,
                    seed,
                    target,
                    candidates,
                    observers,
                    pool,
                }
            },
        )
}

fn deterministic_keypair(address: &str) -> VrfKeypair {
    let mut hash = Hasher::new();
    hash.update(address.as_bytes());
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

fn expected_quorum(total: &Natural) -> Natural {
    if *total == Natural::from(0u32) {
        return Natural::from(0u32);
    }
    let numerator = total.clone() * Natural::from(2u32);
    let denominator = Natural::from(3u32);
    let (mut threshold, remainder) = numerator.div_rem(&denominator);
    if remainder > Natural::from(0u32) {
        threshold += Natural::from(1u32);
    }
    threshold += Natural::from(1u32);
    threshold
}

proptest! {
    #[test]
    fn quorum_threshold_matches_total(input in arb_round_input()) {
        let round = ConsensusRound::new(
            input.height,
            input.round,
            input.seed,
            input.target,
            input.candidates.clone(),
            input.observers.clone(),
            &input.pool,
        );

        let total_from_profiles = input
            .candidates
            .iter()
            .filter_map(|candidate| {
                round.validators().iter().find(|profile| profile.address == candidate.address)
            })
            .fold(Natural::from(0u32), |acc, profile| acc + profile.voting_power());

        prop_assert_eq!(round.total_power(), &total_from_profiles);
        prop_assert_eq!(round.quorum_threshold(), &expected_quorum(round.total_power()));
    }
}

proptest! {
    #[test]
    fn validator_selection_matches_vrf(input in arb_round_input()) {
        let selection = vrf::select_validators(&input.pool, input.target);
        let round = ConsensusRound::new(
            input.height,
            input.round,
            input.seed,
            input.target,
            input.candidates.clone(),
            input.observers.clone(),
            &input.pool,
        );

        let candidate_addresses: BTreeSet<_> = input
            .candidates
            .iter()
            .map(|candidate| candidate.address.clone())
            .collect();

        let mut expected = BTreeSet::new();
        for submission in selection.validators.iter() {
            if submission.verified && candidate_addresses.contains(&submission.address) {
                expected.insert(submission.address.clone());
            }
        }

        if expected.is_empty() {
            if let Some(fallback) = selection.fallback.clone() {
                if fallback.submission.verified
                    && candidate_addresses.contains(&fallback.submission.address)
                {
                    expected.insert(fallback.submission.address.clone());
                }
            }
        }

        let actual: BTreeSet<_> = round
            .validators()
            .iter()
            .map(|profile| profile.address.clone())
            .collect();

        prop_assert_eq!(actual, expected);
    }
}
