use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub type ValidatorId = String;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VRFOutput {
    pub validator_id: ValidatorId,
    pub output: [u8; 32],
    pub proof: Vec<u8>,
    pub reputation_tier: u8,
    pub reputation_score: f64,
    pub timetoken_balance: u64,
    pub seed: [u8; 32],
    pub public_key: Vec<u8>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct ValidatorLedgerEntry {
    pub stake: u64,
    pub reputation_tier: u8,
    pub reputation_score: f64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Validator {
    pub id: ValidatorId,
    pub reputation_tier: u8,
    pub reputation_score: f64,
    pub stake: u64,
    pub timetoken_balance: u64,
    pub vrf_output: [u8; 32],
    pub weight: u64,
}

impl Validator {
    pub fn voting_power(&self) -> u64 {
        self.weight
    }

    pub fn update_weight(&mut self) {
        let tier_multiplier = (self.reputation_tier.max(1) as u64) * 100;
        let score_multiplier = (self.reputation_score * 1000.0).round().max(1.0) as u64;
        let timetoken_bonus = (self.timetoken_balance / 1_000_000).max(1);
        self.weight = tier_multiplier * score_multiplier * timetoken_bonus * self.stake.max(1);
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ValidatorSet {
    pub validators: Vec<Validator>,
    pub total_voting_power: u64,
    pub quorum_threshold: u64,
}

impl ValidatorSet {
    pub fn new(mut validators: Vec<Validator>) -> Self {
        for validator in &mut validators {
            validator.update_weight();
        }
        validators.sort_by(|a, b| a.id.cmp(&b.id));
        let total_voting_power = validators.iter().map(|v| v.voting_power()).sum();
        let quorum_threshold = (total_voting_power * 2) / 3 + 1;
        Self {
            validators,
            total_voting_power,
            quorum_threshold,
        }
    }

    pub fn get(&self, id: &ValidatorId) -> Option<&Validator> {
        self.validators.iter().find(|v| &v.id == id)
    }

    pub fn voting_power(&self, id: &ValidatorId) -> u64 {
        self.get(id).map(|v| v.voting_power()).unwrap_or_default()
    }

    pub fn contains(&self, id: &ValidatorId) -> bool {
        self.get(id).is_some()
    }
}

pub fn select_validators(
    epoch: u64,
    vrf_outputs: &[VRFOutput],
    ledger_entries: &BTreeMap<ValidatorId, ValidatorLedgerEntry>,
) -> ValidatorSet {
    let mut eligible: Vec<Validator> = Vec::new();

    for output in vrf_outputs.iter() {
        let Some(entry) = ledger_entries.get(&output.validator_id) else {
            continue;
        };

        if entry.reputation_tier < 3 {
            continue;
        }

        let input =
            rpp::vrf::PoseidonVrfInput::new(epoch, output.validator_id.clone(), output.seed);
        let public_key = rpp::vrf::VrfPublicKey::new(output.public_key.clone());
        let vrf_output = rpp::vrf::VrfOutput::new(output.output, output.proof.clone());

        if rpp::vrf::verify_vrf(&input, &public_key, &vrf_output).is_err() {
            continue;
        }

        let validator = Validator {
            id: output.validator_id.clone(),
            reputation_tier: entry.reputation_tier,
            reputation_score: entry.reputation_score,
            stake: entry.stake,
            timetoken_balance: output.timetoken_balance,
            vrf_output: output.output,
            weight: 0,
        };
        eligible.push(validator);
    }

    eligible.sort_by(|a, b| a.vrf_output.cmp(&b.vrf_output));
    ValidatorSet::new(eligible)
}

pub fn select_leader(validators: &ValidatorSet) -> Option<Validator> {
    validators.validators.iter().cloned().max_by(|a, b| {
        a.reputation_tier
            .cmp(&b.reputation_tier)
            .then_with(|| a.timetoken_balance.cmp(&b.timetoken_balance))
            .then_with(|| a.vrf_output.cmp(&b.vrf_output))
    })
}

pub fn timetoken_balances(validators: &ValidatorSet) -> BTreeMap<ValidatorId, u64> {
    validators
        .validators
        .iter()
        .map(|v| (v.id.clone(), v.timetoken_balance))
        .collect()
}

pub mod rpp {
    pub mod vrf {
        use blake3::Hasher;

        #[derive(Clone, Debug)]
        pub struct PoseidonVrfInput {
            pub epoch: u64,
            pub validator_id: String,
            pub seed: [u8; 32],
        }

        impl PoseidonVrfInput {
            pub fn new(epoch: u64, validator_id: String, seed: [u8; 32]) -> Self {
                Self {
                    epoch,
                    validator_id,
                    seed,
                }
            }
        }

        #[derive(Clone, Debug)]
        pub struct VrfPublicKey {
            bytes: Vec<u8>,
        }

        impl VrfPublicKey {
            pub fn new(bytes: Vec<u8>) -> Self {
                Self { bytes }
            }

            pub fn as_bytes(&self) -> &[u8] {
                &self.bytes
            }
        }

        #[derive(Clone, Debug)]
        pub struct VrfOutput {
            pub randomness: [u8; 32],
            pub proof: Vec<u8>,
        }

        impl VrfOutput {
            pub fn new(randomness: [u8; 32], proof: Vec<u8>) -> Self {
                Self { randomness, proof }
            }

            pub fn randomness(&self) -> &[u8; 32] {
                &self.randomness
            }
        }

        #[derive(Debug, PartialEq, Eq)]
        pub enum VrfError {
            VerificationFailed,
        }

        pub type VrfResult<T> = Result<T, VrfError>;

        pub fn verify_vrf(
            input: &PoseidonVrfInput,
            public: &VrfPublicKey,
            output: &VrfOutput,
        ) -> VrfResult<()> {
            let mut hasher = Hasher::new();
            hasher.update(&input.seed);
            hasher.update(&input.epoch.to_be_bytes());
            hasher.update(input.validator_id.as_bytes());
            hasher.update(public.as_bytes());
            hasher.update(output.randomness());
            let digest = hasher.finalize();
            if output.proof == digest.as_bytes() {
                Ok(())
            } else {
                Err(VrfError::VerificationFailed)
            }
        }
    }
}
