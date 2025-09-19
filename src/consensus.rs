use malachite::Natural;
use serde::{Deserialize, Serialize};
use stwo::core::vcs::blake2_hash::Blake2sHasher;

use crate::types::{Address, Stake};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RppSelection {
    pub proposer: Address,
    pub randomness: Natural,
    pub total_stake: Natural,
}

pub fn aggregate_total_stake(entries: &[(Address, Stake)]) -> Natural {
    entries.iter().fold(Natural::from(0u32), |acc, (_, stake)| {
        acc + stake.as_natural().clone()
    })
}

fn natural_from_bytes(bytes: &[u8]) -> Natural {
    let mut value = Natural::from(0u32);
    for byte in bytes {
        value *= Natural::from(256u32);
        value += Natural::from(*byte);
    }
    value
}

fn randomness_from_seed(seed: &[u8], round: u64) -> Natural {
    let mut data = seed.to_vec();
    data.extend_from_slice(&round.to_le_bytes());
    let hash = Blake2sHasher::hash(&data);
    let hash_bytes: [u8; 32] = hash.into();
    natural_from_bytes(&hash_bytes)
}

pub fn select_proposer(
    entries: &[(Address, Stake)],
    seed: &[u8; 32],
    round: u64,
) -> Option<RppSelection> {
    if entries.is_empty() {
        return None;
    }
    let total = aggregate_total_stake(entries);
    if total == Natural::from(0u32) {
        return None;
    }
    let randomness = randomness_from_seed(seed, round);
    let mut cursor = randomness.clone() % total.clone();
    for (address, stake) in entries {
        let stake_value = stake.as_natural();
        if cursor < *stake_value {
            return Some(RppSelection {
                proposer: address.clone(),
                randomness: randomness.clone(),
                total_stake: total,
            });
        }
        cursor -= stake_value.clone();
    }
    let (address, _) = entries.last().unwrap();
    Some(RppSelection {
        proposer: address.clone(),
        randomness,
        total_stake: total,
    })
}
