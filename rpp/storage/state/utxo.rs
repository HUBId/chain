use std::cmp::Ordering;
use std::collections::BTreeMap;

use parking_lot::RwLock;
use stwo::core::vcs::blake2_hash::Blake2sHasher;

use crate::errors::{ChainError, ChainResult};
use crate::reputation::{ReputationParams, Tier, TimetokeParams};
use crate::rpp::{AssetType, UtxoOutpoint, UtxoRecord};
use crate::state::merkle::compute_merkle_root;
use crate::types::{Account, Address};

#[derive(Clone, Debug)]
struct AccountUtxoEntry {
    aggregated: UtxoRecord,
    fragments: Vec<UtxoRecord>,
    tier: Tier,
    reputation_score: f64,
    timetoke_hours: u64,
}

impl AccountUtxoEntry {
    fn new(aggregated: UtxoRecord, fragments: Vec<UtxoRecord>, account: &Account) -> Self {
        Self {
            aggregated,
            fragments,
            tier: account.reputation.tier.clone(),
            reputation_score: account.reputation.score,
            timetoke_hours: account.reputation.timetokes.hours_online,
        }
    }
}

#[derive(Clone, Debug)]
pub struct BlueprintTransferPolicy {
    pub min_tier: Tier,
    pub min_score: f64,
    pub min_timetoke_hours: u64,
    pub max_inputs: usize,
    pub preferred_fragment_value: u128,
    pub max_fragments_per_account: usize,
}

impl BlueprintTransferPolicy {
    pub fn blueprint_default() -> Self {
        let reputation_params = ReputationParams::default();
        let timetoke_params = TimetokeParams::default();
        Self {
            min_tier: Tier::Tl2,
            min_score: reputation_params.tier_thresholds.tier5_min_score / 3.0,
            min_timetoke_hours: timetoke_params.decay_step_hours.saturating_mul(6),
            max_inputs: 4,
            preferred_fragment_value: 25_000,
            max_fragments_per_account: 8,
        }
    }

    fn fragment_values(&self, balance: u128) -> Vec<u128> {
        if balance == 0 {
            return Vec::new();
        }
        let mut remaining = balance;
        let mut fragments = Vec::new();
        while remaining > 0 && fragments.len() < self.max_fragments_per_account {
            let next = remaining.min(self.preferred_fragment_value);
            fragments.push(next);
            remaining = remaining.saturating_sub(next);
        }
        if remaining > 0 {
            if let Some(last) = fragments.last_mut() {
                *last = last.saturating_add(remaining);
            }
        }
        fragments
    }

    pub fn ensure_account_allowed(&self, account: &Account) -> ChainResult<()> {
        if account.reputation.tier < self.min_tier {
            return Err(ChainError::Transaction(
                "wallet tier insufficient for requested policy".into(),
            ));
        }
        if account.reputation.score < self.min_score {
            return Err(ChainError::Transaction(
                "wallet reputation score below blueprint minimum".into(),
            ));
        }
        if account.reputation.timetokes.hours_online < self.min_timetoke_hours {
            return Err(ChainError::Transaction(
                "wallet timetoke hours below blueprint minimum".into(),
            ));
        }
        Ok(())
    }
}

impl Default for BlueprintTransferPolicy {
    fn default() -> Self {
        Self::blueprint_default()
    }
}

#[derive(Default)]
pub struct UtxoState {
    entries: RwLock<BTreeMap<Address, AccountUtxoEntry>>,
    policy: BlueprintTransferPolicy,
}

impl UtxoState {
    pub fn new() -> Self {
        Self::with_policy(BlueprintTransferPolicy::blueprint_default())
    }

    pub fn with_policy(policy: BlueprintTransferPolicy) -> Self {
        Self {
            entries: RwLock::new(BTreeMap::new()),
            policy,
        }
    }

    pub fn policy(&self) -> BlueprintTransferPolicy {
        self.policy.clone()
    }

    pub fn upsert_from_account(&self, account: &Account) {
        self.upsert_from_account_with_tx(account, None);
    }

    pub fn upsert_with_transaction(&self, account: &Account, tx_id: [u8; 32]) {
        self.upsert_from_account_with_tx(account, Some(tx_id));
    }

    fn upsert_from_account_with_tx(&self, account: &Account, tx_id: Option<[u8; 32]>) {
        let tx_id = tx_id
            .or_else(|| {
                self.entries
                    .read()
                    .get(&account.address)
                    .map(|entry| entry.aggregated.outpoint.tx_id)
            })
            .unwrap_or([0u8; 32]);
        let aggregated = aggregated_record(account, tx_id);
        let fragments = self
            .policy
            .fragment_values(account.balance)
            .into_iter()
            .enumerate()
            .map(|(index, value)| fragment_record(account, tx_id, index as u32, value))
            .collect();
        let entry = AccountUtxoEntry::new(aggregated, fragments, account);
        self.entries.write().insert(account.address.clone(), entry);
    }

    pub fn get_for_account(&self, address: &Address) -> Option<UtxoRecord> {
        self.entries
            .read()
            .get(address)
            .map(|entry| entry.aggregated.clone())
    }

    pub fn fragments_for_account(&self, address: &Address) -> Vec<UtxoRecord> {
        self.entries
            .read()
            .get(address)
            .map(|entry| entry.fragments.clone())
            .unwrap_or_default()
    }

    pub fn select_inputs_for_owner(
        &self,
        owner: &Address,
        target: u128,
        policy: &BlueprintTransferPolicy,
    ) -> ChainResult<Vec<UtxoRecord>> {
        let entries = self.entries.read();
        let entry = entries.get(owner).ok_or_else(|| {
            ChainError::Transaction("wallet inputs unavailable for requested owner".into())
        })?;
        if entry.tier < policy.min_tier {
            return Err(ChainError::Transaction(
                "owner tier below blueprint requirement".into(),
            ));
        }
        if entry.reputation_score < policy.min_score {
            return Err(ChainError::Transaction(
                "owner reputation score below blueprint requirement".into(),
            ));
        }
        if entry.timetoke_hours < policy.min_timetoke_hours {
            return Err(ChainError::Transaction(
                "owner timetoke hours below blueprint requirement".into(),
            ));
        }
        let mut fragments = entry.fragments.clone();
        fragments.sort_by(|a, b| match b.value.cmp(&a.value) {
            Ordering::Equal => a.outpoint.cmp(&b.outpoint),
            other => other,
        });
        let mut selected = Vec::new();
        let mut total = 0u128;
        for fragment in fragments {
            if total >= target {
                break;
            }
            total = total
                .checked_add(fragment.value)
                .ok_or_else(|| ChainError::Transaction("input value overflow".into()))?;
            selected.push(fragment);
            if selected.len() > policy.max_inputs {
                return Err(ChainError::Transaction(
                    "required inputs exceed blueprint maximum".into(),
                ));
            }
        }
        if total < target {
            return Err(ChainError::Transaction(
                "insufficient input liquidity for requested amount".into(),
            ));
        }
        selected.sort_by(|a, b| a.outpoint.cmp(&b.outpoint));
        Ok(selected)
    }

    pub fn owners_by_tier(&self, min_tier: Tier) -> Vec<UtxoRecord> {
        self.entries
            .read()
            .values()
            .filter(|entry| entry.tier >= min_tier)
            .map(|entry| entry.aggregated.clone())
            .collect()
    }

    pub fn owners_by_reputation(&self, min_score: f64) -> Vec<UtxoRecord> {
        self.entries
            .read()
            .values()
            .filter(|entry| entry.reputation_score >= min_score)
            .map(|entry| entry.aggregated.clone())
            .collect()
    }

    pub fn insert(&self, record: UtxoRecord) {
        let mut entries = self.entries.write();
        entries.insert(
            record.owner.clone(),
            AccountUtxoEntry {
                aggregated: record.clone(),
                fragments: vec![record.clone()],
                tier: Tier::Tl0,
                reputation_score: 0.0,
                timetoke_hours: 0,
            },
        );
    }

    pub fn remove(&self, outpoint: &UtxoOutpoint) -> Option<UtxoRecord> {
        let mut entries = self.entries.write();
        let owner = entries
            .iter()
            .find(|(_, entry)| entry.aggregated.outpoint == *outpoint)
            .map(|(owner, _)| owner.clone());
        owner.and_then(|address| entries.remove(&address).map(|entry| entry.aggregated))
    }

    pub fn get(&self, outpoint: &UtxoOutpoint) -> Option<UtxoRecord> {
        self.entries
            .read()
            .values()
            .find(|entry| entry.aggregated.outpoint == *outpoint)
            .map(|entry| entry.aggregated.clone())
    }

    pub fn snapshot(&self) -> Vec<UtxoRecord> {
        self.entries
            .read()
            .values()
            .map(|entry| entry.aggregated.clone())
            .collect()
    }

    pub fn commitment(&self) -> [u8; 32] {
        let mut leaves: Vec<[u8; 32]> = self
            .entries
            .read()
            .values()
            .map(|entry| {
                let payload = serde_json::to_vec(&entry.aggregated).expect("serialize utxo record");
                Blake2sHasher::hash(&payload).into()
            })
            .collect();
        compute_merkle_root(&mut leaves)
    }
}

fn make_outpoint(tx_id: [u8; 32], index: u32) -> UtxoOutpoint {
    UtxoOutpoint { tx_id, index }
}

fn aggregated_record(account: &Account, tx_id: [u8; 32]) -> UtxoRecord {
    let outpoint = make_outpoint(tx_id, 0);
    build_record(&account.address, account.balance, outpoint, 0)
}

fn fragment_record(
    account: &Account,
    tx_id: [u8; 32],
    fragment_index: u32,
    value: u128,
) -> UtxoRecord {
    let index = fragment_index.saturating_add(1);
    let outpoint = make_outpoint(tx_id, index);
    build_record(&account.address, value, outpoint, index)
}

fn build_record(owner: &Address, value: u128, outpoint: UtxoOutpoint, salt: u32) -> UtxoRecord {
    let mut script_seed = owner.as_bytes().to_vec();
    script_seed.extend_from_slice(&salt.to_be_bytes());
    UtxoRecord {
        outpoint,
        owner: owner.clone(),
        value,
        asset_type: AssetType::Native,
        script_hash: Blake2sHasher::hash(&script_seed).into(),
        timelock: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::reputation::{ReputationProfile, TimetokeBalance};
    use crate::types::Stake;

    fn sample_account(address: &str, balance: u128, tier: Tier, score: f64, hours: u64) -> Account {
        let mut account = Account::new(address.to_string(), balance, Stake::default());
        account.reputation = ReputationProfile::new(address);
        account.reputation.tier = tier;
        account.reputation.score = score;
        account.reputation.timetokes = TimetokeBalance {
            hours_online: hours,
            ..TimetokeBalance::default()
        };
        account
    }

    #[test]
    fn policy_blocks_tier_violation() {
        let policy = BlueprintTransferPolicy {
            min_tier: Tier::Tl2,
            min_score: 0.1,
            min_timetoke_hours: 1,
            max_inputs: 4,
            preferred_fragment_value: 10,
            max_fragments_per_account: 4,
        };
        let state = UtxoState::with_policy(policy.clone());
        let account = sample_account("addr-tier", 40, Tier::Tl1, 0.5, 10);
        state.upsert_from_account(&account);
        let result = state.select_inputs_for_owner(&account.address, 20, &policy);
        assert!(matches!(
            result,
            Err(ChainError::Transaction(message)) if message.contains("tier")
        ));
    }

    #[test]
    fn policy_blocks_low_reputation() {
        let policy = BlueprintTransferPolicy {
            min_tier: Tier::Tl1,
            min_score: 0.6,
            min_timetoke_hours: 1,
            max_inputs: 4,
            preferred_fragment_value: 10,
            max_fragments_per_account: 4,
        };
        let state = UtxoState::with_policy(policy.clone());
        let account = sample_account("addr-rep", 40, Tier::Tl3, 0.2, 10);
        state.upsert_from_account(&account);
        let result = state.select_inputs_for_owner(&account.address, 20, &policy);
        assert!(matches!(
            result,
            Err(ChainError::Transaction(message)) if message.contains("reputation")
        ));
    }
}
