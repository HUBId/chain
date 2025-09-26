use std::cmp::Ordering;
use std::collections::BTreeMap;
use std::convert::TryFrom;

use parking_lot::RwLock;
use stwo::core::vcs::blake2_hash::Blake2sHasher;

use crate::errors::{ChainError, ChainResult};
use crate::reputation::{ReputationParams, Tier, TimetokeParams};
use crate::rpp::{AssetType, UtxoOutpoint, UtxoRecord};
use crate::state::merkle::compute_merkle_root;
use crate::types::{Account, AccountId, Address};

#[derive(Clone, Debug)]
pub struct StoredUtxo {
    pub owner: AccountId,
    pub amount: u64,
    pub spent: bool,
}

impl StoredUtxo {
    fn new(owner: AccountId, amount: u64) -> Self {
        Self {
            owner,
            amount,
            spent: false,
        }
    }
}

#[derive(Clone, Debug)]
struct AccountProfile {
    tier: Tier,
    reputation_score: f64,
    timetoke_hours: u64,
}

impl From<&Account> for AccountProfile {
    fn from(account: &Account) -> Self {
        Self {
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

#[derive(Clone, Debug)]
pub struct StoredUtxo {
    pub record: UtxoRecord,
}

impl StoredUtxo {
    pub fn new(record: UtxoRecord) -> Self {
        Self { record }
    }
}

#[derive(Default)]
pub struct UtxoState {
    entries: RwLock<BTreeMap<UtxoOutpoint, StoredUtxo>>,
    account_profiles: RwLock<BTreeMap<Address, AccountProfile>>,
    policy: BlueprintTransferPolicy,
}

impl UtxoState {
    pub fn new() -> Self {
        Self::with_policy(BlueprintTransferPolicy::blueprint_default())
    }

    pub fn with_policy(policy: BlueprintTransferPolicy) -> Self {
        Self {
            entries: RwLock::new(BTreeMap::new()),
            account_profiles: RwLock::new(BTreeMap::new()),
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
        let mut entries = self.entries.write();
        let existing_tx_id = entries
            .iter()
            .find(|(outpoint, stored)| stored.owner == account.address && outpoint.index == 0)
            .map(|(outpoint, _)| outpoint.tx_id);
        let tx_id = tx_id.or(existing_tx_id).unwrap_or([0u8; 32]);

        entries.retain(|_, stored| stored.owner != account.address);

        let aggregated_outpoint = make_outpoint(tx_id, 0);
        entries.insert(
            aggregated_outpoint,
            StoredUtxo::new(account.address.clone(), to_amount(account.balance)),
        );

        for (index, value) in self
            .policy
            .fragment_values(account.balance)
            .into_iter()
            .enumerate()
        {
            let fragment_index = u32::try_from(index + 1).unwrap_or(u32::MAX);
            let outpoint = make_outpoint(tx_id, fragment_index);
            entries.insert(
                outpoint,
                StoredUtxo::new(account.address.clone(), to_amount(value)),
            );
        }
        drop(entries);

        let mut profiles = self.account_profiles.write();
        profiles.insert(account.address.clone(), AccountProfile::from(account));
    }

    pub fn get_for_account(&self, address: &Address) -> Option<UtxoRecord> {
        self.entries
            .read()
            .iter()
            .find(|(outpoint, stored)| {
                stored.owner == *address && outpoint.index == 0 && !stored.spent
            })
            .map(|(outpoint, stored)| stored_to_record(outpoint, stored))
    }

    pub fn fragments_for_account(&self, address: &Address) -> Vec<UtxoRecord> {
        let entries = self.entries.read();
        entries
            .iter()
            .filter(|(outpoint, stored)| {
                stored.owner == *address && outpoint.index > 0 && !stored.spent
            })
            .map(|(outpoint, stored)| stored_to_record(outpoint, stored))
            .collect()
    }

    pub fn unspent_outputs_for_owner(&self, owner: &Address) -> Vec<UtxoRecord> {
        let entries = self.entries.read();
        let mut outputs: Vec<UtxoRecord> = entries
            .iter()
            .filter(|(outpoint, stored)| {
                stored.owner == *owner && outpoint.index > 0 && !stored.spent
            })
            .map(|(outpoint, stored)| stored_to_record(outpoint, stored))
            .collect();
        outputs.sort_by(|a, b| a.outpoint.cmp(&b.outpoint));
        outputs
    }

    pub fn select_inputs_for_owner(
        &self,
        owner: &Address,
        target: u128,
        policy: &BlueprintTransferPolicy,
    ) -> ChainResult<Vec<UtxoRecord>> {
        let profiles = self.account_profiles.read();
        let profile = profiles.get(owner).ok_or_else(|| {
            ChainError::Transaction("wallet inputs unavailable for requested owner".into())
        })?;
        if profile.tier < policy.min_tier {
            return Err(ChainError::Transaction(
                "owner tier below blueprint requirement".into(),
            ));
        }
        if profile.reputation_score < policy.min_score {
            return Err(ChainError::Transaction(
                "owner reputation score below blueprint requirement".into(),
            ));
        }
        if profile.timetoke_hours < policy.min_timetoke_hours {
            return Err(ChainError::Transaction(
                "owner timetoke hours below blueprint requirement".into(),
            ));
        }
        drop(profiles);

        let entries = self.entries.read();
        let mut fragments: Vec<UtxoRecord> = entries
            .iter()
            .filter(|(outpoint, stored)| {
                stored.owner == *owner && outpoint.index > 0 && !stored.spent
            })
            .map(|(outpoint, stored)| stored_to_record(outpoint, stored))
            .collect();
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
        let entries = self.entries.read();
        let profiles = self.account_profiles.read();
        profiles
            .iter()
            .filter(|(_, profile)| profile.tier >= min_tier)
            .filter_map(|(owner, _)| aggregated_for_owner(&entries, owner))
            .collect()
    }

    pub fn owners_by_reputation(&self, min_score: f64) -> Vec<UtxoRecord> {
        let entries = self.entries.read();
        let profiles = self.account_profiles.read();
        profiles
            .iter()
            .filter(|(_, profile)| profile.reputation_score >= min_score)
            .filter_map(|(owner, _)| aggregated_for_owner(&entries, owner))
            .collect()
    }

    pub fn insert(&self, stored: StoredUtxo) {
        let record = stored.record.clone();
        let mut entries = self.entries.write();
        entries.insert(
            record.outpoint.clone(),
            StoredUtxo::new(record.owner.clone(), to_amount(record.value)),
        );
        drop(entries);

        let mut profiles = self.account_profiles.write();
        profiles
            .entry(record.owner.clone())
            .or_insert(AccountProfile {
                tier: Tier::Tl0,
                reputation_score: 0.0,
                timetoke_hours: 0,
            });
    }

    pub fn remove_spent(&self, outpoint: &UtxoOutpoint) -> bool {
        self.remove(outpoint).is_some()
    }

    pub fn remove(&self, outpoint: &UtxoOutpoint) -> Option<UtxoRecord> {
        let mut entries = self.entries.write();
        let removed = entries.remove(outpoint)?;
        let owner = removed.owner.clone();
        if outpoint.index == 0 {
            entries.retain(|_, stored| stored.owner != owner);
        }
        drop(entries);

        if outpoint.index == 0 {
            self.account_profiles.write().remove(&owner);
        }

        Some(stored_to_record(outpoint, &removed))
    }

    pub fn get(&self, outpoint: &UtxoOutpoint) -> Option<UtxoRecord> {
        self.entries
            .read()
            .get(outpoint)
            .map(|stored| stored_to_record(outpoint, stored))
    }

    pub fn snapshot(&self) -> Vec<UtxoRecord> {
        self.entries
            .read()
            .iter()
            .filter(|(outpoint, stored)| outpoint.index == 0 && !stored.spent)
            .map(|(outpoint, stored)| stored_to_record(outpoint, stored))
            .collect()
    }

    pub fn commitment(&self) -> [u8; 32] {
        let mut leaves: Vec<[u8; 32]> = self
            .entries
            .read()
            .iter()
            .filter(|(outpoint, stored)| outpoint.index == 0 && !stored.spent)
            .map(|(outpoint, stored)| {
                let record = stored_to_record(outpoint, stored);
                let payload = serde_json::to_vec(&record).expect("serialize utxo record");
                Blake2sHasher::hash(&payload).into()
            })
            .collect();
        compute_merkle_root(&mut leaves)
    }
}

fn to_amount(value: u128) -> u64 {
    value.min(u64::MAX as u128) as u64
}

fn stored_to_record(outpoint: &UtxoOutpoint, stored: &StoredUtxo) -> UtxoRecord {
    build_record(
        &stored.owner,
        stored.amount as u128,
        outpoint.clone(),
        outpoint.index,
    )
}

fn aggregated_for_owner(
    entries: &BTreeMap<UtxoOutpoint, StoredUtxo>,
    owner: &Address,
) -> Option<UtxoRecord> {
    entries
        .iter()
        .find(|(outpoint, stored)| stored.owner == *owner && outpoint.index == 0 && !stored.spent)
        .map(|(outpoint, stored)| stored_to_record(outpoint, stored))
}

fn make_outpoint(tx_id: [u8; 32], index: u32) -> UtxoOutpoint {
    UtxoOutpoint { tx_id, index }
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
