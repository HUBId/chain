use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use stwo::core::vcs::blake2_hash::Blake2sHasher;
use tokio::sync::RwLock;

use crate::rpp::{AssetType, UtxoOutpoint, UtxoRecord};
use crate::state::merkle::compute_merkle_root;
use crate::types::{Account, Address};

/// Wrapper around a [`UtxoRecord`] that is stored inside the ledger state.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StoredUtxo {
    pub record: UtxoRecord,
    pub spent: bool,
}

impl StoredUtxo {
    pub fn new(record: UtxoRecord) -> Self {
        Self {
            record,
            spent: false,
        }
    }

    pub fn mark_spent(&mut self) {
        self.spent = true;
    }

    pub fn is_spent(&self) -> bool {
        self.spent
    }
}

#[derive(Default)]
pub struct UtxoState {
    entries: RwLock<BTreeMap<UtxoOutpoint, StoredUtxo>>,
}

impl UtxoState {
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert or replace a UTXO inside the state.
    pub fn insert(&self, stored: StoredUtxo) {
        let outpoint = stored.record.outpoint.clone();
        self.entries.blocking_write().insert(outpoint, stored);
    }

    /// Remove a spent UTXO. Returns `true` if an entry was removed.
    pub fn remove_spent(&self, outpoint: &UtxoOutpoint) -> bool {
        let mut entries = self.entries.blocking_write();
        match entries.get_mut(outpoint) {
            Some(stored) if !stored.is_spent() => {
                stored.mark_spent();
                true
            }
            _ => false,
        }
    }

    /// Fetch a UTXO by its outpoint.
    pub fn get(&self, outpoint: &UtxoOutpoint) -> Option<UtxoRecord> {
        self.entries
            .blocking_read()
            .get(outpoint)
            .filter(|stored| !stored.is_spent())
            .map(|stored| stored.record.clone())
    }

    fn canonical_entry_for_account(&self, address: &Address) -> Option<(UtxoOutpoint, StoredUtxo)> {
        self.entries
            .blocking_read()
            .iter()
            .filter(|(_, stored)| stored.record.owner == *address && !stored.is_spent())
            .min_by(
                |(left_outpoint, left_stored), (right_outpoint, right_stored)| {
                    left_stored
                        .record
                        .outpoint
                        .index
                        .cmp(&right_stored.record.outpoint.index)
                        .then_with(|| left_outpoint.cmp(right_outpoint))
                },
            )
            .map(|(outpoint, stored)| (outpoint.clone(), stored.clone()))
    }

    /// Return the canonical UTXO associated with the provided account.
    pub fn get_for_account(&self, address: &Address) -> Option<UtxoRecord> {
        self.canonical_entry_for_account(address)
            .map(|(_, stored)| stored.record)
    }

    /// Select deterministic inputs for the provided owner.
    pub fn select_inputs_for_owner(&self, owner: &Address) -> Vec<(UtxoOutpoint, StoredUtxo)> {
        self.canonical_entry_for_account(owner)
            .into_iter()
            .collect()
    }

    pub fn upsert_from_account(&self, account: &Account) {
        self.upsert_from_account_with_tx(account, None);
    }

    pub fn upsert_with_transaction(&self, account: &Account, tx_id: [u8; 32]) {
        self.upsert_from_account_with_tx(account, Some(tx_id));
    }

    fn upsert_from_account_with_tx(&self, account: &Account, tx_id: Option<[u8; 32]>) {
        let mut entries = self.entries.blocking_write();
        let existing_tx_id = entries
            .iter()
            .find(|(outpoint, stored)| {
                stored.record.owner == account.address && outpoint.index == 0
            })
            .map(|(outpoint, _)| outpoint.tx_id);
        let tx_id = tx_id.or(existing_tx_id).unwrap_or([0u8; 32]);

        entries.retain(|_, stored| stored.record.owner != account.address);

        let aggregated_outpoint = UtxoOutpoint { tx_id, index: 0 };
        let record = build_record(
            &account.address,
            account.balance,
            aggregated_outpoint.clone(),
            aggregated_outpoint.index,
        );
        entries.insert(aggregated_outpoint, StoredUtxo::new(record));
    }

    pub fn unspent_outputs_for_owner(&self, owner: &Address) -> Vec<UtxoRecord> {
        let mut outputs: Vec<UtxoRecord> = self
            .entries
            .blocking_read()
            .iter()
            .filter(|(_, stored)| stored.record.owner == *owner && !stored.is_spent())
            .map(|(_, stored)| stored.record.clone())
            .collect();
        outputs.sort_by(|a, b| a.outpoint.cmp(&b.outpoint));
        outputs
    }

    pub fn snapshot(&self) -> BTreeMap<UtxoOutpoint, StoredUtxo> {
        self.entries.blocking_read().clone()
    }

    pub fn commitment(&self) -> [u8; 32] {
        let mut leaves: Vec<[u8; 32]> = self
            .entries
            .blocking_read()
            .iter()
            .filter(|(_, stored)| !stored.is_spent())
            .map(|(outpoint, stored)| {
                let payload = bincode::serialize(&(outpoint.clone(), stored.clone()))
                    .expect("serialize utxo snapshot entry");
                Blake2sHasher::hash(&payload).into()
            })
            .collect();
        compute_merkle_root(&mut leaves)
    }
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
    use crate::types::Stake;

    fn sample_account(address: &str, balance: u128) -> Account {
        Account::new(address.to_string(), balance, Stake::default())
    }

    fn sample_record(owner: &str, tx_id: [u8; 32], index: u32, value: u128) -> UtxoRecord {
        UtxoRecord {
            outpoint: UtxoOutpoint { tx_id, index },
            owner: owner.to_string(),
            value,
            asset_type: AssetType::Native,
            script_hash: [index as u8; 32],
            timelock: None,
        }
    }

    #[test]
    fn insert_and_get_round_trip() {
        let state = UtxoState::new();
        let outpoint = UtxoOutpoint {
            tx_id: [1u8; 32],
            index: 0,
        };
        let record = sample_record("alice", outpoint.tx_id, outpoint.index, 42);
        state.insert(StoredUtxo::new(record.clone()));
        let fetched = state.get(&outpoint).expect("utxo fetched");
        assert_eq!(fetched.outpoint, record.outpoint);
        assert_eq!(fetched.owner, record.owner);
        assert_eq!(fetched.value, record.value);
    }

    #[test]
    fn remove_spent_marks_entry() {
        let state = UtxoState::new();
        let outpoint = UtxoOutpoint {
            tx_id: [2u8; 32],
            index: 0,
        };
        let record = sample_record("bob", outpoint.tx_id, outpoint.index, 7);
        state.insert(StoredUtxo::new(record));
        assert!(state.remove_spent(&outpoint));
        assert!(state.get(&outpoint).is_none());
        let snapshot = state.snapshot();
        let stored = snapshot.get(&outpoint).expect("entry exists in snapshot");
        assert!(stored.is_spent());
    }

    #[test]
    fn get_for_account_prefers_lowest_index() {
        let state = UtxoState::new();
        let first = sample_record("carol", [3u8; 32], 1, 10);
        let second = sample_record("carol", [4u8; 32], 0, 20);
        state.insert(StoredUtxo::new(first.clone()));
        state.insert(StoredUtxo::new(second.clone()));
        let fetched = state
            .get_for_account(&"carol".to_string())
            .expect("carol utxo");
        assert_eq!(fetched.outpoint, second.outpoint);
        assert_eq!(fetched.value, second.value);
        let inputs = state.select_inputs_for_owner(&"carol".to_string());
        assert_eq!(inputs.len(), 1);
        assert_eq!(inputs[0].0, second.outpoint);
        assert_eq!(inputs[0].1.record.value, second.value);
    }

    #[test]
    fn upsert_from_account_rebuilds_record() {
        let state = UtxoState::new();
        let account = sample_account("dave", 100);
        state.upsert_from_account(&account);
        let record = state
            .get_for_account(&account.address)
            .expect("utxo record");
        assert_eq!(record.owner, account.address);
        assert_eq!(record.value, account.balance);
        assert_eq!(record.outpoint.index, 0);
    }

    #[test]
    fn snapshot_includes_spent_entries() {
        let state = UtxoState::new();
        let outpoint = UtxoOutpoint {
            tx_id: [7u8; 32],
            index: 3,
        };
        let record = sample_record("eve", outpoint.tx_id, outpoint.index, 55);
        state.insert(StoredUtxo::new(record));
        assert!(state.remove_spent(&outpoint));
        let snapshot = state.snapshot();
        assert_eq!(snapshot.len(), 1);
        let stored = snapshot.get(&outpoint).expect("stored utxo");
        assert!(stored.is_spent());
    }
}
