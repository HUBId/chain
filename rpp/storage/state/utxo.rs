use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use stwo::core::vcs::blake2_hash::Blake2sHasher;
use tokio::sync::RwLock;

use crate::rpp::{AssetType, UtxoOutpoint, UtxoRecord};
use crate::state::merkle::compute_merkle_root;
use crate::types::{Account, Address};

/// Stored representation of a UTXO tracked by the ledger state.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StoredUtxo {
    pub owner: Address,
    pub amount: u128,
    pub spent: bool,
}

impl StoredUtxo {
    pub fn new(owner: Address, amount: u128) -> Self {
        Self {
            owner,
            amount,
            spent: false,
        }
    }

    pub fn mark_spent(&mut self) {
        self.spent = true;
    }

    pub fn is_spent(&self) -> bool {
        self.spent
    }

    pub fn to_record(&self, outpoint: &UtxoOutpoint) -> UtxoRecord {
        let mut script_seed = self.owner.as_bytes().to_vec();
        script_seed.extend_from_slice(&outpoint.index.to_be_bytes());
        let script_hash: [u8; 32] = Blake2sHasher::hash(&script_seed).into();
        UtxoRecord {
            outpoint: outpoint.clone(),
            owner: self.owner.clone(),
            value: self.amount,
            asset_type: AssetType::Native,
            script_hash,
            timelock: None,
        }
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
    pub fn insert(&self, outpoint: UtxoOutpoint, stored: StoredUtxo) {
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
            .map(|stored| stored.to_record(outpoint))
    }

    fn canonical_entry_for_account(&self, address: &Address) -> Option<(UtxoOutpoint, StoredUtxo)> {
        self.entries
            .blocking_read()
            .iter()
            .filter(|(_, stored)| stored.owner == *address && !stored.is_spent())
            .min_by(|(left_outpoint, _), (right_outpoint, _)| {
                left_outpoint
                    .index
                    .cmp(&right_outpoint.index)
                    .then_with(|| left_outpoint.cmp(right_outpoint))
            })
            .map(|(outpoint, stored)| (outpoint.clone(), stored.clone()))
    }

    /// Return the canonical UTXO associated with the provided account.
    pub fn get_for_account(&self, address: &Address) -> Option<UtxoRecord> {
        self.canonical_entry_for_account(address)
            .map(|(outpoint, stored)| stored.to_record(&outpoint))
    }

    /// Snapshot the canonical UTXO and its outpoint for the provided account.
    pub fn snapshot_for_account(&self, address: &Address) -> Option<(UtxoOutpoint, StoredUtxo)> {
        self.canonical_entry_for_account(address)
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
            .find(|(outpoint, stored)| stored.owner == account.address && outpoint.index == 0)
            .map(|(outpoint, _)| outpoint.tx_id);
        let tx_id = tx_id.or(existing_tx_id).unwrap_or([0u8; 32]);

        entries.retain(|_, stored| stored.owner != account.address);

        let aggregated_outpoint = UtxoOutpoint { tx_id, index: 0 };
        let stored = StoredUtxo::new(account.address.clone(), account.balance);
        entries.insert(aggregated_outpoint, stored);
    }

    pub fn unspent_outputs_for_owner(&self, owner: &Address) -> Vec<UtxoRecord> {
        let mut outputs: Vec<UtxoRecord> = self
            .entries
            .blocking_read()
            .iter()
            .filter(|(_, stored)| stored.owner == *owner && !stored.is_spent())
            .map(|(outpoint, stored)| stored.to_record(outpoint))
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::Stake;
    use std::collections::BTreeMap;

    fn sample_account(address: &str, balance: u128) -> Account {
        Account::new(address.to_string(), balance, Stake::default())
    }

    #[test]
    fn insert_and_get_round_trip() {
        let state = UtxoState::new();
        let outpoint = UtxoOutpoint {
            tx_id: [1u8; 32],
            index: 0,
        };
        state.insert(outpoint.clone(), StoredUtxo::new("alice".to_string(), 42));
        let fetched = state.get(&outpoint).expect("utxo fetched");
        assert_eq!(fetched.outpoint, outpoint);
        assert_eq!(fetched.owner, "alice");
        assert_eq!(fetched.value, 42);
    }

    #[test]
    fn remove_spent_marks_entry() {
        let state = UtxoState::new();
        let outpoint = UtxoOutpoint {
            tx_id: [2u8; 32],
            index: 0,
        };
        state.insert(outpoint.clone(), StoredUtxo::new("bob".to_string(), 7));
        assert!(state.remove_spent(&outpoint));
        assert!(state.get(&outpoint).is_none());
        let snapshot = state.snapshot();
        let stored = snapshot.get(&outpoint).expect("entry exists in snapshot");
        assert!(stored.is_spent());
    }

    #[test]
    fn get_for_account_prefers_lowest_index() {
        let state = UtxoState::new();
        let first_outpoint = UtxoOutpoint {
            tx_id: [3u8; 32],
            index: 1,
        };
        let second_outpoint = UtxoOutpoint {
            tx_id: [4u8; 32],
            index: 0,
        };
        state.insert(
            first_outpoint.clone(),
            StoredUtxo::new("carol".to_string(), 10),
        );
        state.insert(
            second_outpoint.clone(),
            StoredUtxo::new("carol".to_string(), 20),
        );
        let fetched = state
            .get_for_account(&"carol".to_string())
            .expect("carol utxo");
        assert_eq!(fetched.outpoint, second_outpoint);
        assert_eq!(fetched.value, 20);
        let inputs = state.select_inputs_for_owner(&"carol".to_string());
        assert_eq!(inputs.len(), 1);
        assert_eq!(inputs[0].0, second_outpoint);
        assert_eq!(inputs[0].1.amount, 20);
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
        state.insert(outpoint.clone(), StoredUtxo::new("eve".to_string(), 55));
        assert!(state.remove_spent(&outpoint));
        let snapshot = state.snapshot();
        assert_eq!(snapshot.len(), 1);
        let stored = snapshot.get(&outpoint).expect("stored utxo");
        assert!(stored.is_spent());
    }

    #[test]
    fn multiple_outputs_per_account_are_sorted_and_serializable() {
        let state = UtxoState::new();
        let owner = "frank".to_string();
        let first_outpoint = UtxoOutpoint {
            tx_id: [9u8; 32],
            index: 2,
        };
        let second_outpoint = UtxoOutpoint {
            tx_id: [8u8; 32],
            index: 1,
        };
        state.insert(first_outpoint.clone(), StoredUtxo::new(owner.clone(), 30));
        state.insert(second_outpoint.clone(), StoredUtxo::new(owner.clone(), 45));
        let outputs = state.unspent_outputs_for_owner(&owner);
        assert_eq!(outputs.len(), 2);
        assert_eq!(outputs[0].outpoint, second_outpoint);
        assert_eq!(outputs[0].value, 45);
        assert_eq!(outputs[1].outpoint, first_outpoint);
        assert_eq!(outputs[1].value, 30);

        let snapshot = state.snapshot();
        let snapshot_pairs: Vec<(UtxoOutpoint, StoredUtxo)> = snapshot
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        let encoded = serde_json::to_string(&snapshot_pairs).expect("serialize snapshot");
        let decoded: Vec<(UtxoOutpoint, StoredUtxo)> =
            serde_json::from_str(&encoded).expect("deserialize snapshot");
        assert_eq!(decoded.len(), snapshot_pairs.len());
        let decoded_map: BTreeMap<UtxoOutpoint, StoredUtxo> = decoded.into_iter().collect();
        let decoded_first = decoded_map.get(&second_outpoint).expect("decoded entry");
        assert_eq!(decoded_first.owner, owner);
        assert_eq!(decoded_first.amount, 45);
        assert!(!decoded_first.is_spent());
    }

    #[test]
    fn spent_flag_flips_and_resets_on_replacement() {
        let state = UtxoState::new();
        let outpoint = UtxoOutpoint {
            tx_id: [10u8; 32],
            index: 4,
        };
        state.insert(outpoint.clone(), StoredUtxo::new("ginny".to_string(), 12));
        assert!(state.remove_spent(&outpoint));
        let snapshot = state.snapshot();
        assert!(snapshot.get(&outpoint).expect("snapshot entry").is_spent());
        assert!(!state.remove_spent(&outpoint));
        state.insert(outpoint.clone(), StoredUtxo::new("ginny".to_string(), 21));
        let refreshed = state.get(&outpoint).expect("reinserted utxo");
        assert_eq!(refreshed.value, 21);
        assert_eq!(refreshed.owner, "ginny");
    }

    #[test]
    fn commitment_changes_are_deterministic_across_sequences() {
        let state_a = UtxoState::new();
        let state_b = UtxoState::new();
        let owner = "harry".to_string();
        let first_outpoint = UtxoOutpoint {
            tx_id: [11u8; 32],
            index: 0,
        };
        let second_outpoint = UtxoOutpoint {
            tx_id: [12u8; 32],
            index: 5,
        };

        state_a.insert(first_outpoint.clone(), StoredUtxo::new(owner.clone(), 40));
        state_a.insert(second_outpoint.clone(), StoredUtxo::new(owner.clone(), 25));
        assert!(state_a.remove_spent(&second_outpoint));
        state_a.insert(second_outpoint.clone(), StoredUtxo::new(owner.clone(), 26));

        state_b.insert(second_outpoint.clone(), StoredUtxo::new(owner.clone(), 25));
        state_b.insert(first_outpoint.clone(), StoredUtxo::new(owner.clone(), 40));
        assert!(state_b.remove_spent(&second_outpoint));
        state_b.insert(second_outpoint.clone(), StoredUtxo::new(owner.clone(), 26));

        let commitment_a = state_a.commitment();
        let commitment_b = state_b.commitment();
        assert_eq!(commitment_a, commitment_b);

        let snapshot = state_a.snapshot();
        let bytes = bincode::serialize(&snapshot).expect("serialize snapshot");
        let restored: BTreeMap<UtxoOutpoint, StoredUtxo> =
            bincode::deserialize(&bytes).expect("deserialize snapshot");
        assert_eq!(restored.len(), snapshot.len());
        let mirror = UtxoState::new();
        for (outpoint, stored) in restored.iter() {
            mirror.insert(outpoint.clone(), stored.clone());
        }
        assert_eq!(mirror.commitment(), commitment_a);
    }
}
