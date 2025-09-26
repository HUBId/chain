use std::collections::BTreeMap;

use parking_lot::RwLock;
use stwo::core::vcs::blake2_hash::Blake2sHasher;

use crate::rpp::{UtxoOutpoint, UtxoRecord};
use crate::state::merkle::compute_merkle_root;
use crate::types::Address;

#[derive(Clone, Debug)]
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

    pub fn mark_spent(&mut self) -> bool {
        if self.spent {
            false
        } else {
            self.spent = true;
            true
        }
    }
}

impl From<UtxoRecord> for StoredUtxo {
    fn from(record: UtxoRecord) -> Self {
        Self::new(record)
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

    pub fn insert(&self, outpoint: UtxoOutpoint, utxo: StoredUtxo) {
        let mut entries = self.entries.write();
        entries.insert(outpoint, utxo);
    }

    pub fn remove_spent(&self, outpoint: &UtxoOutpoint) -> Option<UtxoRecord> {
        let mut entries = self.entries.write();
        let entry = entries.get_mut(outpoint)?;
        if entry.mark_spent() {
            Some(entry.record.clone())
        } else {
            None
        }
    }

    pub fn get(&self, outpoint: &UtxoOutpoint) -> Option<UtxoRecord> {
        self.entries
            .read()
            .get(outpoint)
            .and_then(|entry| (!entry.spent).then(|| entry.record.clone()))
    }

    pub fn get_for_account(&self, account: &Address) -> Vec<UtxoRecord> {
        self.entries
            .read()
            .values()
            .filter(|entry| !entry.spent && &entry.record.owner == account)
            .map(|entry| entry.record.clone())
            .collect()
    }

    pub fn snapshot(&self) -> Vec<UtxoRecord> {
        self.entries
            .read()
            .values()
            .filter(|entry| !entry.spent)
            .map(|entry| entry.record.clone())
            .collect()
    }

    pub fn commitment(&self) -> [u8; 32] {
        let mut leaves: Vec<[u8; 32]> = self
            .entries
            .read()
            .values()
            .filter(|entry| !entry.spent)
            .map(|entry| {
                let payload = serde_json::to_vec(&entry.record)
                    .expect("serialize utxo record for commitment");
                Blake2sHasher::hash(&payload).into()
            })
            .collect();
        compute_merkle_root(&mut leaves)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rpp::AssetType;

    fn sample_outpoint(index: u32) -> UtxoOutpoint {
        UtxoOutpoint {
            tx_id: [index as u8; 32],
            index,
        }
    }

    fn sample_record(owner: &str, value: u128, index: u32) -> UtxoRecord {
        UtxoRecord {
            outpoint: sample_outpoint(index),
            owner: owner.to_string(),
            value,
            asset_type: AssetType::Native,
            script_hash: [index as u8; 32],
            timelock: None,
        }
    }

    #[test]
    fn remove_marks_spent_and_keeps_record() {
        let state = UtxoState::new();
        let record = sample_record("owner", 42, 0);
        let outpoint = record.outpoint.clone();
        state.insert(outpoint.clone(), record.clone().into());

        let removed = state.remove_spent(&outpoint).expect("utxo removed");
        assert_eq!(removed.outpoint, record.outpoint);
        assert_eq!(removed.owner, record.owner);
        assert_eq!(removed.value, record.value);
        assert!(state.get(&outpoint).is_none());

        // second removal should yield None but retain entry for history
        assert!(state.remove_spent(&outpoint).is_none());
    }

    #[test]
    fn get_for_account_filters_spent_entries() {
        let state = UtxoState::new();
        let first = sample_record("alice", 10, 0);
        let second = sample_record("alice", 20, 1);
        let third = sample_record("bob", 5, 2);
        state.insert(first.outpoint.clone(), first.clone().into());
        state.insert(second.outpoint.clone(), second.clone().into());
        state.insert(third.outpoint.clone(), third.clone().into());

        state.remove_spent(&first.outpoint);
        let utxos = state.get_for_account(&"alice".to_string());
        assert_eq!(utxos.len(), 1);
        assert_eq!(utxos[0].outpoint, second.outpoint);
        assert_eq!(utxos[0].value, second.value);
    }

    #[test]
    fn snapshot_only_includes_unspent() {
        let state = UtxoState::new();
        let first = sample_record("alice", 10, 0);
        let second = sample_record("bob", 5, 1);
        state.insert(first.outpoint.clone(), first.clone().into());
        state.insert(second.outpoint.clone(), second.clone().into());
        state.remove_spent(&first.outpoint);

        let snapshot = state.snapshot();
        assert_eq!(snapshot.len(), 1);
        assert_eq!(snapshot[0].outpoint, second.outpoint);
        assert_eq!(snapshot[0].value, second.value);
    }
}
