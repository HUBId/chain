use std::collections::BTreeMap;

use crate::proof_backend::Blake2sHasher;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::sync::RwLock;

use crate::rpp::{AssetType, UtxoOutpoint, UtxoRecord};
use crate::state::merkle::compute_merkle_root;
use crate::types::Address;

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
        let script_hash = locking_script_hash(&self.owner, self.amount);
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

#[derive(Serialize)]
enum LedgerScriptPayload<'a> {
    Recipient { to: &'a Address, amount: u128 },
}

fn encode_recipient_script(owner: &Address, amount: u128) -> Vec<u8> {
    serde_json::to_vec(&LedgerScriptPayload::Recipient { to: owner, amount })
        .expect("serialize ledger recipient script")
}

pub fn locking_script_hash(owner: &Address, amount: u128) -> [u8; 32] {
    let script_bytes = encode_recipient_script(owner, amount);
    let mut hasher = Sha256::new();
    hasher.update(&(script_bytes.len() as u32).to_le_bytes());
    hasher.update(&script_bytes);
    hasher.finalize().into()
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

    fn sort_pairs(pairs: &mut Vec<(UtxoOutpoint, StoredUtxo)>) {
        pairs.sort_by(|(left_outpoint, _), (right_outpoint, _)| {
            left_outpoint
                .index
                .cmp(&right_outpoint.index)
                .then_with(|| left_outpoint.cmp(right_outpoint))
        });
    }

    fn collect_pairs<F>(&self, mut predicate: F) -> Vec<(UtxoOutpoint, StoredUtxo)>
    where
        F: FnMut(&UtxoOutpoint, &StoredUtxo) -> bool,
    {
        let entries = self.entries.blocking_read();
        let mut pairs = Vec::new();
        for (outpoint, stored) in entries.iter() {
            if predicate(outpoint, stored) {
                pairs.push((outpoint.clone(), stored.clone()));
            }
        }
        drop(entries);
        Self::sort_pairs(&mut pairs);
        pairs
    }

    fn unspent_pairs_for_owner(&self, owner: &Address) -> Vec<(UtxoOutpoint, StoredUtxo)> {
        self.collect_pairs(|_, stored| stored.owner == *owner && !stored.is_spent())
    }

    /// Return the canonical UTXO associated with the provided account.
    pub fn get_for_account(&self, address: &Address) -> Vec<UtxoRecord> {
        self.unspent_pairs_for_owner(address)
            .into_iter()
            .map(|(outpoint, stored)| stored.to_record(&outpoint))
            .collect()
    }

    /// Snapshot the canonical UTXO and its outpoint for the provided account.
    pub fn snapshot_for_account(&self, address: &Address) -> Vec<(UtxoOutpoint, StoredUtxo)> {
        self.unspent_pairs_for_owner(address)
    }

    /// Select deterministic inputs for the provided owner.
    pub fn select_inputs_for_owner(&self, owner: &Address) -> Vec<(UtxoOutpoint, StoredUtxo)> {
        self.unspent_pairs_for_owner(owner)
    }

    pub fn unspent_outputs_for_owner(&self, owner: &Address) -> Vec<UtxoRecord> {
        self.unspent_pairs_for_owner(owner)
            .into_iter()
            .map(|(outpoint, stored)| stored.to_record(&outpoint))
            .collect()
    }

    pub fn snapshot(&self) -> Vec<(UtxoOutpoint, StoredUtxo)> {
        self.collect_pairs(|_, _| true)
    }

    pub fn commitment(&self) -> [u8; 32] {
        let mut leaves: Vec<[u8; 32]> = self
            .collect_pairs(|_, stored| !stored.is_spent())
            .into_iter()
            .map(|(outpoint, stored)| {
                let payload =
                    bincode::serialize(&(outpoint, stored)).expect("serialize utxo snapshot entry");
                Blake2sHasher::hash(&payload).into()
            })
            .collect();
        compute_merkle_root(&mut leaves)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
        let stored = snapshot
            .iter()
            .find(|(candidate, _)| candidate == &outpoint)
            .expect("entry exists in snapshot");
        assert!(stored.1.is_spent());
    }

    #[test]
    fn multi_output_helpers_are_consistent() {
        let state = UtxoState::new();
        let owner = "carol".to_string();
        let peer = "dave".to_string();

        let lowest_outpoint = UtxoOutpoint {
            tx_id: [3u8; 32],
            index: 0,
        };
        let spent_outpoint = UtxoOutpoint {
            tx_id: [4u8; 32],
            index: 2,
        };
        let highest_outpoint = UtxoOutpoint {
            tx_id: [5u8; 32],
            index: 7,
        };
        let peer_outpoint = UtxoOutpoint {
            tx_id: [6u8; 32],
            index: 1,
        };

        state.insert(highest_outpoint.clone(), StoredUtxo::new(owner.clone(), 30));
        state.insert(lowest_outpoint.clone(), StoredUtxo::new(owner.clone(), 45));
        state.insert(spent_outpoint.clone(), StoredUtxo::new(owner.clone(), 25));
        state.insert(peer_outpoint.clone(), StoredUtxo::new(peer.clone(), 99));

        assert!(state.remove_spent(&spent_outpoint));

        let account_records = state.get_for_account(&owner);
        let account_snapshot = state.snapshot_for_account(&owner);
        let deterministic_inputs = state.select_inputs_for_owner(&owner);
        let unspent_outputs = state.unspent_outputs_for_owner(&owner);

        assert_eq!(account_records.len(), 2);
        assert_eq!(account_snapshot.len(), 2);
        assert_eq!(deterministic_inputs.len(), 2);
        assert_eq!(unspent_outputs.len(), 2);

        let expected_order = vec![lowest_outpoint.clone(), highest_outpoint.clone()];

        assert_eq!(
            account_records
                .iter()
                .map(|record| record.outpoint.clone())
                .collect::<Vec<_>>(),
            expected_order
        );
        assert!(account_records.iter().all(|record| record.value > 0));

        assert_eq!(
            account_snapshot
                .iter()
                .map(|(outpoint, _)| outpoint.clone())
                .collect::<Vec<_>>(),
            expected_order
        );
        assert!(
            account_snapshot
                .iter()
                .all(|(_, stored)| !stored.is_spent())
        );

        assert_eq!(
            deterministic_inputs
                .iter()
                .map(|(outpoint, _)| outpoint.clone())
                .collect::<Vec<_>>(),
            expected_order
        );

        assert_eq!(
            unspent_outputs
                .iter()
                .map(|record| record.outpoint.clone())
                .collect::<Vec<_>>(),
            expected_order
        );

        let peer_records = state.get_for_account(&peer);
        assert_eq!(peer_records.len(), 1);
        assert_eq!(peer_records[0].outpoint, peer_outpoint);

        let snapshot: BTreeMap<_, _> = state.snapshot().into_iter().collect();
        assert!(
            snapshot
                .get(&spent_outpoint)
                .expect("spent entry present in snapshot")
                .is_spent()
        );
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
        let stored = &snapshot[0];
        assert_eq!(stored.0, outpoint);
        assert!(stored.1.is_spent());
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
        let encoded = serde_json::to_string(&snapshot).expect("serialize snapshot");
        let decoded: Vec<(UtxoOutpoint, StoredUtxo)> =
            serde_json::from_str(&encoded).expect("deserialize snapshot");
        assert_eq!(decoded.len(), snapshot.len());
        let decoded_first = decoded
            .iter()
            .find(|(outpoint, _)| *outpoint == second_outpoint)
            .expect("decoded entry");
        assert_eq!(decoded_first.1.owner, owner);
        assert_eq!(decoded_first.1.amount, 45);
        assert!(!decoded_first.1.is_spent());
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
        let refreshed = snapshot
            .iter()
            .find(|(candidate, _)| candidate == &outpoint)
            .expect("snapshot entry");
        assert!(refreshed.1.is_spent());
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
        let peer = "ivy".to_string();

        let low = UtxoOutpoint {
            tx_id: [11u8; 32],
            index: 0,
        };
        let mid = UtxoOutpoint {
            tx_id: [12u8; 32],
            index: 3,
        };
        let high = UtxoOutpoint {
            tx_id: [13u8; 32],
            index: 9,
        };
        let peer_outpoint = UtxoOutpoint {
            tx_id: [14u8; 32],
            index: 1,
        };

        state_a.insert(low.clone(), StoredUtxo::new(owner.clone(), 40));
        state_a.insert(mid.clone(), StoredUtxo::new(owner.clone(), 25));
        state_a.insert(high.clone(), StoredUtxo::new(owner.clone(), 31));
        state_a.insert(peer_outpoint.clone(), StoredUtxo::new(peer.clone(), 77));
        assert!(state_a.remove_spent(&mid));
        state_a.insert(mid.clone(), StoredUtxo::new(owner.clone(), 26));

        state_b.insert(peer_outpoint.clone(), StoredUtxo::new(peer.clone(), 77));
        state_b.insert(high.clone(), StoredUtxo::new(owner.clone(), 31));
        state_b.insert(low.clone(), StoredUtxo::new(owner.clone(), 40));
        assert!(state_b.remove_spent(&high));
        state_b.insert(high.clone(), StoredUtxo::new(owner.clone(), 31));
        state_b.insert(mid.clone(), StoredUtxo::new(owner.clone(), 26));

        let snapshot_a = state_a.snapshot();
        let snapshot_b = state_b.snapshot();

        fn summarize(
            snapshot: &[(UtxoOutpoint, StoredUtxo)],
        ) -> Vec<(UtxoOutpoint, (Address, u128, bool))> {
            snapshot
                .iter()
                .map(|(outpoint, stored)| {
                    (
                        outpoint.clone(),
                        (stored.owner.clone(), stored.amount, stored.is_spent()),
                    )
                })
                .collect()
        }

        assert_eq!(summarize(&snapshot_a), summarize(&snapshot_b));

        let commitment_a = state_a.commitment();
        let commitment_b = state_b.commitment();
        assert_eq!(commitment_a, commitment_b);

        fn recompute(snapshot: &[(UtxoOutpoint, StoredUtxo)]) -> [u8; 32] {
            let mut leaves: Vec<[u8; 32]> = snapshot
                .iter()
                .filter(|(_, stored)| !stored.is_spent())
                .map(|(outpoint, stored)| {
                    let payload =
                        bincode::serialize(&(outpoint.clone(), stored.clone())).expect("encode");
                    Blake2sHasher::hash(&payload).into()
                })
                .collect();
            compute_merkle_root(&mut leaves)
        }

        assert_eq!(commitment_a, recompute(&snapshot_a));
        assert_eq!(commitment_b, recompute(&snapshot_b));

        let mirror = UtxoState::new();
        for (outpoint, stored) in snapshot_a.iter() {
            mirror.insert(outpoint.clone(), stored.clone());
        }
        assert_eq!(mirror.commitment(), commitment_a);
    }
}
