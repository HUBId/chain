use std::collections::BTreeMap;

use crate::proof_backend::Blake2sHasher;
use parking_lot::RwLock;

use crate::rpp::TimetokeRecord;
use crate::state::merkle::compute_merkle_root;
use crate::types::{Account, Address};

#[derive(Default)]
pub struct TimetokeState {
    records: RwLock<BTreeMap<Address, TimetokeRecord>>,
}

impl TimetokeState {
    pub fn new() -> Self {
        Self {
            records: RwLock::new(BTreeMap::new()),
        }
    }

    pub fn upsert_from_account(&self, account: &Account) {
        let record = TimetokeRecord {
            identity: account.address.clone(),
            balance: account.reputation.timetokes.hours_online as u128,
            epoch_accrual: 0,
            decay_rate: 1.0,
            last_update: account.reputation.timetokes.last_proof_timestamp,
            last_sync: account.reputation.timetokes.last_sync_timestamp,
            last_decay: account.reputation.timetokes.last_decay_timestamp,
        };
        self.records.write().insert(account.address.clone(), record);
    }

    pub fn upsert(&self, record: TimetokeRecord) {
        self.records.write().insert(record.identity.clone(), record);
    }

    pub fn get(&self, address: &Address) -> Option<TimetokeRecord> {
        self.records.read().get(address).cloned()
    }

    pub fn snapshot(&self) -> Vec<TimetokeRecord> {
        let mut records = self.records.read().values().cloned().collect::<Vec<_>>();
        records.sort_by(|a, b| a.identity.cmp(&b.identity));
        records
    }

    pub fn commitment(&self) -> [u8; 32] {
        let mut leaves: Vec<[u8; 32]> = self
            .records
            .read()
            .values()
            .map(|record| {
                let payload = serde_json::to_vec(record).expect("serialize timetoke record");
                Blake2sHasher::hash(&payload).into()
            })
            .collect();
        compute_merkle_root(&mut leaves)
    }
}
