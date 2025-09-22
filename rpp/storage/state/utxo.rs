use std::collections::BTreeMap;

use parking_lot::RwLock;
use stwo::core::vcs::blake2_hash::Blake2sHasher;

use crate::rpp::{AssetType, UtxoOutpoint, UtxoRecord};
use crate::state::merkle::compute_merkle_root;
use crate::types::{Account, Address};

#[derive(Default)]
pub struct UtxoState {
    records: RwLock<BTreeMap<UtxoOutpoint, UtxoRecord>>,
}

impl UtxoState {
    pub fn new() -> Self {
        Self {
            records: RwLock::new(BTreeMap::new()),
        }
    }

    pub fn upsert_from_account(&self, account: &Account) -> UtxoRecord {
        let record = record_for_account(account);
        self.records
            .write()
            .insert(record.outpoint.clone(), record.clone());
        record
    }

    pub fn get_for_account(&self, address: &Address) -> Option<UtxoRecord> {
        let outpoint = account_outpoint(address);
        self.records.read().get(&outpoint).cloned()
    }

    pub fn insert(&self, record: UtxoRecord) {
        self.records.write().insert(record.outpoint.clone(), record);
    }

    pub fn remove(&self, outpoint: &UtxoOutpoint) -> Option<UtxoRecord> {
        self.records.write().remove(outpoint)
    }

    pub fn get(&self, outpoint: &UtxoOutpoint) -> Option<UtxoRecord> {
        self.records.read().get(outpoint).cloned()
    }

    pub fn snapshot(&self) -> Vec<UtxoRecord> {
        self.records.read().values().cloned().collect::<Vec<_>>()
    }

    pub fn commitment(&self) -> [u8; 32] {
        let mut leaves: Vec<[u8; 32]> = self
            .records
            .read()
            .values()
            .map(|record| {
                let payload = serde_json::to_vec(record).expect("serialize utxo record");
                Blake2sHasher::hash(&payload).into()
            })
            .collect();
        compute_merkle_root(&mut leaves)
    }
}

fn account_outpoint(address: &Address) -> UtxoOutpoint {
    let digest: [u8; 32] = Blake2sHasher::hash(address.as_bytes()).into();
    UtxoOutpoint {
        tx_id: digest,
        index: 0,
    }
}

fn record_for_account(account: &Account) -> UtxoRecord {
    UtxoRecord {
        outpoint: account_outpoint(&account.address),
        owner: account.address.clone(),
        value: account.balance,
        asset_type: AssetType::Native,
        script_hash: Blake2sHasher::hash(account.address.as_bytes()).into(),
        timelock: None,
    }
}
