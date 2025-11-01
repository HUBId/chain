use std::collections::BTreeMap;

use crate::proof_backend::Blake2sHasher;
use parking_lot::RwLock;

use crate::rpp::ZsiRecord;
use crate::state::merkle::compute_merkle_root;
use crate::types::{Account, Address};

#[derive(Default)]
pub struct ZsiRegistry {
    records: RwLock<BTreeMap<Address, ZsiRecord>>,
}

impl ZsiRegistry {
    pub fn new() -> Self {
        Self {
            records: RwLock::new(BTreeMap::new()),
        }
    }

    pub fn upsert_from_account(&self, account: &Account) {
        let attestation = account
            .reputation
            .zsi
            .reputation_proof
            .as_ref()
            .map(|proof| Blake2sHasher::hash(proof.as_bytes()).into())
            .unwrap_or_else(|| {
                Blake2sHasher::hash(account.reputation.zsi.public_key_commitment.as_bytes()).into()
            });
        let record = ZsiRecord {
            identity: account.address.clone(),
            genesis_id: account.reputation.zsi.public_key_commitment.clone(),
            attestation_digest: attestation,
            approvals: Vec::new(),
        };
        self.records.write().insert(account.address.clone(), record);
    }

    pub fn get(&self, address: &Address) -> Option<ZsiRecord> {
        self.records.read().get(address).cloned()
    }

    pub fn commitment(&self) -> [u8; 32] {
        let mut leaves: Vec<[u8; 32]> = self
            .records
            .read()
            .values()
            .map(|record| {
                let payload = serde_json::to_vec(record).expect("serialize zsi record");
                Blake2sHasher::hash(&payload).into()
            })
            .collect();
        compute_merkle_root(&mut leaves)
    }
}
