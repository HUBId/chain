use std::collections::BTreeMap;

use crate::proof_backend::Blake2sHasher;
use parking_lot::RwLock;

use crate::reputation::Tier;
use crate::rpp::{ReputationRecord, TierDescriptor};
use crate::state::merkle::compute_merkle_root;
use crate::types::{Account, Address};

#[derive(Default)]
pub struct ReputationState {
    records: RwLock<BTreeMap<Address, ReputationRecord>>,
}

impl ReputationState {
    pub fn new() -> Self {
        Self {
            records: RwLock::new(BTreeMap::new()),
        }
    }

    pub fn upsert_from_account(&self, account: &Account) {
        let record = ReputationRecord {
            identity: account.address.clone(),
            score: account.reputation.score,
            tier: map_tier_descriptor(&account.reputation.tier),
            uptime_hours: account.reputation.timetokes.hours_online,
            consensus_success: account.reputation.consensus_success,
            peer_feedback: account.reputation.peer_feedback,
            zsi_validated: account.reputation.zsi.validated,
        };
        self.records.write().insert(account.address.clone(), record);
    }

    pub fn remove(&self, address: &Address) {
        self.records.write().remove(address);
    }

    pub fn get(&self, address: &Address) -> Option<ReputationRecord> {
        self.records.read().get(address).cloned()
    }

    pub fn commitment(&self) -> [u8; 32] {
        let mut leaves: Vec<[u8; 32]> = self
            .records
            .read()
            .values()
            .map(|record| {
                let payload = serde_json::to_vec(record).expect("serialize reputation record");
                Blake2sHasher::hash(&payload).into()
            })
            .collect();
        compute_merkle_root(&mut leaves)
    }
}

fn map_tier_descriptor(tier: &Tier) -> TierDescriptor {
    match tier {
        Tier::Tl0 => TierDescriptor::Candidate,
        Tier::Tl1 => TierDescriptor::Validator,
        Tier::Tl2 => TierDescriptor::Guardian,
        Tier::Tl3 => TierDescriptor::Custom("Committed".into()),
        Tier::Tl4 => TierDescriptor::Custom("Reliable".into()),
        Tier::Tl5 => TierDescriptor::Custom("Trusted".into()),
    }
}
