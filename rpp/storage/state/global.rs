use std::collections::HashMap;

use parking_lot::{RwLock, RwLockReadGuard, RwLockWriteGuard};
use crate::proof_backend::Blake2sHasher;

use crate::state::merkle::compute_merkle_root;
use crate::types::{Account, Address, Stake};

/// Stores the canonical account-based view of the chain state.
#[derive(Default)]
pub struct GlobalState {
    accounts: RwLock<HashMap<Address, Account>>,
}

impl GlobalState {
    pub fn new() -> Self {
        Self {
            accounts: RwLock::new(HashMap::new()),
        }
    }

    pub fn load(initial: Vec<Account>) -> Self {
        let state = Self::new();
        {
            let mut accounts = state.accounts.write();
            for account in initial {
                accounts.insert(account.address.clone(), account);
            }
        }
        state
    }

    pub fn read_accounts(&self) -> RwLockReadGuard<'_, HashMap<Address, Account>> {
        self.accounts.read()
    }

    pub fn write_accounts(&self) -> RwLockWriteGuard<'_, HashMap<Address, Account>> {
        self.accounts.write()
    }

    pub fn upsert(&self, account: Account) -> Option<Account> {
        self.accounts
            .write()
            .insert(account.address.clone(), account)
    }

    pub fn get(&self, address: &str) -> Option<Account> {
        self.accounts.read().get(address).cloned()
    }

    pub fn accounts_snapshot(&self) -> Vec<Account> {
        let mut accounts = self.accounts.read().values().cloned().collect::<Vec<_>>();
        accounts.sort_by(|a, b| a.address.cmp(&b.address));
        accounts
    }

    pub fn stake_snapshot(&self) -> Vec<(Address, Stake)> {
        self.accounts
            .read()
            .values()
            .map(|account| (account.address.clone(), account.stake.clone()))
            .collect()
    }

    pub fn state_root(&self) -> [u8; 32] {
        let mut leaves = self
            .accounts
            .read()
            .values()
            .map(|account| {
                let bytes = serde_json::to_vec(account).expect("serialize account");
                <[u8; 32]>::from(Blake2sHasher::hash(bytes.as_slice()))
            })
            .collect::<Vec<_>>();
        compute_merkle_root(&mut leaves)
    }
}
