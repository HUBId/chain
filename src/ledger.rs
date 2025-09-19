use std::collections::HashMap;

use parking_lot::RwLock;
use stwo::core::vcs::blake2_hash::Blake2sHasher;

use crate::errors::{ChainError, ChainResult};
use crate::types::{Account, Address, SignedTransaction, Stake};

pub struct Ledger {
    accounts: RwLock<HashMap<Address, Account>>,
}

impl Ledger {
    pub fn new() -> Self {
        Self {
            accounts: RwLock::new(HashMap::new()),
        }
    }

    pub fn load(initial: Vec<Account>) -> Self {
        let ledger = Ledger::new();
        let mut accounts = ledger.accounts.write();
        for account in initial {
            accounts.insert(account.address.clone(), account);
        }
        drop(accounts);
        ledger
    }

    pub fn upsert_account(&self, account: Account) {
        self.accounts
            .write()
            .insert(account.address.clone(), account);
    }

    pub fn get_account(&self, address: &str) -> Option<Account> {
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

    pub fn apply_transaction(&self, tx: &SignedTransaction) -> ChainResult<u64> {
        tx.verify()?;
        let mut accounts = self.accounts.write();
        let sender = accounts
            .get_mut(&tx.payload.from)
            .ok_or_else(|| ChainError::Transaction("sender account not found".into()))?;
        if sender.nonce + 1 != tx.payload.nonce {
            return Err(ChainError::Transaction("invalid nonce".into()));
        }
        let total = tx
            .payload
            .amount
            .checked_add(tx.payload.fee as u128)
            .ok_or_else(|| ChainError::Transaction("transaction amount overflow".into()))?;
        if sender.balance < total {
            return Err(ChainError::Transaction("insufficient balance".into()));
        }
        sender.balance -= total;
        sender.nonce += 1;

        let recipient = accounts
            .entry(tx.payload.to.clone())
            .or_insert_with(|| Account::new(tx.payload.to.clone(), 0, Stake::default()));
        recipient.balance = recipient.balance.saturating_add(tx.payload.amount);
        let weights = crate::reputation::ReputationWeights::default();
        let now = crate::reputation::current_timestamp();
        recipient.reputation.recompute_score(&weights, now);
        recipient.reputation.update_decay_reference(now);

        Ok(tx.payload.fee)
    }

    pub fn reward_proposer(&self, address: &str, reward: u64) {
        let mut accounts = self.accounts.write();
        let account = accounts
            .entry(address.to_string())
            .or_insert_with(|| Account::new(address.to_string(), 0, Stake::default()));
        account.balance = account.balance.saturating_add(reward as u128);
        account.reputation.record_consensus_success();
        let weights = crate::reputation::ReputationWeights::default();
        let now = crate::reputation::current_timestamp();
        account.reputation.recompute_score(&weights, now);
        account.reputation.update_decay_reference(now);
    }

    pub fn state_root(&self) -> [u8; 32] {
        let mut accounts = self.accounts.read().values().cloned().collect::<Vec<_>>();
        accounts.sort_by(|a, b| a.address.cmp(&b.address));
        let mut leaves = accounts
            .iter()
            .map(|account| {
                let bytes = serde_json::to_vec(account).expect("serialize account");
                <[u8; 32]>::from(Blake2sHasher::hash(bytes.as_slice()))
            })
            .collect::<Vec<_>>();
        compute_merkle_root(&mut leaves)
    }
}

pub fn compute_merkle_root(leaves: &mut Vec<[u8; 32]>) -> [u8; 32] {
    if leaves.is_empty() {
        return Blake2sHasher::hash(b"rpp-empty").into();
    }
    while leaves.len() > 1 {
        let mut next = Vec::with_capacity((leaves.len() + 1) / 2);
        for chunk in leaves.chunks(2) {
            let left = chunk[0];
            let right = if chunk.len() == 2 { chunk[1] } else { chunk[0] };
            let mut data = Vec::with_capacity(64);
            data.extend_from_slice(&left);
            data.extend_from_slice(&right);
            next.push(Blake2sHasher::hash(&data).into());
        }
        *leaves = next;
    }
    leaves[0]
}
