use std::collections::{HashMap, HashSet, hash_map::Entry};

use parking_lot::RwLock;
use stwo::core::vcs::blake2_hash::Blake2sHasher;

use crate::errors::{ChainError, ChainResult};
use crate::identity_tree::{IDENTITY_TREE_DEPTH, IdentityCommitmentProof, IdentityCommitmentTree};
use crate::reputation::{self, Tier};
use crate::types::{
    Account, Address, IdentityDeclaration, SignedTransaction, Stake, WalletBindingChange,
};
use hex;
use serde::{Deserialize, Serialize};

const EPOCH_NONCE_DOMAIN: &[u8] = b"rpp-epoch-nonce";

#[derive(Clone, Debug)]
struct EpochState {
    epoch: u64,
    nonce: [u8; 32],
    used_vrf_tags: HashSet<String>,
}

impl EpochState {
    fn new(epoch: u64, nonce: [u8; 32]) -> Self {
        Self {
            epoch,
            nonce,
            used_vrf_tags: HashSet::new(),
        }
    }
}

pub const DEFAULT_EPOCH_LENGTH: u64 = 720;

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum SlashingReason {
    InvalidIdentity,
    InvalidVote,
    ConsensusFault,
}

impl SlashingReason {
    fn penalty_percent(self) -> u8 {
        match self {
            SlashingReason::InvalidIdentity => 50,
            SlashingReason::InvalidVote => 25,
            SlashingReason::ConsensusFault => 10,
        }
    }
}

pub struct Ledger {
    accounts: RwLock<HashMap<Address, Account>>,
    identity_tree: RwLock<IdentityCommitmentTree>,
    epoch_length: u64,
    epoch_state: RwLock<EpochState>,
    slashing_log: RwLock<Vec<SlashingEvent>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SlashingEvent {
    pub address: Address,
    pub reason: SlashingReason,
    pub penalty_percent: u8,
    pub timestamp: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ReputationAudit {
    pub address: Address,
    pub balance: u128,
    pub stake: String,
    pub score: f64,
    pub tier: Tier,
    pub uptime_hours: u64,
    pub consensus_success: u64,
    pub peer_feedback: i64,
    pub last_decay_timestamp: u64,
    pub zsi_validated: bool,
    pub zsi_commitment: String,
    pub zsi_reputation_proof: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EpochInfo {
    pub epoch: u64,
    pub epoch_nonce: String,
}

impl Ledger {
    pub fn new(epoch_length: u64) -> Self {
        let ledger = Self {
            accounts: RwLock::new(HashMap::new()),
            identity_tree: RwLock::new(IdentityCommitmentTree::new(IDENTITY_TREE_DEPTH)),
            epoch_length: epoch_length.max(1),
            epoch_state: RwLock::new(EpochState::new(u64::MAX, [0u8; 32])),
            slashing_log: RwLock::new(Vec::new()),
        };
        ledger.sync_epoch_for_height(0);
        ledger
    }

    pub fn load(initial: Vec<Account>, epoch_length: u64) -> Self {
        let ledger = Ledger::new(epoch_length);
        let mut accounts = ledger.accounts.write();
        let mut tree = ledger.identity_tree.write();
        for account in initial {
            tree.force_insert(
                &account.address,
                &account.reputation.zsi.public_key_commitment,
            )
            .expect("genesis identity commitment");
            accounts.insert(account.address.clone(), account);
        }
        drop(accounts);
        drop(tree);
        ledger.sync_epoch_for_height(0);
        ledger
    }

    pub fn upsert_account(&self, account: Account) -> ChainResult<()> {
        let new_commitment = account.reputation.zsi.public_key_commitment.clone();
        let address = account.address.clone();
        let previous_commitment = {
            let mut accounts = self.accounts.write();
            accounts
                .insert(address.clone(), account)
                .map(|existing| existing.reputation.zsi.public_key_commitment)
        };
        let mut tree = self.identity_tree.write();
        tree.replace_commitment(&address, previous_commitment.as_deref(), &new_commitment)?;
        Ok(())
    }

    pub fn identity_commitment_proof(&self, wallet_addr: &str) -> IdentityCommitmentProof {
        self.identity_tree.read().proof_for(wallet_addr)
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

    pub fn ensure_node_binding(
        &self,
        address: &str,
        wallet_public_key_hex: &str,
    ) -> ChainResult<()> {
        let binding_change = {
            let mut accounts = self.accounts.write();
            let account = accounts.get_mut(address).ok_or_else(|| {
                ChainError::Config("node account missing for identity binding".into())
            })?;
            let change = account.ensure_wallet_binding(wallet_public_key_hex)?;
            account.bind_node_identity()?;
            change
        };
        let WalletBindingChange { previous, current } = binding_change;
        let mut tree = self.identity_tree.write();
        tree.replace_commitment(address, previous.as_deref(), &current)?;
        Ok(())
    }

    pub fn slash_validator(&self, address: &str, reason: SlashingReason) -> ChainResult<()> {
        let mut accounts = self.accounts.write();
        let account = accounts.get_mut(address).ok_or_else(|| {
            ChainError::Transaction("validator account missing for slashing".into())
        })?;
        account.stake.slash_percent(reason.penalty_percent());
        account.reputation.zsi.invalidate();
        account.reputation.tier = Tier::Tl0;
        account.reputation.score = 0.0;
        account.reputation.consensus_success = 0;
        account.reputation.peer_feedback = 0;
        account.reputation.timetokes = reputation::TimetokeBalance::default();
        account.reputation.last_decay_timestamp = reputation::current_timestamp();
        let timestamp = account.reputation.last_decay_timestamp;
        let mut log = self.slashing_log.write();
        log.push(SlashingEvent {
            address: address.to_string(),
            reason,
            penalty_percent: reason.penalty_percent(),
            timestamp,
        });
        Ok(())
    }

    pub fn sync_epoch_for_height(&self, height: u64) {
        let target_epoch = height / self.epoch_length;
        {
            let state = self.epoch_state.read();
            if state.epoch == target_epoch {
                return;
            }
        }
        let new_state = self.build_epoch_state(target_epoch);
        let mut state = self.epoch_state.write();
        *state = new_state;
    }

    fn build_epoch_state(&self, epoch: u64) -> EpochState {
        let state_root = self.state_root();
        let nonce = derive_epoch_nonce(epoch, &state_root);
        EpochState::new(epoch, nonce)
    }

    pub fn current_epoch(&self) -> u64 {
        self.epoch_state.read().epoch
    }

    pub fn current_epoch_nonce(&self) -> [u8; 32] {
        self.epoch_state.read().nonce
    }

    pub fn epoch_info(&self) -> EpochInfo {
        let state = self.epoch_state.read();
        EpochInfo {
            epoch: state.epoch,
            epoch_nonce: hex::encode(state.nonce),
        }
    }

    pub fn register_identity(&self, declaration: IdentityDeclaration) -> ChainResult<()> {
        declaration.verify()?;
        let genesis = &declaration.genesis;
        let key_commitment = genesis.public_key_commitment()?;
        {
            let commitments = self.identity_tree.read();
            if commitments.contains_commitment(&key_commitment) {
                return Err(ChainError::Transaction(
                    "identity already registered for this public key".into(),
                ));
            }
        }
        {
            let accounts = self.accounts.read();
            if accounts.contains_key(&genesis.wallet_addr) {
                return Err(ChainError::Transaction(
                    "wallet address already associated with an identity".into(),
                ));
            }
        }

        let current_state_root = hex::encode(self.state_root());
        if current_state_root != genesis.state_root {
            return Err(ChainError::Transaction(
                "identity declaration references an outdated state root".into(),
            ));
        }
        let current_identity_root = hex::encode(self.identity_root());
        if current_identity_root != genesis.identity_root {
            return Err(ChainError::Transaction(
                "identity declaration references an outdated identity root".into(),
            ));
        }

        if !genesis.commitment_proof.is_vacant()? {
            return Err(ChainError::Transaction(
                "identity commitment slot already occupied".into(),
            ));
        }

        {
            let tree = self.identity_tree.read();
            let current_leaf = tree.leaf_hex(&genesis.wallet_addr);
            if current_leaf != genesis.commitment_proof.leaf {
                return Err(ChainError::Transaction(
                    "identity declaration proof does not match ledger state".into(),
                ));
            }
            let proof_root = genesis
                .commitment_proof
                .compute_root(&genesis.wallet_addr)?;
            if proof_root != genesis.identity_root {
                return Err(ChainError::Transaction(
                    "identity commitment proof does not reconstruct the identity root".into(),
                ));
            }
        }

        let mut account = Account::new(genesis.wallet_addr.clone(), 0, Stake::default());
        account.reputation = crate::reputation::ReputationProfile::new(&genesis.wallet_pk);
        account.ensure_wallet_binding(&genesis.wallet_pk)?;
        account
            .reputation
            .bind_genesis_identity(declaration.commitment());

        {
            let mut state = self.epoch_state.write();
            let expected_nonce = hex::encode(state.nonce);
            if expected_nonce != genesis.epoch_nonce {
                return Err(ChainError::Transaction(
                    "identity declaration references an outdated epoch nonce".into(),
                ));
            }
            if !state.used_vrf_tags.insert(genesis.vrf_tag.clone()) {
                return Err(ChainError::Transaction(
                    "VRF tag already registered for this epoch".into(),
                ));
            }
        }
        self.upsert_account(account)?;
        Ok(())
    }

    pub fn identity_root(&self) -> [u8; 32] {
        self.identity_tree.read().root()
    }

    pub fn apply_transaction(&self, tx: &SignedTransaction) -> ChainResult<u64> {
        tx.verify()?;
        let binding_change;
        {
            let mut accounts = self.accounts.write();
            let sender = accounts
                .get_mut(&tx.payload.from)
                .ok_or_else(|| ChainError::Transaction("sender account not found".into()))?;
            binding_change = sender.ensure_wallet_binding(&tx.public_key)?;
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

            let weights = crate::reputation::ReputationWeights::default();
            let now = crate::reputation::current_timestamp();
            match accounts.entry(tx.payload.to.clone()) {
                Entry::Occupied(mut existing) => {
                    let recipient = existing.get_mut();
                    recipient.balance = recipient.balance.saturating_add(tx.payload.amount);
                    recipient.reputation.recompute_score(&weights, now);
                    recipient.reputation.update_decay_reference(now);
                }
                Entry::Vacant(entry) => {
                    let mut account = Account::new(tx.payload.to.clone(), 0, Stake::default());
                    account.balance = tx.payload.amount;
                    account.reputation.recompute_score(&weights, now);
                    account.reputation.update_decay_reference(now);
                    entry.insert(account);
                }
            }
        }
        let WalletBindingChange { previous, current } = binding_change;
        let mut tree = self.identity_tree.write();
        tree.replace_commitment(&tx.payload.from, previous.as_deref(), &current)?;
        Ok(tx.payload.fee)
    }

    pub fn reward_proposer(&self, address: &str, reward: u64) -> ChainResult<()> {
        let mut accounts = self.accounts.write();
        let account = accounts
            .entry(address.to_string())
            .or_insert_with(|| Account::new(address.to_string(), 0, Stake::default()));
        account.bind_node_identity()?;
        account.balance = account.balance.saturating_add(reward as u128);
        account.reputation.record_consensus_success();
        let weights = crate::reputation::ReputationWeights::default();
        let now = crate::reputation::current_timestamp();
        account.reputation.recompute_score(&weights, now);
        account.reputation.update_decay_reference(now);
        Ok(())
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

    pub fn slashing_events(&self, limit: usize) -> Vec<SlashingEvent> {
        let log = self.slashing_log.read();
        let start = log.len().saturating_sub(limit);
        log[start..].to_vec()
    }

    pub fn reputation_audit(&self, address: &str) -> ChainResult<Option<ReputationAudit>> {
        let accounts = self.accounts.read();
        Ok(accounts.get(address).map(|account| ReputationAudit {
            address: account.address.clone(),
            balance: account.balance,
            stake: account.stake.to_string(),
            score: account.reputation.score,
            tier: account.reputation.tier.clone(),
            uptime_hours: account.reputation.timetokes.hours_online,
            consensus_success: account.reputation.consensus_success,
            peer_feedback: account.reputation.peer_feedback,
            last_decay_timestamp: account.reputation.last_decay_timestamp,
            zsi_validated: account.reputation.zsi.validated,
            zsi_commitment: account.reputation.zsi.public_key_commitment.clone(),
            zsi_reputation_proof: account.reputation.zsi.reputation_proof.clone(),
        }))
    }
}

fn derive_epoch_nonce(epoch: u64, state_root: &[u8; 32]) -> [u8; 32] {
    let mut data = Vec::with_capacity(EPOCH_NONCE_DOMAIN.len() + 8 + state_root.len());
    data.extend_from_slice(EPOCH_NONCE_DOMAIN);
    data.extend_from_slice(&epoch.to_le_bytes());
    data.extend_from_slice(state_root);
    Blake2sHasher::hash(&data).into()
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::consensus::evaluate_vrf;
    use crate::crypto::address_from_public_key;
    use crate::stwo::circuit::StarkCircuit;
    use crate::stwo::circuit::identity::{IdentityCircuit, IdentityWitness};
    use crate::stwo::circuit::string_to_field;
    use crate::stwo::fri::FriProver;
    use crate::stwo::params::StarkParameters;
    use crate::stwo::proof::{ProofKind, ProofPayload, StarkProof};
    use crate::types::{
        IdentityDeclaration, IdentityGenesis, IdentityProof, SignedTransaction, Transaction,
    };
    use ed25519_dalek::{Keypair, PublicKey, SecretKey, Signer};
    use stwo::core::vcs::blake2_hash::Blake2sHasher;

    fn sample_identity_declaration(ledger: &Ledger) -> IdentityDeclaration {
        ledger.sync_epoch_for_height(1);
        let pk_bytes = vec![1u8; 32];
        let wallet_pk = hex::encode(&pk_bytes);
        let wallet_addr = hex::encode::<[u8; 32]>(Blake2sHasher::hash(&pk_bytes).into());
        let epoch_nonce_bytes = ledger.current_epoch_nonce();
        let vrf = evaluate_vrf(&epoch_nonce_bytes, 0, &wallet_addr);
        let commitment_proof = ledger.identity_commitment_proof(&wallet_addr);
        let genesis = IdentityGenesis {
            wallet_pk,
            wallet_addr,
            vrf_tag: vrf.proof.clone(),
            epoch_nonce: hex::encode(epoch_nonce_bytes),
            state_root: hex::encode(ledger.state_root()),
            identity_root: hex::encode(ledger.identity_root()),
            initial_reputation: 0,
            commitment_proof: commitment_proof.clone(),
        };
        let commitment_hex = genesis.expected_commitment().expect("commitment");
        let witness = IdentityWitness {
            wallet_pk: genesis.wallet_pk.clone(),
            wallet_addr: genesis.wallet_addr.clone(),
            vrf_tag: genesis.vrf_tag.clone(),
            epoch_nonce: genesis.epoch_nonce.clone(),
            state_root: genesis.state_root.clone(),
            identity_root: genesis.identity_root.clone(),
            initial_reputation: genesis.initial_reputation,
            commitment: commitment_hex.clone(),
            identity_leaf: commitment_proof.leaf.clone(),
            identity_path: commitment_proof.siblings.clone(),
        };
        let parameters = StarkParameters::blueprint_default();
        let circuit = IdentityCircuit::new(witness.clone());
        circuit.evaluate_constraints().expect("constraints");
        let trace = circuit
            .generate_trace(&parameters)
            .expect("trace generation");
        circuit
            .verify_air(&parameters, &trace)
            .expect("air verification");
        let inputs = vec![
            string_to_field(&parameters, &witness.wallet_addr),
            string_to_field(&parameters, &witness.vrf_tag),
            string_to_field(&parameters, &witness.identity_root),
            string_to_field(&parameters, &witness.state_root),
        ];
        let hasher = parameters.poseidon_hasher();
        let fri_prover = FriProver::new(&parameters);
        let fri_proof = fri_prover.prove(&trace, &inputs);
        let proof = StarkProof::new(
            ProofKind::Identity,
            ProofPayload::Identity(witness),
            inputs,
            trace,
            fri_proof,
            &hasher,
        );
        IdentityDeclaration {
            genesis,
            proof: IdentityProof {
                commitment: commitment_hex,
                zk_proof: proof,
            },
        }
    }

    #[test]
    fn register_identity_creates_account() {
        let ledger = Ledger::new(DEFAULT_EPOCH_LENGTH);
        let declaration = sample_identity_declaration(&ledger);
        ledger.register_identity(declaration.clone()).unwrap();

        let account = ledger
            .get_account(&declaration.genesis.wallet_addr)
            .unwrap();
        assert!(account.reputation.zsi.validated);
        assert_eq!(
            account.reputation.zsi.reputation_proof,
            Some(declaration.proof.commitment.clone())
        );
        assert_eq!(
            account.identity.wallet_public_key,
            Some(declaration.genesis.wallet_pk.clone())
        );
        assert!(account.identity.node_address.is_none());
        assert_eq!(account.reputation.score, 0.0);
        assert_eq!(account.reputation.tier, crate::reputation::Tier::Tl0);
    }

    #[test]
    fn duplicate_identity_rejected() {
        let ledger = Ledger::new(DEFAULT_EPOCH_LENGTH);
        let declaration = sample_identity_declaration(&ledger);
        ledger.register_identity(declaration.clone()).unwrap();
        let err = ledger.register_identity(declaration).unwrap_err();
        assert!(matches!(err, ChainError::Transaction(_)));
    }

    fn deterministic_keypair() -> Keypair {
        let secret = SecretKey::from_bytes(&[7u8; 32]).expect("secret");
        let public = PublicKey::from(&secret);
        Keypair { secret, public }
    }

    #[test]
    fn transaction_binds_wallet_key() {
        let ledger = Ledger::new(DEFAULT_EPOCH_LENGTH);
        let keypair = deterministic_keypair();
        let address = address_from_public_key(&keypair.public);
        let mut account = Account::new(address.clone(), 1_000, Stake::default());
        let _ = account
            .ensure_wallet_binding(&hex::encode(keypair.public.to_bytes()))
            .unwrap();
        ledger.upsert_account(account).unwrap();

        let recipient = "ff00".repeat(16);
        let tx = Transaction::new(address.clone(), recipient.clone(), 100, 1, 1, None);
        let signature = keypair.sign(&tx.canonical_bytes());
        let signed = SignedTransaction::new(tx, signature, &keypair.public);
        ledger.apply_transaction(&signed).unwrap();

        let account = ledger.get_account(&address).unwrap();
        assert_eq!(
            account.identity.wallet_public_key,
            Some(hex::encode(keypair.public.to_bytes()))
        );
        assert_eq!(account.nonce, 1);
    }

    #[test]
    fn slashing_resets_validator_state() {
        let ledger = Ledger::new(DEFAULT_EPOCH_LENGTH);
        let address = "deadbeef".repeat(4);
        let mut account = Account::new(address.clone(), 0, Stake::from_u128(1_000));
        account.reputation.bind_genesis_identity("proof");
        account.reputation.tier = crate::reputation::Tier::Tl4;
        account.reputation.score = 1.5;
        account.reputation.consensus_success = 8;
        account.reputation.peer_feedback = 4;
        account.reputation.timetokes.hours_online = 12;
        ledger.upsert_account(account).unwrap();

        ledger
            .slash_validator(&address, super::SlashingReason::InvalidVote)
            .unwrap();

        let slashed = ledger.get_account(&address).unwrap();
        assert_eq!(slashed.stake.to_string(), "750");
        assert!(!slashed.reputation.zsi.validated);
        assert_eq!(slashed.reputation.tier, crate::reputation::Tier::Tl0);
        assert_eq!(slashed.reputation.score, 0.0);
        assert_eq!(slashed.reputation.consensus_success, 0);
        assert_eq!(slashed.reputation.peer_feedback, 0);
        assert_eq!(slashed.reputation.timetokes.hours_online, 0);
    }

    #[test]
    fn records_slashing_events() {
        let ledger = Ledger::new(DEFAULT_EPOCH_LENGTH);
        let mut account = Account::new("validator".into(), 1_000_000, Stake::from_u128(10_000));
        account.reputation.bind_genesis_identity("genesis-proof");
        ledger.upsert_account(account).unwrap();

        ledger
            .slash_validator("validator", SlashingReason::InvalidVote)
            .unwrap();

        let events = ledger.slashing_events(10);
        assert_eq!(events.len(), 1);
        let event = &events[0];
        assert_eq!(event.address, "validator");
        assert_eq!(event.reason, SlashingReason::InvalidVote);
        assert_eq!(
            event.penalty_percent,
            SlashingReason::InvalidVote.penalty_percent()
        );
        assert!(event.timestamp > 0);
    }

    #[test]
    fn reputation_audit_reflects_account_state() {
        let ledger = Ledger::new(DEFAULT_EPOCH_LENGTH);
        let mut account = Account::new("audited".into(), 5_000, Stake::from_u128(1_000));
        account.reputation.bind_genesis_identity("audit-proof");
        account.reputation.consensus_success = 7;
        account.reputation.peer_feedback = 3;
        account.reputation.timetokes.hours_online = 12;
        ledger.upsert_account(account.clone()).unwrap();

        let audit = ledger
            .reputation_audit("audited")
            .unwrap()
            .expect("audit entry");
        assert_eq!(audit.address, account.address);
        assert_eq!(audit.balance, account.balance);
        assert_eq!(audit.stake, account.stake.to_string());
        assert_eq!(
            audit.consensus_success,
            account.reputation.consensus_success
        );
        assert_eq!(audit.peer_feedback, account.reputation.peer_feedback);
        assert_eq!(
            audit.uptime_hours,
            account.reputation.timetokes.hours_online
        );
        assert!(audit.zsi_validated);
        assert_eq!(
            audit.zsi_commitment,
            account.reputation.zsi.public_key_commitment
        );
        assert_eq!(
            audit.zsi_reputation_proof,
            account.reputation.zsi.reputation_proof
        );
    }
}
