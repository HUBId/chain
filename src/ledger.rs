use std::collections::{HashSet, hash_map::Entry};
use std::mem;

use parking_lot::RwLock;
use stwo::core::vcs::blake2_hash::Blake2sHasher;

use crate::errors::{ChainError, ChainResult};
use crate::identity_tree::{IDENTITY_TREE_DEPTH, IdentityCommitmentProof, IdentityCommitmentTree};
use crate::proof_system::ProofVerifierRegistry;
use crate::reputation::{self, Tier};
use crate::rpp::{
    AccountBalanceWitness, ConsensusWitness, GlobalStateCommitments, ModuleWitnessBundle,
    ProofArtifact, ReputationEventKind, ReputationRecord, ReputationWitness, TimetokeRecord,
    TimetokeWitness, TransactionWitness, UtxoRecord, ZsiRecord, ZsiWitness,
};
use crate::state::{
    GlobalState, ProofRegistry, ReputationState, TimetokeState, UtxoState, ZsiRegistry,
};
use crate::types::{
    Account, Address, IdentityDeclaration, SignedTransaction, Stake, UptimeProof,
    WalletBindingChange,
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
    global_state: GlobalState,
    utxo_state: UtxoState,
    reputation_state: ReputationState,
    timetoke_state: TimetokeState,
    zsi_registry: ZsiRegistry,
    proof_registry: ProofRegistry,
    module_witnesses: RwLock<ModuleWitnessBook>,
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
            global_state: GlobalState::new(),
            utxo_state: UtxoState::new(),
            reputation_state: ReputationState::new(),
            timetoke_state: TimetokeState::new(),
            zsi_registry: ZsiRegistry::new(),
            proof_registry: ProofRegistry::new(),
            module_witnesses: RwLock::new(ModuleWitnessBook::default()),
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
        let mut tree = ledger.identity_tree.write();
        for account in initial {
            tree.force_insert(
                &account.address,
                &account.reputation.zsi.public_key_commitment,
            )
            .expect("genesis identity commitment");
            ledger.global_state.upsert(account.clone());
            ledger.index_account_modules(&account);
        }
        drop(tree);
        ledger.sync_epoch_for_height(0);
        ledger
    }

    pub fn upsert_account(&self, account: Account) -> ChainResult<()> {
        let new_commitment = account.reputation.zsi.public_key_commitment.clone();
        let address = account.address.clone();
        let previous_commitment = self
            .global_state
            .upsert(account.clone())
            .map(|existing| existing.reputation.zsi.public_key_commitment);
        self.index_account_modules(&account);
        let mut tree = self.identity_tree.write();
        tree.replace_commitment(&address, previous_commitment.as_deref(), &new_commitment)?;
        Ok(())
    }

    pub fn identity_commitment_proof(&self, wallet_addr: &str) -> IdentityCommitmentProof {
        self.identity_tree.read().proof_for(wallet_addr)
    }

    pub fn get_account(&self, address: &str) -> Option<Account> {
        self.global_state.get(address)
    }

    pub fn accounts_snapshot(&self) -> Vec<Account> {
        self.global_state.accounts_snapshot()
    }

    fn module_records(&self, address: &str) -> ModuleRecordSnapshots {
        let address = address.to_string();
        ModuleRecordSnapshots {
            utxo: self.utxo_state.get_for_account(&address),
            reputation: self.reputation_state.get(&address),
            timetoke: self.timetoke_state.get(&address),
            zsi: self.zsi_registry.get(&address),
        }
    }

    pub fn stake_snapshot(&self) -> Vec<(Address, Stake)> {
        self.global_state.stake_snapshot()
    }

    pub fn ensure_node_binding(
        &self,
        address: &str,
        wallet_public_key_hex: &str,
    ) -> ChainResult<()> {
        let (binding_change, updated_account) = {
            let mut accounts = self.global_state.write_accounts();
            let account = accounts.get_mut(address).ok_or_else(|| {
                ChainError::Config("node account missing for identity binding".into())
            })?;
            let change = account.ensure_wallet_binding(wallet_public_key_hex)?;
            account.bind_node_identity()?;
            (change, account.clone())
        };
        let WalletBindingChange { previous, current } = binding_change;
        let mut tree = self.identity_tree.write();
        tree.replace_commitment(address, previous.as_deref(), &current)?;
        self.index_account_modules(&updated_account);
        Ok(())
    }

    pub fn slash_validator(&self, address: &str, reason: SlashingReason) -> ChainResult<()> {
        let module_before = self.module_records(address);
        let (timestamp, updated_account) = {
            let mut accounts = self.global_state.write_accounts();
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
            (timestamp, account.clone())
        };
        let mut log = self.slashing_log.write();
        log.push(SlashingEvent {
            address: address.to_string(),
            reason,
            penalty_percent: reason.penalty_percent(),
            timestamp,
        });
        self.index_account_modules(&updated_account);
        let module_after = self.module_records(address);
        if let Some(reputation_after) = module_after.reputation.clone() {
            let mut book = self.module_witnesses.write();
            book.record_reputation(ReputationWitness::new(
                updated_account.address.clone(),
                ReputationEventKind::Slashing,
                module_before.reputation,
                reputation_after,
            ));
        }
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
            let accounts = self.global_state.read_accounts();
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
        let module_before = self.module_records(&genesis.wallet_addr);
        self.upsert_account(account.clone())?;
        let module_after = self.module_records(&genesis.wallet_addr);
        {
            let mut book = self.module_witnesses.write();
            if let Some(zsi_after) = module_after.zsi.clone() {
                book.record_zsi(ZsiWitness::new(
                    account.address.clone(),
                    module_before.zsi.clone(),
                    zsi_after,
                ));
            }
            if let Some(reputation_after) = module_after.reputation.clone() {
                book.record_reputation(ReputationWitness::new(
                    account.address.clone(),
                    ReputationEventKind::IdentityOnboarding,
                    module_before.reputation,
                    reputation_after,
                ));
            }
        }
        Ok(())
    }

    pub fn identity_root(&self) -> [u8; 32] {
        self.identity_tree.read().root()
    }

    pub fn apply_uptime_proof(&self, proof: &UptimeProof) -> ChainResult<u64> {
        if proof.window_end <= proof.window_start {
            return Err(ChainError::Transaction(
                "uptime proof window end must be greater than start".into(),
            ));
        }
        if proof.window_end.saturating_sub(proof.window_start) < 3_600 {
            return Err(ChainError::Transaction(
                "uptime proof must cover at least one hour".into(),
            ));
        }
        if !proof.verify_commitment() {
            return Err(ChainError::Transaction(
                "uptime proof commitment mismatch".into(),
            ));
        }
        if let Some(zk_proof) = &proof.proof {
            let registry = ProofVerifierRegistry::default();
            registry.verify_uptime(zk_proof)?;
            let claim = proof.claim()?;
            if claim.wallet_address != proof.wallet_address {
                return Err(ChainError::Transaction(
                    "uptime proof wallet address mismatch".into(),
                ));
            }
        }
        let module_before = self.module_records(&proof.wallet_address);
        let (credited_hours, updated_account) = {
            let mut accounts = self.global_state.write_accounts();
            let account = accounts.get_mut(&proof.wallet_address).ok_or_else(|| {
                ChainError::Transaction("uptime proof references unknown account".into())
            })?;
            if !account.reputation.zsi.validated {
                return Err(ChainError::Transaction(
                    "uptime proof requires a validated genesis identity".into(),
                ));
            }
            if !account
                .reputation
                .record_online_proof(proof.window_start, proof.window_end)
            {
                return Err(ChainError::Transaction(
                    "uptime proof does not extend the recorded online window".into(),
                ));
            }
            let weights = crate::reputation::ReputationWeights::default();
            let now = crate::reputation::current_timestamp();
            account.reputation.recompute_score(&weights, now);
            account.reputation.update_decay_reference(now);
            (account.reputation.timetokes.hours_online, account.clone())
        };
        self.index_account_modules(&updated_account);
        let module_after = self.module_records(&proof.wallet_address);
        {
            let mut book = self.module_witnesses.write();
            if let Some(timetoke_after) = module_after.timetoke.clone() {
                book.record_timetoke(TimetokeWitness::new(
                    proof.wallet_address.clone(),
                    module_before.timetoke.clone(),
                    timetoke_after,
                    proof.window_start,
                    proof.window_end,
                    credited_hours,
                ));
            }
            if let Some(reputation_after) = module_after.reputation.clone() {
                book.record_reputation(ReputationWitness::new(
                    proof.wallet_address.clone(),
                    ReputationEventKind::TimetokeAccrual,
                    module_before.reputation,
                    reputation_after,
                ));
            }
        }
        Ok(credited_hours)
    }

    pub fn apply_transaction(&self, tx: &SignedTransaction) -> ChainResult<u64> {
        tx.verify()?;
        let module_sender_before = self.module_records(&tx.payload.from);
        let module_recipient_before = self.module_records(&tx.payload.to);
        let weights = crate::reputation::ReputationWeights::default();
        let now = crate::reputation::current_timestamp();
        let (binding_change, sender_before, sender_after, recipient_before, recipient_after) = {
            let mut accounts = self.global_state.write_accounts();
            let (binding_change, sender_before, sender_after) = {
                let sender = accounts
                    .get_mut(&tx.payload.from)
                    .ok_or_else(|| ChainError::Transaction("sender account not found".into()))?;
                let binding_change = sender.ensure_wallet_binding(&tx.public_key)?;
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
                let before = sender.clone();
                sender.balance -= total;
                sender.nonce += 1;
                let after = sender.clone();
                (binding_change, before, after)
            };

            let (recipient_before, recipient_after) = match accounts.entry(tx.payload.to.clone()) {
                Entry::Occupied(mut existing) => {
                    let recipient = existing.get_mut();
                    let before = recipient.clone();
                    recipient.balance = recipient.balance.saturating_add(tx.payload.amount);
                    recipient.reputation.recompute_score(&weights, now);
                    recipient.reputation.update_decay_reference(now);
                    (Some(before), recipient.clone())
                }
                Entry::Vacant(entry) => {
                    let mut account = Account::new(tx.payload.to.clone(), 0, Stake::default());
                    account.balance = tx.payload.amount;
                    account.reputation.recompute_score(&weights, now);
                    account.reputation.update_decay_reference(now);
                    let inserted = entry.insert(account);
                    (None, inserted.clone())
                }
            };
            (
                binding_change,
                sender_before,
                sender_after,
                recipient_before,
                recipient_after,
            )
        };
        let WalletBindingChange { previous, current } = binding_change;
        let mut tree = self.identity_tree.write();
        tree.replace_commitment(&tx.payload.from, previous.as_deref(), &current)?;
        drop(tree);
        self.index_account_modules(&sender_after);
        self.index_account_modules(&recipient_after);
        let sender_modules_after = self.module_records(&tx.payload.from);
        let recipient_modules_after = self.module_records(&tx.payload.to);

        let sender_before_witness = AccountBalanceWitness::new(
            sender_before.address.clone(),
            sender_before.balance,
            sender_before.nonce,
        );
        let sender_after_witness = AccountBalanceWitness::new(
            sender_after.address.clone(),
            sender_after.balance,
            sender_after.nonce,
        );
        let recipient_before_witness = recipient_before.as_ref().map(|account| {
            AccountBalanceWitness::new(account.address.clone(), account.balance, account.nonce)
        });
        let recipient_after_witness = AccountBalanceWitness::new(
            recipient_after.address.clone(),
            recipient_after.balance,
            recipient_after.nonce,
        );
        let tx_witness = TransactionWitness::new(
            tx.hash(),
            tx.payload.fee,
            sender_before_witness,
            sender_after_witness,
            recipient_before_witness,
            recipient_after_witness,
            module_sender_before.utxo.clone(),
            sender_modules_after.utxo.clone(),
            module_recipient_before.utxo.clone(),
            recipient_modules_after.utxo.clone(),
        );

        let sender_reputation_witness = sender_modules_after.reputation.clone().map(|after| {
            ReputationWitness::new(
                sender_after.address.clone(),
                ReputationEventKind::TransferDebit,
                module_sender_before.reputation,
                after,
            )
        });
        let recipient_reputation_witness =
            recipient_modules_after.reputation.clone().map(|after| {
                ReputationWitness::new(
                    recipient_after.address.clone(),
                    ReputationEventKind::TransferCredit,
                    module_recipient_before.reputation,
                    after,
                )
            });

        {
            let mut book = self.module_witnesses.write();
            book.record_transaction(tx_witness);
            if let Some(witness) = sender_reputation_witness {
                book.record_reputation(witness);
            }
            if let Some(witness) = recipient_reputation_witness {
                book.record_reputation(witness);
            }
        }

        Ok(tx.payload.fee)
    }

    pub fn reward_proposer(&self, address: &str, reward: u64) -> ChainResult<()> {
        let module_before = self.module_records(address);
        let updated_account = {
            let mut accounts = self.global_state.write_accounts();
            match accounts.entry(address.to_string()) {
                Entry::Occupied(mut entry) => {
                    let account = entry.get_mut();
                    account.bind_node_identity()?;
                    account.balance = account.balance.saturating_add(reward as u128);
                    account.reputation.record_consensus_success();
                    let weights = crate::reputation::ReputationWeights::default();
                    let now = crate::reputation::current_timestamp();
                    account.reputation.recompute_score(&weights, now);
                    account.reputation.update_decay_reference(now);
                    account.clone()
                }
                Entry::Vacant(entry) => {
                    let mut account = Account::new(address.to_string(), 0, Stake::default());
                    account.bind_node_identity()?;
                    account.balance = account.balance.saturating_add(reward as u128);
                    account.reputation.record_consensus_success();
                    let weights = crate::reputation::ReputationWeights::default();
                    let now = crate::reputation::current_timestamp();
                    account.reputation.recompute_score(&weights, now);
                    account.reputation.update_decay_reference(now);
                    let inserted = entry.insert(account);
                    inserted.clone()
                }
            }
        };
        self.index_account_modules(&updated_account);
        let module_after = self.module_records(address);
        if let Some(reputation_after) = module_after.reputation.clone() {
            let mut book = self.module_witnesses.write();
            book.record_reputation(ReputationWitness::new(
                updated_account.address.clone(),
                ReputationEventKind::ConsensusReward,
                module_before.reputation,
                reputation_after,
            ));
        }
        Ok(())
    }

    pub fn global_commitments(&self) -> GlobalStateCommitments {
        GlobalStateCommitments {
            global_state_root: self.state_root(),
            utxo_root: self.utxo_state.commitment(),
            reputation_root: self.reputation_state.commitment(),
            timetoke_root: self.timetoke_state.commitment(),
            zsi_root: self.zsi_registry.commitment(),
            proof_root: self.proof_registry.commitment(),
        }
    }

    pub fn drain_module_witnesses(&self) -> ModuleWitnessBundle {
        self.module_witnesses.write().drain()
    }

    pub fn stage_module_witnesses(
        &self,
        bundle: &ModuleWitnessBundle,
    ) -> ChainResult<Vec<ProofArtifact>> {
        let artifacts = bundle
            .expected_artifacts()?
            .into_iter()
            .map(|(module, commitment, payload)| ProofArtifact {
                module,
                commitment,
                proof: payload,
                verification_key: None,
            })
            .collect::<Vec<_>>();
        for artifact in &artifacts {
            self.proof_registry.register(artifact.clone());
        }
        Ok(artifacts)
    }

    pub fn record_consensus_witness(&self, height: u64, round: u64, participants: Vec<Address>) {
        let witness = ConsensusWitness::new(height, round, participants);
        let mut book = self.module_witnesses.write();
        book.record_consensus(witness);
    }

    pub fn state_root(&self) -> [u8; 32] {
        self.global_state.state_root()
    }

    pub fn slashing_events(&self, limit: usize) -> Vec<SlashingEvent> {
        let log = self.slashing_log.read();
        let start = log.len().saturating_sub(limit);
        log[start..].to_vec()
    }

    pub fn reputation_audit(&self, address: &str) -> ChainResult<Option<ReputationAudit>> {
        let accounts = self.global_state.read_accounts();
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

    fn index_account_modules(&self, account: &Account) {
        self.reputation_state.upsert_from_account(account);
        self.timetoke_state.upsert_from_account(account);
        self.zsi_registry.upsert_from_account(account);
        self.utxo_state.upsert_from_account(account);
    }
}

#[derive(Default, Clone)]
struct ModuleRecordSnapshots {
    utxo: Option<UtxoRecord>,
    reputation: Option<ReputationRecord>,
    timetoke: Option<TimetokeRecord>,
    zsi: Option<ZsiRecord>,
}

impl ModuleRecordSnapshots {
    fn empty() -> Self {
        Self::default()
    }
}

#[derive(Default)]
struct ModuleWitnessBook {
    transactions: Vec<TransactionWitness>,
    timetoke: Vec<TimetokeWitness>,
    reputation: Vec<ReputationWitness>,
    zsi: Vec<ZsiWitness>,
    consensus: Vec<ConsensusWitness>,
}

impl ModuleWitnessBook {
    fn record_transaction(&mut self, witness: TransactionWitness) {
        self.transactions.push(witness);
    }

    fn record_timetoke(&mut self, witness: TimetokeWitness) {
        self.timetoke.push(witness);
    }

    fn record_reputation(&mut self, witness: ReputationWitness) {
        self.reputation.push(witness);
    }

    fn record_zsi(&mut self, witness: ZsiWitness) {
        self.zsi.push(witness);
    }

    fn record_consensus(&mut self, witness: ConsensusWitness) {
        self.consensus.push(witness);
    }

    fn drain(&mut self) -> ModuleWitnessBundle {
        ModuleWitnessBundle {
            transactions: mem::take(&mut self.transactions),
            timetoke: mem::take(&mut self.timetoke),
            reputation: mem::take(&mut self.reputation),
            zsi: mem::take(&mut self.zsi),
            consensus: mem::take(&mut self.consensus),
        }
    }
}

fn derive_epoch_nonce(epoch: u64, state_root: &[u8; 32]) -> [u8; 32] {
    let mut data = Vec::with_capacity(EPOCH_NONCE_DOMAIN.len() + 8 + state_root.len());
    data.extend_from_slice(EPOCH_NONCE_DOMAIN);
    data.extend_from_slice(&epoch.to_le_bytes());
    data.extend_from_slice(state_root);
    Blake2sHasher::hash(&data).into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::consensus::evaluate_vrf;
    use crate::crypto::address_from_public_key;
    use crate::rpp::{
        AccountBalanceWitness, ConsensusWitness, ModuleWitnessBundle, ProofModule,
        ReputationEventKind, ReputationRecord, ReputationWitness, TierDescriptor, TimetokeRecord,
        TimetokeWitness, TransactionWitness, ZsiRecord, ZsiWitness,
    };
    use crate::stwo::circuit::StarkCircuit;
    use crate::stwo::circuit::identity::{IdentityCircuit, IdentityWitness};
    use crate::stwo::circuit::string_to_field;
    use crate::stwo::fri::FriProver;
    use crate::stwo::params::StarkParameters;
    use crate::stwo::proof::{ProofKind, ProofPayload, StarkProof};
    use crate::types::{
        ChainProof, IdentityDeclaration, IdentityGenesis, IdentityProof, SignedTransaction,
        Transaction, UptimeProof,
    };
    use ed25519_dalek::{Keypair, PublicKey, SecretKey, Signer};
    use std::collections::{HashMap, HashSet};
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
                zk_proof: ChainProof::Stwo(proof),
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

    #[test]
    fn apply_uptime_proof_updates_timetokes() {
        let ledger = Ledger::new(DEFAULT_EPOCH_LENGTH);
        let address = "cafebabe".repeat(4);
        let mut account = Account::new(address.clone(), 0, Stake::default());
        account.reputation.bind_genesis_identity("genesis-proof");
        ledger.upsert_account(account).unwrap();

        let window_start = 3_600;
        let window_end = 10_800;
        let proof = UptimeProof::legacy(address.clone(), window_start, window_end);

        let total_hours = ledger.apply_uptime_proof(&proof).unwrap();
        assert_eq!(total_hours, 2);
        let account = ledger.get_account(&address).unwrap();
        assert_eq!(account.reputation.timetokes.hours_online, 2);
        assert_eq!(
            account.reputation.timetokes.last_proof_timestamp,
            window_end
        );
    }

    #[test]
    fn reject_duplicate_uptime_proofs() {
        let ledger = Ledger::new(DEFAULT_EPOCH_LENGTH);
        let address = "feedface".repeat(4);
        let mut account = Account::new(address.clone(), 0, Stake::default());
        account.reputation.bind_genesis_identity("genesis-proof");
        ledger.upsert_account(account).unwrap();

        let first_start = 1_000;
        let first_end = first_start + 3_600;
        let proof = UptimeProof::legacy(address.clone(), first_start, first_end);

        ledger.apply_uptime_proof(&proof).unwrap();

        let duplicate = UptimeProof::legacy(address.clone(), first_start, first_end);

        let err = ledger.apply_uptime_proof(&duplicate).unwrap_err();
        assert!(matches!(err, ChainError::Transaction(_)));
    }

    #[test]
    fn uptime_proof_only_counts_new_hours() {
        let ledger = Ledger::new(DEFAULT_EPOCH_LENGTH);
        let address = "decafbad".repeat(4);
        let mut account = Account::new(address.clone(), 0, Stake::default());
        account.reputation.bind_genesis_identity("genesis-proof");
        ledger.upsert_account(account).unwrap();

        let first_start = 0;
        let first_end = 3_600;
        let first_proof = UptimeProof::legacy(address.clone(), first_start, first_end);

        ledger.apply_uptime_proof(&first_proof).unwrap();

        // Second proof overlaps the first hour but extends for two additional hours.
        let second_start = 1_800; // overlaps with the already credited hour
        let second_end = 10_800; // extends two new hours beyond the first proof
        let mut second_proof = UptimeProof::legacy(address.clone(), second_start, second_end);
        second_proof.node_clock = Some(second_end);
        second_proof.epoch = Some(0);
        second_proof.head_hash = Some(hex::encode([0u8; 32]));

        let total_hours = ledger.apply_uptime_proof(&second_proof).unwrap();
        assert_eq!(total_hours, 3);
        let account = ledger.get_account(&address).unwrap();
        assert_eq!(account.reputation.timetokes.hours_online, 3);
    }

    fn sample_witness_bundle() -> ModuleWitnessBundle {
        let mut bundle = ModuleWitnessBundle::default();

        let sender_before = AccountBalanceWitness::new("alice".into(), 1_000, 1);
        let sender_after = AccountBalanceWitness::new("alice".into(), 900, 2);
        let recipient_before = AccountBalanceWitness::new("bob".into(), 500, 0);
        let recipient_after = AccountBalanceWitness::new("bob".into(), 600, 0);
        let tx_witness = TransactionWitness::new(
            [0x11; 32],
            10,
            sender_before,
            sender_after,
            Some(recipient_before),
            recipient_after,
            None,
            None,
            None,
            None,
        );
        bundle.record_transaction(tx_witness);

        let previous_timetoke = TimetokeRecord {
            identity: "alice".into(),
            balance: 10,
            epoch_accrual: 1,
            decay_rate: 0.0,
            last_update: 100,
        };
        let updated_timetoke = TimetokeRecord {
            identity: "alice".into(),
            balance: 12,
            epoch_accrual: 3,
            decay_rate: 0.0,
            last_update: 200,
        };
        bundle.record_timetoke(TimetokeWitness::new(
            "alice".into(),
            Some(previous_timetoke),
            updated_timetoke,
            0,
            3_600,
            2,
        ));

        let previous_reputation = ReputationRecord {
            identity: "alice".into(),
            score: 1.0,
            tier: TierDescriptor::Candidate,
            uptime_hours: 1,
            consensus_success: 1,
            peer_feedback: 0,
            zsi_validated: true,
        };
        let updated_reputation = ReputationRecord {
            identity: "alice".into(),
            score: 2.5,
            tier: TierDescriptor::Validator,
            uptime_hours: 3,
            consensus_success: 2,
            peer_feedback: 1,
            zsi_validated: true,
        };
        bundle.record_reputation(ReputationWitness::new(
            "alice".into(),
            ReputationEventKind::ConsensusReward,
            Some(previous_reputation),
            updated_reputation,
        ));

        let zsi_updated = ZsiRecord {
            identity: "alice".into(),
            genesis_id: "genesis".into(),
            attestation_digest: [0x22; 32],
            approvals: Vec::new(),
        };
        bundle.record_zsi(ZsiWitness::new("alice".into(), None, zsi_updated));

        bundle.record_consensus(ConsensusWitness::new(
            42,
            3,
            vec!["alice".into(), "bob".into()],
        ));

        bundle
    }

    #[test]
    fn staging_module_witnesses_updates_proof_root() {
        let ledger = Ledger::new(DEFAULT_EPOCH_LENGTH);
        let initial_root = ledger.global_commitments().proof_root;

        let bundle = sample_witness_bundle();
        let expected = bundle.expected_artifacts().expect("expected artifacts");
        let staged = ledger
            .stage_module_witnesses(&bundle)
            .expect("stage witnesses");

        assert_eq!(staged.len(), expected.len());
        let mut expected_map = HashMap::new();
        for (module, digest, payload) in expected {
            expected_map.insert(module, (digest, payload));
        }
        for artifact in &staged {
            let (digest, payload) = expected_map
                .get(&artifact.module)
                .expect("artifact present");
            assert_eq!(&artifact.commitment, digest);
            assert_eq!(&artifact.proof, payload);
        }

        let updated_root = ledger.global_commitments().proof_root;
        assert_ne!(updated_root, initial_root);
        assert_ne!(updated_root, [0u8; 32]);

        let modules = staged
            .iter()
            .map(|artifact| artifact.module)
            .collect::<HashSet<_>>();
        for required in [
            ProofModule::UtxoWitness,
            ProofModule::TimetokeWitness,
            ProofModule::ReputationWitness,
            ProofModule::ZsiWitness,
            ProofModule::BlockWitness,
            ProofModule::ConsensusWitness,
        ] {
            assert!(modules.contains(&required));
        }
    }
}
