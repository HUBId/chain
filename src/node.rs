use std::collections::VecDeque;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use ed25519_dalek::Keypair;
use malachite::Natural;
use parking_lot::RwLock;
use tokio::time;
use tracing::{info, warn};

use hex;
use serde::Serialize;

use crate::config::{GenesisAccount, NodeConfig};
use crate::consensus::{
    BftVote, BftVoteKind, ConsensusCertificate, ConsensusRound, SignedBftVote,
    aggregate_total_stake, classify_participants, evaluate_vrf,
};
use crate::crypto::{
    address_from_public_key, load_or_generate_keypair, sign_message, signature_to_hex,
};
use crate::errors::{ChainError, ChainResult};
use crate::ledger::{
    EpochInfo, Ledger, ReputationAudit, SlashingEvent, SlashingReason, compute_merkle_root,
};
use crate::storage::Storage;
use crate::stwo::proof::{ProofPayload, StarkProof};
use crate::stwo::prover::{StarkProver, WalletProver};
use crate::stwo::verifier::{NodeVerifier, StarkVerifier};
use crate::types::{
    Account, Address, Block, BlockHeader, BlockMetadata, BlockStarkProofs, IdentityDeclaration,
    PruningProof, RecursiveProof, SignedTransaction, Stake, TransactionProofBundle,
};

const BASE_BLOCK_REWARD: u64 = 5;

#[derive(Clone, Copy)]
struct ChainTip {
    height: u64,
    last_hash: [u8; 32],
}

#[derive(Clone, Debug, Serialize)]
pub struct NodeStatus {
    pub address: Address,
    pub height: u64,
    pub last_hash: String,
    pub epoch: u64,
    pub epoch_nonce: String,
    pub pending_transactions: usize,
    pub pending_identities: usize,
    pub pending_votes: usize,
}

#[derive(Clone, Debug, Serialize)]
pub struct PendingTransactionSummary {
    pub hash: String,
    pub from: Address,
    pub to: Address,
    pub amount: u128,
    pub fee: u64,
    pub nonce: u64,
}

#[derive(Clone, Debug, Serialize)]
pub struct PendingIdentitySummary {
    pub wallet_addr: Address,
    pub commitment: String,
    pub epoch_nonce: String,
    pub state_root: String,
    pub identity_root: String,
    pub vrf_tag: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct PendingVoteSummary {
    pub hash: String,
    pub voter: Address,
    pub height: u64,
    pub round: u64,
    pub block_hash: String,
    pub kind: BftVoteKind,
}

#[derive(Clone, Debug, Serialize)]
pub struct MempoolStatus {
    pub transactions: Vec<PendingTransactionSummary>,
    pub identities: Vec<PendingIdentitySummary>,
    pub votes: Vec<PendingVoteSummary>,
}

#[derive(Clone, Debug, Serialize)]
pub struct ConsensusStatus {
    pub height: u64,
    pub block_hash: Option<String>,
    pub proposer: Option<Address>,
    pub round: u64,
    pub total_power: String,
    pub quorum_threshold: String,
    pub pre_vote_power: String,
    pub pre_commit_power: String,
    pub commit_power: String,
    pub quorum_reached: bool,
    pub observers: u64,
    pub epoch: u64,
    pub epoch_nonce: String,
    pub pending_votes: usize,
}

#[derive(Clone, Debug, Serialize)]
pub struct VrfStatus {
    pub address: Address,
    pub epoch: u64,
    pub epoch_nonce: String,
    pub proof: crate::consensus::VrfProof,
}

pub struct Node {
    inner: Arc<NodeInner>,
}

struct NodeInner {
    config: NodeConfig,
    keypair: Keypair,
    address: Address,
    storage: Storage,
    ledger: Ledger,
    mempool: RwLock<VecDeque<TransactionProofBundle>>,
    identity_mempool: RwLock<VecDeque<IdentityDeclaration>>,
    chain_tip: RwLock<ChainTip>,
    block_interval: Duration,
    vote_mempool: RwLock<VecDeque<SignedBftVote>>,
}

#[derive(Clone)]
pub struct NodeHandle {
    inner: Arc<NodeInner>,
}

impl Node {
    pub fn new(config: NodeConfig) -> ChainResult<Self> {
        config.ensure_directories()?;
        let keypair = load_or_generate_keypair(&config.key_path)?;
        let address = address_from_public_key(&keypair.public);
        let db_path = config.data_dir.join("db");
        let storage = Storage::open(&db_path)?;
        let mut accounts = storage.load_accounts()?;
        let mut tip_metadata = storage.tip()?;
        if tip_metadata.is_none() {
            let genesis_accounts = if config.genesis.accounts.is_empty() {
                vec![GenesisAccount {
                    address: address.clone(),
                    balance: 1_000_000_000,
                    stake: "1000".to_string(),
                }]
            } else {
                config.genesis.accounts.clone()
            };
            accounts = build_genesis_accounts(genesis_accounts)?;
            for account in &accounts {
                storage.persist_account(account)?;
            }
            let ledger = Ledger::load(accounts.clone(), config.epoch_length);
            let mut tx_hashes: Vec<[u8; 32]> = Vec::new();
            let tx_root = compute_merkle_root(&mut tx_hashes);
            let state_root = ledger.state_root();
            let state_root_hex = hex::encode(state_root);
            let stakes = ledger.stake_snapshot();
            let total_stake = aggregate_total_stake(&stakes);
            let genesis_seed = [0u8; 32];
            let vrf = evaluate_vrf(&genesis_seed, 0, &address);
            let header = BlockHeader::new(
                0,
                hex::encode([0u8; 32]),
                hex::encode(tx_root),
                state_root_hex.clone(),
                total_stake.to_string(),
                vrf.randomness.to_string(),
                vrf.proof.clone(),
                address.clone(),
            );
            let pruning_proof = PruningProof::genesis(&state_root_hex);
            let recursive_proof = RecursiveProof::genesis(&header, &pruning_proof);
            let prover = WalletProver::new(&storage);
            let transactions: Vec<SignedTransaction> = Vec::new();
            let transaction_proofs: Vec<StarkProof> = Vec::new();
            let identity_proofs: Vec<StarkProof> = Vec::new();
            let state_witness = prover.build_state_witness(
                &pruning_proof.previous_state_root,
                &header.state_root,
                &Vec::new(),
                &transactions,
            )?;
            let state_proof = prover.prove_state_transition(state_witness)?;
            let pruning_witness = prover.build_pruning_witness(
                &Vec::new(),
                &transactions,
                &pruning_proof,
                Vec::new(),
            )?;
            let pruning_stark = prover.prove_pruning(pruning_witness)?;
            let recursive_witness = prover.build_recursive_witness(
                None,
                &identity_proofs,
                &transaction_proofs,
                &state_proof,
                &pruning_stark,
                header.height,
            )?;
            let recursive_stark = prover.prove_recursive(recursive_witness)?;
            let stark_bundle = BlockStarkProofs::new(
                transaction_proofs,
                state_proof,
                pruning_stark,
                recursive_stark,
            );
            let signature = sign_message(&keypair, &header.canonical_bytes());
            let consensus_certificate = ConsensusCertificate::genesis();
            let genesis_block = Block::new(
                header,
                Vec::new(),
                Vec::new(),
                pruning_proof,
                recursive_proof,
                stark_bundle,
                signature,
                consensus_certificate,
            );
            genesis_block.verify(None)?;
            storage.store_block(&genesis_block)?;
            tip_metadata = Some(BlockMetadata::from(&genesis_block));
        }

        if accounts.is_empty() {
            accounts = storage.load_accounts()?;
        }

        let ledger = Ledger::load(accounts, config.epoch_length);

        let node_pk_hex = hex::encode(keypair.public.to_bytes());
        if ledger.get_account(&address).is_none() {
            let mut account = Account::new(address.clone(), 0, Stake::default());
            let _ = account.ensure_wallet_binding(&node_pk_hex)?;
            ledger.upsert_account(account)?;
        }
        ledger.ensure_node_binding(&address, &node_pk_hex)?;

        let next_height = tip_metadata
            .as_ref()
            .map(|meta| meta.height.saturating_add(1))
            .unwrap_or(0);
        ledger.sync_epoch_for_height(next_height);

        let inner = Arc::new(NodeInner {
            block_interval: Duration::from_millis(config.block_time_ms),
            config,
            keypair,
            address,
            storage,
            ledger,
            mempool: RwLock::new(VecDeque::new()),
            identity_mempool: RwLock::new(VecDeque::new()),
            chain_tip: RwLock::new(ChainTip {
                height: 0,
                last_hash: [0u8; 32],
            }),
            vote_mempool: RwLock::new(VecDeque::new()),
        });
        inner.bootstrap()?;
        Ok(Self { inner })
    }

    pub fn handle(&self) -> NodeHandle {
        NodeHandle {
            inner: self.inner.clone(),
        }
    }

    pub async fn start(self) -> ChainResult<()> {
        self.inner.clone().run().await
    }
}

impl NodeHandle {
    pub fn submit_transaction(&self, bundle: TransactionProofBundle) -> ChainResult<String> {
        self.inner.submit_transaction(bundle)
    }

    pub fn submit_identity(&self, declaration: IdentityDeclaration) -> ChainResult<String> {
        self.inner.submit_identity(declaration)
    }

    pub fn submit_vote(&self, vote: SignedBftVote) -> ChainResult<String> {
        self.inner.submit_vote(vote)
    }

    pub fn get_block(&self, height: u64) -> ChainResult<Option<Block>> {
        self.inner.get_block(height)
    }

    pub fn latest_block(&self) -> ChainResult<Option<Block>> {
        self.inner.latest_block()
    }

    pub fn get_account(&self, address: &str) -> ChainResult<Option<Account>> {
        self.inner.get_account(address)
    }

    pub fn node_status(&self) -> ChainResult<NodeStatus> {
        self.inner.node_status()
    }

    pub fn mempool_status(&self) -> ChainResult<MempoolStatus> {
        self.inner.mempool_status()
    }

    pub fn consensus_status(&self) -> ChainResult<ConsensusStatus> {
        self.inner.consensus_status()
    }

    pub fn vrf_status(&self, address: &str) -> ChainResult<VrfStatus> {
        self.inner.vrf_status(address)
    }

    pub fn slashing_events(&self, limit: usize) -> ChainResult<Vec<SlashingEvent>> {
        self.inner.slashing_events(limit)
    }

    pub fn reputation_audit(&self, address: &str) -> ChainResult<Option<ReputationAudit>> {
        self.inner.reputation_audit(address)
    }

    pub fn address(&self) -> &str {
        &self.inner.address
    }
}

impl NodeInner {
    async fn run(self: Arc<Self>) -> ChainResult<()> {
        info!(address = %self.address, "starting node");
        let mut ticker = time::interval(self.block_interval);
        loop {
            ticker.tick().await;
            if let Err(err) = self.produce_block() {
                warn!(?err, "block production failed");
            }
        }
    }

    fn submit_transaction(&self, bundle: TransactionProofBundle) -> ChainResult<String> {
        bundle.transaction.verify()?;
        let verifier = NodeVerifier::new();
        verifier.verify_transaction(&bundle.proof)?;
        let witness_tx = match &bundle.proof.payload {
            ProofPayload::Transaction(witness) => &witness.signed_tx,
            _ => {
                return Err(ChainError::Crypto(
                    "transaction proof payload mismatch".into(),
                ));
            }
        };
        if witness_tx != &bundle.transaction {
            return Err(ChainError::Crypto(
                "transaction proof does not match submitted transaction".into(),
            ));
        }
        let mut mempool = self.mempool.write();
        if mempool.len() >= self.config.mempool_limit {
            return Err(ChainError::Transaction("mempool full".into()));
        }
        let tx_hash = bundle.hash();
        if mempool
            .iter()
            .any(|existing| existing.transaction.id == bundle.transaction.id)
        {
            return Err(ChainError::Transaction("transaction already queued".into()));
        }
        mempool.push_back(bundle);
        Ok(tx_hash)
    }

    fn submit_identity(&self, declaration: IdentityDeclaration) -> ChainResult<String> {
        let next_height = self.chain_tip.read().height.saturating_add(1);
        self.ledger.sync_epoch_for_height(next_height);
        let verifier = NodeVerifier::new();
        verifier.verify_identity(&declaration.proof.zk_proof)?;
        declaration.verify()?;

        let expected_epoch_nonce = hex::encode(self.ledger.current_epoch_nonce());
        if expected_epoch_nonce != declaration.genesis.epoch_nonce {
            return Err(ChainError::Transaction(
                "identity declaration references an outdated epoch nonce".into(),
            ));
        }

        let expected_state_root = hex::encode(self.ledger.state_root());
        if expected_state_root != declaration.genesis.state_root {
            return Err(ChainError::Transaction(
                "identity declaration references an outdated state root".into(),
            ));
        }
        let expected_identity_root = hex::encode(self.ledger.identity_root());
        if expected_identity_root != declaration.genesis.identity_root {
            return Err(ChainError::Transaction(
                "identity declaration references an outdated identity root".into(),
            ));
        }

        let hash = hex::encode(declaration.hash()?);
        let mut mempool = self.identity_mempool.write();
        if mempool.len() >= self.config.mempool_limit {
            return Err(ChainError::Transaction("identity mempool full".into()));
        }
        if mempool
            .iter()
            .any(|existing| existing.genesis.wallet_addr == declaration.genesis.wallet_addr)
        {
            return Err(ChainError::Transaction(
                "identity for this wallet already queued".into(),
            ));
        }
        mempool.push_back(declaration);
        Ok(hash)
    }

    fn submit_vote(&self, vote: SignedBftVote) -> ChainResult<String> {
        vote.verify()?;
        let next_height = self.chain_tip.read().height.saturating_add(1);
        if vote.vote.height < next_height {
            return Err(ChainError::Transaction(
                "vote references an already finalized height".into(),
            ));
        }
        let mut mempool = self.vote_mempool.write();
        if mempool.len() >= self.config.mempool_limit {
            return Err(ChainError::Transaction("vote mempool full".into()));
        }
        let vote_hash = vote.hash();
        if mempool.iter().any(|existing| existing.hash() == vote_hash) {
            return Err(ChainError::Transaction("vote already queued".into()));
        }
        mempool.push_back(vote);
        Ok(vote_hash)
    }

    fn get_block(&self, height: u64) -> ChainResult<Option<Block>> {
        self.storage.read_block(height)
    }

    fn latest_block(&self) -> ChainResult<Option<Block>> {
        let tip_height = self.chain_tip.read().height;
        self.storage.read_block(tip_height)
    }

    fn get_account(&self, address: &str) -> ChainResult<Option<Account>> {
        Ok(self.ledger.get_account(address))
    }

    fn node_status(&self) -> ChainResult<NodeStatus> {
        let tip = *self.chain_tip.read();
        let epoch_info: EpochInfo = self.ledger.epoch_info();
        Ok(NodeStatus {
            address: self.address.clone(),
            height: tip.height,
            last_hash: hex::encode(tip.last_hash),
            epoch: epoch_info.epoch,
            epoch_nonce: epoch_info.epoch_nonce,
            pending_transactions: self.mempool.read().len(),
            pending_identities: self.identity_mempool.read().len(),
            pending_votes: self.vote_mempool.read().len(),
        })
    }

    fn mempool_status(&self) -> ChainResult<MempoolStatus> {
        let transactions = self
            .mempool
            .read()
            .iter()
            .map(|bundle| PendingTransactionSummary {
                hash: bundle.hash(),
                from: bundle.transaction.payload.from.clone(),
                to: bundle.transaction.payload.to.clone(),
                amount: bundle.transaction.payload.amount,
                fee: bundle.transaction.payload.fee,
                nonce: bundle.transaction.payload.nonce,
            })
            .collect();
        let identities = self
            .identity_mempool
            .read()
            .iter()
            .map(|declaration| PendingIdentitySummary {
                wallet_addr: declaration.genesis.wallet_addr.clone(),
                commitment: declaration.commitment().to_string(),
                epoch_nonce: declaration.genesis.epoch_nonce.clone(),
                state_root: declaration.genesis.state_root.clone(),
                identity_root: declaration.genesis.identity_root.clone(),
                vrf_tag: declaration.genesis.vrf_tag.clone(),
            })
            .collect();
        let votes = self
            .vote_mempool
            .read()
            .iter()
            .map(|vote| PendingVoteSummary {
                hash: vote.hash(),
                voter: vote.vote.voter.clone(),
                height: vote.vote.height,
                round: vote.vote.round,
                block_hash: vote.vote.block_hash.clone(),
                kind: vote.vote.kind,
            })
            .collect();
        Ok(MempoolStatus {
            transactions,
            identities,
            votes,
        })
    }

    fn consensus_status(&self) -> ChainResult<ConsensusStatus> {
        let tip = *self.chain_tip.read();
        let block = self.storage.read_block(tip.height)?;
        let epoch_info = self.ledger.epoch_info();
        let pending_votes = self.vote_mempool.read().len();
        let (
            block_hash,
            proposer,
            round,
            total_power,
            quorum_threshold,
            pre_vote_power,
            pre_commit_power,
            commit_power,
            observers,
            quorum_reached,
        ) = if let Some(block) = block.as_ref() {
            let certificate = &block.consensus;
            let commit = Natural::from_str(&certificate.commit_power)
                .unwrap_or_else(|_| Natural::from(0u32));
            let quorum = Natural::from_str(&certificate.quorum_threshold)
                .unwrap_or_else(|_| Natural::from(0u32));
            (
                Some(block.hash.clone()),
                Some(block.header.proposer.clone()),
                certificate.round,
                certificate.total_power.clone(),
                certificate.quorum_threshold.clone(),
                certificate.pre_vote_power.clone(),
                certificate.pre_commit_power.clone(),
                certificate.commit_power.clone(),
                certificate.observers,
                commit >= quorum && commit > Natural::from(0u32),
            )
        } else {
            (
                None,
                None,
                0,
                "0".to_string(),
                "0".to_string(),
                "0".to_string(),
                "0".to_string(),
                "0".to_string(),
                0,
                false,
            )
        };

        Ok(ConsensusStatus {
            height: tip.height,
            block_hash,
            proposer,
            round,
            total_power,
            quorum_threshold,
            pre_vote_power,
            pre_commit_power,
            commit_power,
            quorum_reached,
            observers,
            epoch: epoch_info.epoch,
            epoch_nonce: epoch_info.epoch_nonce,
            pending_votes,
        })
    }

    fn vrf_status(&self, address: &str) -> ChainResult<VrfStatus> {
        let epoch_info = self.ledger.epoch_info();
        let nonce = self.ledger.current_epoch_nonce();
        let proof = evaluate_vrf(&nonce, 0, &address.to_string());
        Ok(VrfStatus {
            address: address.to_string(),
            epoch: epoch_info.epoch,
            epoch_nonce: epoch_info.epoch_nonce,
            proof,
        })
    }

    fn slashing_events(&self, limit: usize) -> ChainResult<Vec<SlashingEvent>> {
        Ok(self.ledger.slashing_events(limit))
    }

    fn reputation_audit(&self, address: &str) -> ChainResult<Option<ReputationAudit>> {
        self.ledger.reputation_audit(address)
    }

    fn build_local_vote(
        &self,
        height: u64,
        round: u64,
        block_hash: &str,
        kind: BftVoteKind,
    ) -> SignedBftVote {
        let vote = BftVote {
            round,
            height,
            block_hash: block_hash.to_string(),
            voter: self.address.clone(),
            kind,
        };
        let signature = sign_message(&self.keypair, &vote.message_bytes());
        SignedBftVote {
            vote,
            public_key: hex::encode(self.keypair.public.to_bytes()),
            signature: signature_to_hex(&signature),
        }
    }

    fn drain_votes_for(&self, height: u64, block_hash: &str) -> Vec<SignedBftVote> {
        let mut mempool = self.vote_mempool.write();
        let mut retained = VecDeque::new();
        let mut matched = Vec::new();
        while let Some(vote) = mempool.pop_front() {
            if vote.vote.height == height && vote.vote.block_hash == block_hash {
                matched.push(vote);
            } else {
                retained.push_back(vote);
            }
        }
        *mempool = retained;
        matched
    }

    fn produce_block(&self) -> ChainResult<()> {
        let mut identity_pending: Vec<IdentityDeclaration> = Vec::new();
        {
            let mut mempool = self.identity_mempool.write();
            while identity_pending.len() < self.config.max_block_identity_registrations {
                if let Some(declaration) = mempool.pop_front() {
                    identity_pending.push(declaration);
                } else {
                    break;
                }
            }
        }

        let mut pending: Vec<TransactionProofBundle> = Vec::new();
        {
            let mut mempool = self.mempool.write();
            while pending.len() < self.config.max_block_transactions {
                if let Some(tx) = mempool.pop_front() {
                    pending.push(tx);
                } else {
                    break;
                }
            }
        }
        if pending.is_empty() && identity_pending.is_empty() {
            return Ok(());
        }
        let tip_snapshot = *self.chain_tip.read();
        let height = tip_snapshot.height + 1;
        self.ledger.sync_epoch_for_height(height);
        let accounts_snapshot = self.ledger.accounts_snapshot();
        let (validators, observers) = classify_participants(&accounts_snapshot);
        let mut round = ConsensusRound::new(height, tip_snapshot.last_hash, validators, observers);
        let selection = match round.select_proposer() {
            Some(selection) => selection,
            None => {
                warn!("no proposer could be selected");
                return Ok(());
            }
        };
        if selection.proposer != self.address {
            info!(proposer = %selection.proposer, "not elected proposer for this round");
            return Ok(());
        }
        if round.total_power().clone() == Natural::from(0u32) {
            warn!("validator set has no voting power");
            return Ok(());
        }

        let mut accepted_identities: Vec<IdentityDeclaration> = Vec::new();
        for declaration in identity_pending {
            match self.ledger.register_identity(declaration.clone()) {
                Ok(_) => accepted_identities.push(declaration),
                Err(err) => {
                    warn!(?err, "dropping invalid identity declaration");
                    if let Err(slash_err) = self
                        .ledger
                        .slash_validator(&self.address, SlashingReason::InvalidIdentity)
                    {
                        warn!(?slash_err, "failed to slash proposer for invalid identity");
                    }
                }
            }
        }

        let mut accepted: Vec<TransactionProofBundle> = Vec::new();
        let mut total_fees: u64 = 0;
        for bundle in pending {
            match self.ledger.apply_transaction(&bundle.transaction) {
                Ok(fee) => {
                    total_fees = total_fees.saturating_add(fee);
                    accepted.push(bundle);
                }
                Err(err) => warn!(?err, "dropping invalid transaction"),
            }
        }

        if accepted.is_empty() && accepted_identities.is_empty() {
            return Ok(());
        }

        let block_reward = BASE_BLOCK_REWARD.saturating_add(total_fees);
        self.ledger.reward_proposer(&self.address, block_reward)?;

        let (transactions, transaction_proofs): (Vec<SignedTransaction>, Vec<_>) = accepted
            .into_iter()
            .map(|bundle| (bundle.transaction, bundle.proof))
            .unzip();

        let identity_proofs: Vec<StarkProof> = accepted_identities
            .iter()
            .map(|declaration| declaration.proof.zk_proof.clone())
            .collect();

        let mut operation_hashes = Vec::new();
        for declaration in &accepted_identities {
            operation_hashes.push(declaration.hash()?);
        }
        for tx in &transactions {
            operation_hashes.push(tx.hash());
        }
        let tx_root = compute_merkle_root(&mut operation_hashes);
        let state_root = self.ledger.state_root();
        let header = BlockHeader::new(
            height,
            hex::encode(tip_snapshot.last_hash),
            hex::encode(tx_root),
            hex::encode(state_root),
            selection.total_voting_power.to_string(),
            selection.randomness.to_string(),
            selection.proof.proof.clone(),
            self.address.clone(),
        );
        let block_hash_hex = hex::encode(header.hash());
        round.set_block_hash(block_hash_hex.clone());

        let local_prevote =
            self.build_local_vote(height, round.round(), &block_hash_hex, BftVoteKind::PreVote);
        round.register_prevote(&local_prevote)?;
        let local_precommit = self.build_local_vote(
            height,
            round.round(),
            &block_hash_hex,
            BftVoteKind::PreCommit,
        );
        round.register_precommit(&local_precommit)?;

        let external_votes = self.drain_votes_for(height, &block_hash_hex);
        for vote in external_votes {
            let result = match vote.vote.kind {
                BftVoteKind::PreVote => round.register_prevote(&vote),
                BftVoteKind::PreCommit => round.register_precommit(&vote),
            };
            if let Err(err) = result {
                warn!(?err, voter = %vote.vote.voter, "rejecting invalid consensus vote");
                if let Err(slash_err) = self
                    .ledger
                    .slash_validator(&vote.vote.voter, SlashingReason::InvalidVote)
                {
                    warn!(
                        ?slash_err,
                        voter = %vote.vote.voter,
                        "failed to slash validator for invalid vote"
                    );
                }
            }
        }

        let previous_block = self.storage.read_block(tip_snapshot.height)?;
        let pruning_proof = PruningProof::from_previous(previous_block.as_ref(), &header);
        let recursive_proof = match previous_block.as_ref() {
            Some(block) => RecursiveProof::extend(&block.recursive_proof, &header, &pruning_proof),
            None => RecursiveProof::genesis(&header, &pruning_proof),
        };

        let prover = WalletProver::new(&self.storage);
        let state_witness = prover.build_state_witness(
            &pruning_proof.previous_state_root,
            &header.state_root,
            &accepted_identities,
            &transactions,
        )?;
        let state_proof = prover.prove_state_transition(state_witness)?;

        let previous_transactions = previous_block
            .as_ref()
            .map(|block| block.transactions.clone())
            .unwrap_or_default();
        let previous_identities = previous_block
            .as_ref()
            .map(|block| block.identities.clone())
            .unwrap_or_default();
        let pruning_witness = prover.build_pruning_witness(
            &previous_identities,
            &previous_transactions,
            &pruning_proof,
            Vec::new(),
        )?;
        let pruning_stark = prover.prove_pruning(pruning_witness)?;

        let previous_recursive_stark = previous_block
            .as_ref()
            .map(|block| &block.stark.recursive_proof);
        let recursive_witness = prover.build_recursive_witness(
            previous_recursive_stark,
            &identity_proofs,
            &transaction_proofs,
            &state_proof,
            &pruning_stark,
            header.height,
        )?;
        let recursive_stark = prover.prove_recursive(recursive_witness)?;

        let stark_bundle = BlockStarkProofs::new(
            transaction_proofs,
            state_proof,
            pruning_stark,
            recursive_stark,
        );

        let signature = sign_message(&self.keypair, &header.canonical_bytes());
        if !round.commit_reached() {
            warn!("quorum not reached for commit");
            return Ok(());
        }
        let consensus_certificate = round.certificate();
        let block = Block::new(
            header,
            accepted_identities,
            transactions,
            pruning_proof,
            recursive_proof,
            stark_bundle,
            signature,
            consensus_certificate,
        );
        block.verify(previous_block.as_ref())?;
        self.storage.store_block(&block)?;
        self.ledger.sync_epoch_for_height(height.saturating_add(1));
        self.persist_accounts()?;
        let mut tip = self.chain_tip.write();
        tip.height = block.header.height;
        tip.last_hash = block.block_hash();
        info!(height = tip.height, "sealed block");
        Ok(())
    }

    fn persist_accounts(&self) -> ChainResult<()> {
        let accounts = self.ledger.accounts_snapshot();
        for account in accounts {
            self.storage.persist_account(&account)?;
        }
        Ok(())
    }

    fn bootstrap(&self) -> ChainResult<()> {
        if let Some(metadata) = self.storage.tip()? {
            let block = self
                .storage
                .read_block(metadata.height)?
                .ok_or_else(|| ChainError::Config("tip metadata missing block".into()))?;
            block.verify(None)?;
            let mut tip = self.chain_tip.write();
            tip.height = block.header.height;
            tip.last_hash = block.block_hash();
        } else {
            let mut tip = self.chain_tip.write();
            tip.height = 0;
            tip.last_hash = [0u8; 32];
        }
        Ok(())
    }
}

fn build_genesis_accounts(entries: Vec<GenesisAccount>) -> ChainResult<Vec<Account>> {
    entries
        .into_iter()
        .map(|entry| {
            let stake = entry.stake_value()?;
            Ok(Account::new(entry.address, entry.balance, stake))
        })
        .collect()
}
