use std::collections::VecDeque;
use std::sync::Arc;
use std::time::Duration;

use ed25519_dalek::Keypair;
use malachite::Natural;
use parking_lot::RwLock;
use tokio::time;
use tracing::{info, warn};

use crate::config::{GenesisAccount, NodeConfig};
use crate::consensus::{
    ConsensusCertificate, ConsensusRound, aggregate_total_stake, classify_participants,
    evaluate_vrf,
};
use crate::crypto::{address_from_public_key, load_or_generate_keypair, sign_message};
use crate::errors::{ChainError, ChainResult};
use crate::ledger::{Ledger, compute_merkle_root};
use crate::reputation::Tier;
use crate::storage::Storage;
use crate::stwo::proof::{ProofPayload, StarkProof};
use crate::stwo::prover::{StarkProver, WalletProver};
use crate::stwo::verifier::{NodeVerifier, StarkVerifier};
use crate::types::{
    Account, Address, Block, BlockHeader, BlockStarkProofs, PruningProof, RecursiveProof,
    SignedTransaction, TransactionProofBundle,
};

const BASE_BLOCK_REWARD: u64 = 5;

#[derive(Clone, Copy)]
struct ChainTip {
    height: u64,
    last_hash: [u8; 32],
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
    chain_tip: RwLock<ChainTip>,
    block_interval: Duration,
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
        if storage.tip()?.is_none() {
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
            let ledger = Ledger::load(accounts.clone());
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
            let state_witness = prover.build_state_witness(
                &pruning_proof.previous_state_root,
                &header.state_root,
                &transactions,
            )?;
            let state_proof = prover.prove_state_transition(state_witness)?;
            let pruning_witness =
                prover.build_pruning_witness(&transactions, &pruning_proof, Vec::new());
            let pruning_stark = prover.prove_pruning(pruning_witness)?;
            let recursive_witness = prover.build_recursive_witness(
                None,
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
                pruning_proof,
                recursive_proof,
                stark_bundle,
                signature,
                consensus_certificate,
            );
            genesis_block.verify(None)?;
            storage.store_block(&genesis_block)?;
        }

        if accounts.is_empty() {
            accounts = storage.load_accounts()?;
        }

        let ledger = Ledger::load(accounts);

        let inner = Arc::new(NodeInner {
            block_interval: Duration::from_millis(config.block_time_ms),
            config,
            keypair,
            address,
            storage,
            ledger,
            mempool: RwLock::new(VecDeque::new()),
            chain_tip: RwLock::new(ChainTip {
                height: 0,
                last_hash: [0u8; 32],
            }),
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

    pub fn get_block(&self, height: u64) -> ChainResult<Option<Block>> {
        self.inner.get_block(height)
    }

    pub fn latest_block(&self) -> ChainResult<Option<Block>> {
        self.inner.latest_block()
    }

    pub fn get_account(&self, address: &str) -> ChainResult<Option<Account>> {
        self.inner.get_account(address)
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

    fn produce_block(&self) -> ChainResult<()> {
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
        if pending.is_empty() {
            return Ok(());
        }
        let tip_snapshot = *self.chain_tip.read();
        let accounts_snapshot = self.ledger.accounts_snapshot();
        let (validators, observers) = classify_participants(&accounts_snapshot);
        let mut round = ConsensusRound::new(
            tip_snapshot.height + 1,
            tip_snapshot.last_hash,
            validators,
            observers,
        );
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

        if accepted.is_empty() {
            return Ok(());
        }

        let block_reward = BASE_BLOCK_REWARD.saturating_add(total_fees);
        self.ledger.reward_proposer(&self.address, block_reward);

        let (transactions, transaction_proofs): (Vec<SignedTransaction>, Vec<_>) = accepted
            .into_iter()
            .map(|bundle| (bundle.transaction, bundle.proof))
            .unzip();

        let mut tx_hashes = transactions.iter().map(|tx| tx.hash()).collect::<Vec<_>>();
        let tx_root = compute_merkle_root(&mut tx_hashes);
        let state_root = self.ledger.state_root();
        let height = tip_snapshot.height + 1;
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
            &transactions,
        )?;
        let state_proof = prover.prove_state_transition(state_witness)?;

        let previous_transactions = previous_block
            .as_ref()
            .map(|block| block.transactions.clone())
            .unwrap_or_default();
        let pruning_witness =
            prover.build_pruning_witness(&previous_transactions, &pruning_proof, Vec::new());
        let pruning_stark = prover.prove_pruning(pruning_witness)?;

        let previous_recursive_stark = previous_block
            .as_ref()
            .map(|block| &block.stark.recursive_proof);
        let recursive_witness = prover.build_recursive_witness(
            previous_recursive_stark,
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
        let validator_addresses = round
            .validators()
            .iter()
            .map(|validator| validator.address.clone())
            .collect::<Vec<_>>();
        for address in &validator_addresses {
            round.register_prevote(address);
        }
        for address in &validator_addresses {
            round.register_precommit(address);
        }
        if !round.commit_reached() {
            warn!("quorum not reached for commit");
            return Ok(());
        }
        let consensus_certificate = round.certificate();
        let block = Block::new(
            header,
            transactions,
            pruning_proof,
            recursive_proof,
            stark_bundle,
            signature,
            consensus_certificate,
        );
        block.verify(previous_block.as_ref())?;
        self.storage.store_block(&block)?;
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
            let mut account = Account::new(entry.address, entry.balance, stake);
            account.reputation.tier = Tier::Tl3;
            account.reputation.score = 1.0;
            Ok(account)
        })
        .collect()
}
