use std::collections::{HashMap, HashSet};
use std::convert::TryFrom;
use std::sync::Arc;

use anyhow::{Context, Result, anyhow};
use serde_json;

use crate::vendor::electrs::chain::{Chain, NewHeader};
use crate::vendor::electrs::firewood_adapter::{FirewoodAdapter, RuntimeAdapters};
use crate::vendor::electrs::rpp_ledger::bitcoin::blockdata::{
    block::Header as LedgerBlockHeader, constants,
};
use crate::vendor::electrs::rpp_ledger::bitcoin::{BlockHash, Network, OutPoint, Script, Txid};
use crate::vendor::electrs::rpp_ledger::bitcoin_slices::bsl::Transaction as LedgerTransaction;
use crate::vendor::electrs::types::{
    encode_ledger_memo, encode_ledger_script, encode_transaction_metadata, HashPrefixRow,
    LedgerMemoPayload, LedgerScriptPayload, SerBlock, StoredTransactionMetadata, TxidRow,
    bsl_txid, serialize_block, serialize_transaction, HASH_PREFIX_ROW_SIZE,
};
use rpp::runtime::node::MempoolStatus;
use rpp::runtime::types::{
    Block as RuntimeBlock, BlockHeader as RuntimeBlockHeader, ChainProof, SignedTransaction,
};
use rpp::proofs::rpp::TransactionWitness;
use rpp_p2p::GossipTopic;
use sha2::{Digest, Sha512};
use tokio::sync::broadcast;

#[derive(Clone, Debug)]
pub struct ConvertedBlock {
    pub ledger_header: LedgerBlockHeader,
    pub ledger_transactions: Vec<LedgerTransaction>,
    pub runtime_header: RuntimeBlockHeader,
    pub runtime_transactions: Vec<SignedTransaction>,
    pub transaction_witnesses: Vec<TransactionWitness>,
    pub transaction_metadata: Vec<Option<Vec<u8>>>,
    #[cfg(feature = "backend-rpp-stark")]
    pub rpp_stark_proofs: Vec<Vec<u8>>,
}

/// Lightweight daemon harness that mimics a Bitcoin Core RPC backend.
///
/// The real electrs daemon talks to bitcoind over RPC and P2P. Within the
/// repository we only need a deterministic, in-memory source of blocks so that
/// higher level components (indexer, status tracker) can be exercised in tests.
/// This harness stores headers and transactions and exposes a subset of the
/// upstream electrs interface.
pub struct Daemon {
    firewood: FirewoodAdapter,
    runtime: RuntimeAdapters,
}

impl Daemon {
    /// Create a new daemon backed by the Firewood runtime.
    pub fn new(firewood: FirewoodAdapter) -> Result<Self> {
        let runtime = firewood
            .runtime()
            .cloned()
            .ok_or_else(|| anyhow!("firewood runtime adapters not attached"))?;

        Ok(Self { firewood, runtime })
    }

    /// Return the configured ledger network.
    pub fn network(&self) -> Network {
        Network::Regtest
    }

    /// Current best block hash tracked by the daemon.
    pub fn tip(&self) -> Result<BlockHash> {
        let latest = self
            .runtime
            .node()
            .latest_block()
            .map_err(|err| anyhow!("query latest block: {err}"))?;

        if let Some(block) = latest {
            let converted = Self::convert_block(&block);
            Ok(converted.ledger_header.block_hash())
        } else {
            let genesis = constants::genesis_block(self.network());
            Ok(genesis.header.block_hash())
        }
    }

    /// Height of the best block known to the daemon.
    pub fn height(&self) -> Result<usize> {
        let status = self
            .runtime
            .node()
            .node_status()
            .map_err(|err| anyhow!("query node status: {err}"))?;
        usize::try_from(status.height)
            .map_err(|_| anyhow!("runtime height {} exceeds usize", status.height))
    }

    /// List headers that extend the provided chain tip.
    pub(crate) fn get_new_headers(&self, chain: &Chain) -> Result<Vec<NewHeader>> {
        let start_height = chain
            .height()
            .checked_add(1)
            .ok_or_else(|| anyhow!("chain height overflow"))?;
        let runtime_headers = self
            .firewood
            .stream_headers_from(start_height as u64)
            .context("stream runtime headers")?;

        let mut headers = Vec::new();
        for header in runtime_headers {
            let height = usize::try_from(header.height).map_err(|_| {
                anyhow!(
                    "runtime header height {} exceeds addressable range",
                    header.height
                )
            })?;
            if height < start_height {
                continue;
            }
            let converted = Self::convert_runtime_header(&header);
            headers.push(NewHeader::from((converted, height)));
        }

        Ok(headers)
    }

    /// Snapshot all blocks that appear above the provided height.
    pub fn blocks_since(&self, height: usize) -> Result<Vec<ConvertedBlock>> {
        let start = height
            .checked_add(1)
            .ok_or_else(|| anyhow!("height overflow"))?;
        let tip = self.chain_tip_height()?;
        if (start as u64) > tip {
            return Ok(Vec::new());
        }

        self.collect_blocks(start as u64, tip)
    }

    /// Fetch a snapshot of the runtime mempool state.
    pub fn mempool_snapshot(&self) -> Result<MempoolStatus> {
        self.firewood.mempool_snapshot()
    }

    pub(crate) fn runtime(&self) -> &RuntimeAdapters {
        &self.runtime
    }

    pub(crate) fn firewood(&self) -> &FirewoodAdapter {
        &self.firewood
    }

    /// Iterate over blocks matching the supplied hashes and invoke `func` with
    /// their serialized representation.
    pub(crate) fn for_blocks<B, F>(&self, blockhashes: B, mut func: F) -> Result<()>
    where
        B: IntoIterator<Item = BlockHash>,
        F: FnMut(BlockHash, SerBlock),
    {
        let requested: Vec<BlockHash> = blockhashes.into_iter().collect();
        if requested.is_empty() {
            return Ok(());
        }

        let mut pending: HashSet<BlockHash> = requested.iter().copied().collect();
        let runtime_blocks = self
            .runtime
            .storage()
            .load_blockchain()
            .map_err(|err| anyhow!("load runtime blockchain: {err}"))?;

        let mut height_to_hash: HashMap<u64, BlockHash> = HashMap::new();
        let mut heights: Vec<u64> = Vec::new();
        for block in runtime_blocks {
            if pending.is_empty() {
                break;
            }
            let header = Self::convert_runtime_header(&block.header);
            let hash = header.block_hash();
            if pending.remove(&hash) {
                let height = block.header.height;
                height_to_hash.insert(height, hash);
                heights.push(height);
            }
        }

        if heights.is_empty() {
            return Ok(());
        }

        heights.sort_unstable();
        heights.dedup();

        let mut serialized_blocks: HashMap<BlockHash, SerBlock> = HashMap::new();
        let mut index = 0usize;
        while index < heights.len() {
            let mut start = heights[index];
            let mut end = start;
            while index + 1 < heights.len() && heights[index + 1] == end + 1 {
                index += 1;
                end = heights[index];
            }

            let blocks = self.reconstruct_verified_range(start, end)?;
            for block in blocks {
                let Some(expected_hash) = height_to_hash.get(&block.header.height) else {
                    continue;
                };
                let converted = Self::convert_block(&block);
                if converted.ledger_header.block_hash() != *expected_hash {
                    continue;
                }
                let serialized = serialize_block(&converted.ledger_transactions);
                serialized_blocks.entry(*expected_hash).or_insert(serialized);
            }

            index += 1;
        }

        for blockhash in requested {
            if let Some(serialized) = serialized_blocks.get(&blockhash) {
                func(blockhash, serialized.clone());
            }
        }
        Ok(())
    }

    /// Subscribe to new block notifications. Each call returns a dedicated
    /// receiver hooked into the runtime gossip pipeline.
    pub(crate) fn new_block_notification(&self) -> Result<broadcast::Receiver<Vec<u8>>> {
        self.firewood
            .subscribe_gossip(GossipTopic::Blocks)
            .context("subscribe to block gossip")
    }

    /// Find the serialized representation of `txid`, if the daemon knows about it.
    pub fn find_transaction(&self, txid: Txid) -> Option<(BlockHash, Box<[u8]>)> {
        const TXID_PREFIX: u8 = b't';
        let mut key_prefix = Vec::with_capacity(1 + HASH_PREFIX_ROW_SIZE);
        key_prefix.push(TXID_PREFIX);
        key_prefix.extend_from_slice(&TxidRow::scan_prefix(txid));

        let mut heights = Vec::new();
        for (key, value) in self.firewood.scan_prefix(&key_prefix) {
            if key.len() != 1 + HASH_PREFIX_ROW_SIZE {
                continue;
            }
            if value.len() != 32 || value.as_slice() != txid.as_bytes() {
                continue;
            }
            let mut row_bytes = [0u8; HASH_PREFIX_ROW_SIZE];
            row_bytes.copy_from_slice(&key[1..]);
            let row = HashPrefixRow::from_db_row(row_bytes);
            heights.push(row.height() as u64);
        }

        heights.sort_unstable();
        heights.dedup();

        for height in heights {
            let blocks = self.reconstruct_verified_range(height, height).ok()?;
            let block = match blocks.into_iter().next() {
                Some(block) => block,
                None => continue,
            };
            let converted = Self::convert_block(&block);
            for tx in &converted.ledger_transactions {
                if bsl_txid(tx) == txid {
                    let bytes = serialize_transaction(tx).into_boxed_slice();
                    return Some((converted.ledger_header.block_hash(), bytes));
                }
            }
        }

        None
    }

    fn chain_tip_height(&self) -> Result<u64> {
        let status = self
            .runtime
            .node()
            .node_status()
            .map_err(|err| anyhow!("query node status: {err}"))?;
        Ok(status
            .tip
            .as_ref()
            .map(|tip| tip.height)
            .unwrap_or(status.height))
    }

    fn collect_blocks(&self, start: u64, end: u64) -> Result<Vec<ConvertedBlock>> {
        if start > end {
            return Ok(Vec::new());
        }

        let mut blocks = Vec::new();
        for height in start..=end {
            if let Some(block) = self.fetch_block(height)? {
                blocks.push(block);
            }
        }
        Ok(blocks)
    }

    fn fetch_block(&self, height: u64) -> Result<Option<ConvertedBlock>> {
        let block = self
            .runtime
            .node()
            .get_block(height)
            .map_err(|err| anyhow!("load block {height}: {err}"))?;
        Ok(block.map(|block| Self::convert_block(&block)))
    }

    pub(crate) fn convert_block(block: &RuntimeBlock) -> ConvertedBlock {
        let ledger_header = Self::convert_runtime_header(&block.header);
        let ledger_transactions = block
            .transactions
            .iter()
            .map(Self::convert_transaction)
            .collect();
        let transaction_metadata = Self::build_transaction_metadata(block);
        ConvertedBlock {
            ledger_header,
            ledger_transactions,
            runtime_header: block.header.clone(),
            runtime_transactions: block.transactions.clone(),
            transaction_witnesses: block.module_witnesses.transactions.clone(),
            transaction_metadata,
            #[cfg(feature = "backend-rpp-stark")]
            rpp_stark_proofs: Self::collect_rpp_stark_payloads(block),
        }
    }

    fn convert_runtime_header(header: &RuntimeBlockHeader) -> LedgerBlockHeader {
        LedgerBlockHeader {
            parent: BlockHash(Self::decode_field::<32>(&[header.previous_hash.as_str()])),
            state_root: Self::decode_field::<32>(&[
                header.state_root.as_str(),
                header.proof_root.as_str(),
            ]),
            tx_root: Self::decode_field::<32>(&[
                header.tx_root.as_str(),
                header.utxo_root.as_str(),
            ]),
            vrf_output: Self::decode_field::<32>(&[
                header.randomness.as_str(),
                header.vrf_preoutput.as_str(),
            ]),
            stark_proof: Self::decode_field::<64>(&[
                header.vrf_proof.as_str(),
                header.reputation_root.as_str(),
            ]),
            producer: Self::decode_field::<32>(&[
                header.proposer.as_str(),
                header.leader_tier.as_str(),
            ]),
            timestamp: header.timestamp,
        }
    }

    fn convert_transaction(tx: &SignedTransaction) -> LedgerTransaction {
        let tx_hash = tx.hash();
        let txid = Txid::from_slice(&tx_hash)
            .unwrap_or_else(|_| Txid(Self::hash_to_array::<32>(&tx_hash)));
        let outpoint = OutPoint::new(txid, 0);

        let to_script = Script::new(encode_ledger_script(&LedgerScriptPayload::Recipient {
            to: tx.payload.to.clone(),
            amount: tx.payload.amount,
        }));
        let from_script = Script::new(encode_ledger_script(&LedgerScriptPayload::Sender {
            from: tx.payload.from.clone(),
            fee: tx.payload.fee,
        }));

        let memo = encode_ledger_memo(&LedgerMemoPayload {
            nonce: tx.payload.nonce,
            memo: tx.payload.memo.clone(),
            signature: tx.signature.clone(),
            public_key: tx.public_key.clone(),
        });

        LedgerTransaction::new(vec![outpoint], vec![to_script, from_script], memo)
    }

    fn build_transaction_metadata(block: &RuntimeBlock) -> Vec<Option<Vec<u8>>> {
        let mut witness_by_id: HashMap<[u8; 32], TransactionWitness> = HashMap::new();
        for witness in &block.module_witnesses.transactions {
            witness_by_id.insert(witness.tx_id, witness.clone());
        }

        block
            .transactions
            .iter()
            .enumerate()
            .map(|(index, tx)| {
                let witness = witness_by_id.remove(&tx.hash());
                let metadata = StoredTransactionMetadata {
                    transaction: tx.clone(),
                    witness,
                    rpp_stark_proof: Self::transaction_proof_bytes(block, index),
                };
                Some(encode_transaction_metadata(&metadata))
            })
            .collect()
    }

    fn transaction_proof_bytes(block: &RuntimeBlock, index: usize) -> Option<Vec<u8>> {
        #[cfg(feature = "backend-rpp-stark")]
        {
            block
                .stark
                .transaction_proofs
                .get(index)
                .and_then(|proof| match proof {
                    ChainProof::RppStark(inner) => serde_json::to_vec(inner).ok(),
                    _ => None,
                })
        }
        #[cfg(not(feature = "backend-rpp-stark"))]
        {
            let _ = (block, index);
            None
        }
    }

    #[cfg(feature = "backend-rpp-stark")]
    fn collect_rpp_stark_payloads(block: &RuntimeBlock) -> Vec<Vec<u8>> {
        let mut proofs = Vec::new();
        for proof in &block.stark.transaction_proofs {
            if let ChainProof::RppStark(inner) = proof {
                if let Ok(bytes) = serde_json::to_vec(inner) {
                    proofs.push(bytes);
                }
            }
        }

        for proof in [
            &block.stark.state_proof,
            &block.stark.pruning_proof,
            &block.stark.recursive_proof,
        ] {
            if let ChainProof::RppStark(inner) = proof {
                if let Ok(bytes) = serde_json::to_vec(inner) {
                    proofs.push(bytes);
                }
            }
        }

        if let Some(proof) = block.consensus_proof.as_ref() {
            if let ChainProof::RppStark(inner) = proof {
                if let Ok(bytes) = serde_json::to_vec(inner) {
                    proofs.push(bytes);
                }
            }
        }

        proofs
    }

    #[cfg(not(feature = "backend-rpp-stark"))]
    fn collect_rpp_stark_payloads(_block: &RuntimeBlock) -> Vec<Vec<u8>> {
        Vec::new()
    }

    fn decode_field<const N: usize>(candidates: &[&str]) -> [u8; N] {
        for candidate in candidates {
            let trimmed = candidate.trim_start_matches("0x");
            if let Ok(bytes) = hex::decode(trimmed) {
                if bytes.len() == N {
                    let mut array = [0u8; N];
                    array.copy_from_slice(&bytes);
                    return array;
                }
            }
        }

        Self::hash_to_array::<N>(candidates.join("|").as_bytes())
    }

    fn hash_to_array<const N: usize>(data: impl AsRef<[u8]>) -> [u8; N] {
        debug_assert!(N <= 64, "hash_to_array supports up to 64 bytes");
        let mut hasher = Sha512::new();
        hasher.update(data.as_ref());
        let digest = hasher.finalize();
        let mut output = [0u8; N];
        output.copy_from_slice(&digest[..N]);
        output
    }

    fn reconstruct_verified_range(&self, start: u64, end: u64) -> Result<Vec<RuntimeBlock>> {
        let provider = Arc::clone(self.runtime.payload_provider());
        let blocks = self
            .runtime
            .node()
            .reconstruct_range(start, end, provider.as_ref())
            .map_err(|err| anyhow!("reconstruct blocks {start}..={end}: {err}"))?;
        let verifier = Arc::clone(self.runtime.proof_verifier());
        for block in &blocks {
            let proof_bytes = serde_json::to_vec(&block.recursive_proof.proof)
                .context("encode recursive proof payload")?;
            verifier
                .verify_recursive(
                    &proof_bytes,
                    &block.recursive_proof.commitment,
                    block.recursive_proof.previous_commitment.as_deref(),
                )
                .map_err(|err| {
                    anyhow!(
                        "verify recursive proof for block {}: {err}",
                        block.header.height
                    )
                })?;
        }
        Ok(blocks)
    }
}

#[cfg(test)]
pub(crate) mod test_helpers {
    use super::*;

    use std::collections::HashMap;
    use std::net::SocketAddr;
    use std::sync::{Arc, Mutex};

    use ed25519_dalek::{Keypair, Signer};
    use rand::rngs::OsRng;
    use tempfile::TempDir;

    use rpp::crypto::{address_from_public_key, sign_message};
    use rpp::errors::{ChainError, ChainResult};
    use rpp::proofs::rpp::{ConsensusWitness, ModuleWitnessBundle, ProofArtifact, TransactionWitness};
    use rpp::reputation::{ReputationWeights, Tier};
    use rpp::runtime::config::NodeConfig;
    use rpp::runtime::node::Node;
    use rpp::runtime::orchestration::PipelineOrchestrator;
    use rpp::runtime::sync::{PayloadProvider, ReconstructionRequest, RuntimeRecursiveProofVerifier};
    use rpp::runtime::types::{
        Account, AttestedIdentityRequest, Block, BlockHeader, BlockMetadata, BlockPayload, ChainProof,
        ConsensusCertificate, PruningProof, RecursiveProof, ReputationUpdate, SignedBftVote,
        SignedTransaction, Stake, StateWitness, TimetokeUpdate, Transaction, TransactionProofBundle,
        UptimeProof, VoteRecord,
    };
    use rpp::runtime::types::block::BlockProofBundle;
    use rpp::runtime::types::transaction::Signature as TxSignature;
    use rpp::runtime::types::BftVoteKind;
    use rpp::runtime::vrf::{evaluate_vrf, vrf_public_key_to_hex};
    use rpp::storage::Storage;
    use rpp::stwo::circuit::recursive::RecursiveWitness;
    use rpp::stwo::proof::{
        CommitmentSchemeProofData, ExecutionTrace, FriProof, ProofKind, ProofPayload, StarkProof,
    };
    use rpp::types::BftVote;
    use rpp::vrf::generate_vrf_keypair;
    use sha2::{Digest, Sha256};

    use crate::vendor::electrs::types::{
        bsl_txid, serialize_block, serialize_transaction, SerBlock, HASH_PREFIX_ROW_SIZE,
    };

    #[derive(Debug)]
    pub struct TestContext {
        pub daemon: Daemon,
        pub block_one_hash: BlockHash,
        pub block_two_hash: BlockHash,
        pub transaction_id: Txid,
        pub expected_block_bytes: SerBlock,
        pub expected_transaction_bytes: Box<[u8]>,
    }

    pub fn setup() -> TestContext {
        let temp_dir = TempDir::new().expect("tempdir");
        let firewood_dir = temp_dir.path().join("firewood");
        let mut config = node_config(temp_dir.path());
        config.rollout.feature_gates.reconstruction = true;
        let node = Node::new(config).expect("node");
        let node_handle = node.handle();
        let storage = node_handle.storage();

        let mut payloads = HashMap::new();

        let (genesis_block, genesis_keypair) = make_block(0, None);
        let genesis_metadata = BlockMetadata::from(&genesis_block);
        storage
            .store_block(&genesis_block, &genesis_metadata)
            .expect("store genesis");
        persist_validator_account(&storage, &genesis_keypair);
        payloads.insert(0, BlockPayload::from_block(&genesis_block));

        let (mut block_one, block_one_keypair) = make_block(1, Some(&genesis_block));
        inject_transaction(&mut block_one);
        persist_validator_account(&storage, &block_one_keypair);
        let block_one_metadata = BlockMetadata::from(&block_one);
        storage
            .store_block(&block_one, &block_one_metadata)
            .expect("store block one");
        payloads.insert(1, BlockPayload::from_block(&block_one));

        let (mut block_two, block_two_keypair) = make_block(2, Some(&block_one));
        persist_validator_account(&storage, &block_two_keypair);
        block_two.recursive_proof.commitment = "invalid".to_string();
        let block_two_metadata = BlockMetadata::from(&block_two);
        storage
            .store_block(&block_two, &block_two_metadata)
            .expect("store block two");
        payloads.insert(2, BlockPayload::from_block(&block_two));

        let provider = Arc::new(TestPayloadProvider::new(payloads));
        let proof_verifier = Arc::new(RuntimeRecursiveProofVerifier::default());
        let (orchestrator, _shutdown) = PipelineOrchestrator::new(node_handle.clone(), None);
        let runtime_adapters = RuntimeAdapters::new(
            Arc::new(storage.clone()),
            node_handle.clone(),
            orchestrator,
            provider,
            proof_verifier,
        );

        std::fs::create_dir_all(&firewood_dir).expect("firewood dir");
        let mut firewood =
            FirewoodAdapter::open_with_runtime(&firewood_dir, runtime_adapters).expect("firewood");

        let block_one_converted = Daemon::convert_block(&block_one);
        let block_one_hash = block_one_converted.ledger_header.block_hash();
        let block_two_hash = Daemon::convert_block(&block_two)
            .ledger_header
            .block_hash();
        let transaction = block_one_converted
            .ledger_transactions
            .first()
            .expect("transaction");
        let txid = bsl_txid(transaction);
        index_transaction(&mut firewood, txid, 1);
        let expected_block_bytes = serialize_block(&block_one_converted.ledger_transactions);
        let expected_transaction_bytes = serialize_transaction(transaction).into_boxed_slice();
        firewood.commit().expect("commit index");

        let daemon = Daemon::new(firewood).expect("daemon");

        TestContext {
            daemon,
            block_one_hash,
            block_two_hash,
            transaction_id: txid,
            expected_block_bytes,
            expected_transaction_bytes,
        }
    }

    struct TestPayloadProvider {
        payloads: Mutex<HashMap<u64, BlockPayload>>,
    }

    impl TestPayloadProvider {
        fn new(payloads: HashMap<u64, BlockPayload>) -> Self {
            Self {
                payloads: Mutex::new(payloads),
            }
        }
    }

    impl PayloadProvider for TestPayloadProvider {
        fn fetch_payload(&self, request: &ReconstructionRequest) -> ChainResult<BlockPayload> {
            self.payloads
                .lock()
                .unwrap()
                .get(&request.height)
                .cloned()
                .ok_or_else(|| ChainError::Config("missing payload".into()))
        }
    }

    fn node_config(root: &std::path::Path) -> NodeConfig {
        let data_dir = root.join("data");
        let keys_dir = root.join("keys");
        std::fs::create_dir_all(&data_dir).expect("data dir");
        std::fs::create_dir_all(&keys_dir).expect("keys dir");
        let mut config = NodeConfig::default();
        config.data_dir = data_dir.clone();
        config.snapshot_dir = data_dir.join("snapshots");
        config.proof_cache_dir = data_dir.join("proofs");
        config.key_path = keys_dir.join("node.toml");
        config.vrf_key_path = keys_dir.join("vrf.toml");
        config.p2p_key_path = keys_dir.join("p2p.toml");
        config.p2p.peerstore_path = data_dir.join("p2p/peerstore.json");
        config.p2p.gossip_path = Some(data_dir.join("p2p/gossip.json"));
        config.rpc_listen = SocketAddr::from(([127, 0, 0, 1], 0));
        config.rollout.feature_gates.recursive_proofs = true;
        config
    }

    fn index_transaction(store: &mut FirewoodAdapter, txid: Txid, height: usize) {
        const PREFIX: u8 = b't';
        let row = TxidRow::row(txid, height);
        let mut key = Vec::with_capacity(1 + HASH_PREFIX_ROW_SIZE);
        key.push(PREFIX);
        key.extend_from_slice(&row.to_db_row());
        store.put(key, txid.as_bytes().to_vec());
    }

    fn inject_transaction(block: &mut Block) {
        let bundle = sample_transaction_bundle(&block.header.proposer, 0);
        block.transactions.push(bundle.transaction.clone());
        block
            .stark
            .transaction_proofs
            .push(bundle.proof.clone());
        let witness = match &bundle.proof {
            ChainProof::Stwo(proof) => match &proof.payload {
                ProofPayload::Transaction(witness) => witness.clone(),
                _ => panic!("unexpected payload"),
            },
            _ => panic!("unexpected backend"),
        };
        block.module_witnesses.record_transaction(witness);
    }

    fn sample_transaction_bundle(to: &str, nonce: u64) -> TransactionProofBundle {
        let keypair = generate_keypair();
        let from = address_from_public_key(&keypair.public);
        let tx = Transaction::new(from.clone(), to.to_string(), 42, 1, nonce, None);
        let signature = sign_message(&keypair, &tx.canonical_bytes());
        let signed_tx = SignedTransaction::new(tx, signature, &keypair.public);

        let mut sender = Account::new(from.clone(), 1_000_000, Stake::from_u128(1_000));
        sender.nonce = nonce;
        let receiver = Account::new(to.to_string(), 0, Stake::default());

        let witness = TransactionWitness {
            signed_tx: signed_tx.clone(),
            sender_account: sender,
            receiver_account: Some(receiver),
            required_tier: Tier::Tl0,
            reputation_weights: ReputationWeights::default(),
        };

        let proof = StarkProof {
            kind: ProofKind::Transaction,
            commitment: String::new(),
            public_inputs: Vec::new(),
            payload: ProofPayload::Transaction(witness),
            trace: ExecutionTrace { segments: Vec::new() },
            commitment_proof: CommitmentSchemeProofData::default(),
            fri_proof: FriProof::default(),
        };

        TransactionProofBundle::new(signed_tx, ChainProof::Stwo(proof))
    }

    fn generate_keypair() -> Keypair {
        let mut rng = OsRng;
        Keypair::generate(&mut rng)
    }

    fn persist_validator_account(storage: &Storage, keypair: &Keypair) {
        let address = address_from_public_key(&keypair.public);
        let mut account = Account::new(address.clone(), 0, Stake::default());
        account
            .ensure_wallet_binding(&hex::encode(keypair.public.to_bytes()))
            .expect("bind wallet");
        storage
            .persist_account(&account)
            .expect("persist account");
    }

    fn make_block(height: u64, previous: Option<&Block>) -> (Block, Keypair) {
        let previous_hash = previous
            .map(|block| block.hash.clone())
            .unwrap_or_else(|| hex::encode([0u8; 32]));
        let seed = previous
            .map(|block| block.block_hash())
            .unwrap_or([0u8; 32]);
        let mut tx_leaves: Vec<[u8; 32]> = Vec::new();
        let tx_root = hex::encode(compute_merkle_root(&mut tx_leaves));
        let state_root = hex::encode([height as u8 + 2; 32]);
        let utxo_root = hex::encode([height as u8 + 3; 32]);
        let reputation_root = hex::encode([height as u8 + 4; 32]);
        let timetoke_root = hex::encode([height as u8 + 5; 32]);
        let zsi_root = hex::encode([height as u8 + 6; 32]);
        let proof_root = hex::encode([height as u8 + 7; 32]);
        let mut rng = OsRng;
        let keypair = Keypair::generate(&mut rng);
        let address = address_from_public_key(&keypair.public);
        let vrf_keypair = generate_vrf_keypair().expect("vrf keypair");
        let vrf = evaluate_vrf(&seed, height, &address, height, Some(&vrf_keypair.secret))
            .expect("evaluate vrf");
        let header = BlockHeader::new(
            height,
            previous_hash,
            tx_root,
            state_root.clone(),
            utxo_root.clone(),
            reputation_root.clone(),
            timetoke_root.clone(),
            zsi_root.clone(),
            proof_root.clone(),
            "0".to_string(),
            vrf.randomness.to_string(),
            vrf_public_key_to_hex(&vrf_keypair.public),
            vrf.preoutput.clone(),
            vrf.proof.clone(),
            address.clone(),
            Tier::Tl3.to_string(),
            height,
        );
        let block_hash_hex = hex::encode(header.hash());
        let prevote = BftVote {
            round: height,
            height,
            block_hash: block_hash_hex.clone(),
            voter: address.clone(),
            kind: BftVoteKind::PreVote,
        };
        let prevote_sig = keypair.sign(&prevote.message_bytes());
        let signed_prevote = SignedBftVote {
            vote: prevote,
            public_key: hex::encode(keypair.public.to_bytes()),
            signature: hex::encode(prevote_sig.to_bytes()),
        };
        let precommit_vote = BftVote {
            kind: BftVoteKind::PreCommit,
            ..signed_prevote.vote.clone()
        };
        let precommit_sig = keypair.sign(&precommit_vote.message_bytes());
        let signed_precommit = SignedBftVote {
            vote: precommit_vote,
            public_key: hex::encode(keypair.public.to_bytes()),
            signature: hex::encode(precommit_sig.to_bytes()),
        };
        let pruning_proof = PruningProof::from_previous(previous, &header);
        let aggregated_commitment = hex::encode([height as u8 + 8; 32]);
        let previous_recursive_commitment =
            previous.map(|block| block.recursive_proof.commitment.clone());
        let recursive_stark = dummy_recursive_proof(
            previous_recursive_commitment.clone(),
            aggregated_commitment.clone(),
            &header,
            &pruning_proof,
        );
        let recursive_chain_proof = ChainProof::Stwo(recursive_stark.clone());
        let recursive_proof = match previous {
            Some(prev) => RecursiveProof::extend(
                &prev.recursive_proof,
                &header,
                &pruning_proof,
                &recursive_chain_proof,
            )
            .expect("recursive extend"),
            None => RecursiveProof::genesis(&header, &pruning_proof, &recursive_chain_proof)
                .expect("recursive genesis"),
        };
        let state_stark = dummy_state_proof();
        let pruning_stark = dummy_pruning_proof();
        let mut module_witnesses = ModuleWitnessBundle::default();
        module_witnesses.record_consensus(ConsensusWitness::new(height, height, vec![address.clone()]));
        let proof_artifacts = module_witnesses
            .expected_artifacts()
            .expect("artifacts")
            .into_iter()
            .map(|(module, commitment, payload)| ProofArtifact {
                module,
                commitment,
                proof: payload,
                verification_key: None,
            })
            .collect();
        let stark_bundle = BlockProofBundle::new(
            Vec::new(),
            ChainProof::Stwo(state_stark),
            ChainProof::Stwo(pruning_stark),
            recursive_chain_proof,
        );
        let signature: TxSignature = keypair.sign(&header.canonical_bytes());
        let mut consensus = ConsensusCertificate::genesis();
        consensus.round = height;
        consensus.total_power = "1".to_string();
        consensus.quorum_threshold = "1".to_string();
        consensus.pre_vote_power = "1".to_string();
        consensus.pre_commit_power = "1".to_string();
        consensus.commit_power = "1".to_string();
        consensus.pre_votes = vec![VoteRecord {
            vote: signed_prevote.clone(),
            weight: "1".to_string(),
        }];
        consensus.pre_commits = vec![VoteRecord {
            vote: signed_precommit,
            weight: "1".to_string(),
        }];
        let block = Block::new(
            header,
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            module_witnesses,
            proof_artifacts,
            pruning_proof,
            recursive_proof,
            stark_bundle,
            signature,
            consensus,
            None,
        );
        (block, keypair)
    }

    fn dummy_state_proof() -> StarkProof {
        StarkProof {
            kind: ProofKind::State,
            commitment: "11".repeat(32),
            public_inputs: Vec::new(),
            payload: ProofPayload::State(StateWitness {
                prev_state_root: "22".repeat(32),
                new_state_root: "33".repeat(32),
                identities: Vec::new(),
                transactions: Vec::new(),
                accounts_before: Vec::new(),
                accounts_after: Vec::new(),
                required_tier: Tier::Tl0,
                reputation_weights: ReputationWeights::default(),
            }),
            trace: ExecutionTrace { segments: Vec::new() },
            commitment_proof: CommitmentSchemeProofData::default(),
            fri_proof: FriProof::default(),
        }
    }

    fn dummy_pruning_proof() -> StarkProof {
        StarkProof {
            kind: ProofKind::Pruning,
            commitment: "44".repeat(32),
            public_inputs: Vec::new(),
            payload: ProofPayload::Pruning(rpp::runtime::types::PruningWitness {
                previous_tx_root: "55".repeat(32),
                pruned_tx_root: "66".repeat(32),
                original_transactions: Vec::new(),
                removed_transactions: Vec::new(),
            }),
            trace: ExecutionTrace { segments: Vec::new() },
            commitment_proof: CommitmentSchemeProofData::default(),
            fri_proof: FriProof::default(),
        }
    }

    fn dummy_recursive_proof(
        previous_commitment: Option<String>,
        aggregated_commitment: String,
        header: &BlockHeader,
        pruning: &PruningProof,
    ) -> StarkProof {
        let previous_commitment =
            previous_commitment.or_else(|| Some(RecursiveProof::anchor()));
        StarkProof {
            kind: ProofKind::Recursive,
            commitment: aggregated_commitment.clone(),
            public_inputs: Vec::new(),
            payload: ProofPayload::Recursive(RecursiveWitness {
                previous_commitment,
                aggregated_commitment,
                identity_commitments: Vec::new(),
                tx_commitments: Vec::new(),
                uptime_commitments: Vec::new(),
                attested_identities: Vec::new(),
                reputation_updates: Vec::new(),
                uptime_proofs: Vec::new(),
                transactions: Vec::new(),
                pruning_witnesses: Vec::new(),
                parent_state_root: header.state_root.clone(),
                new_state_root: header.state_root.clone(),
                parent_utxo_root: header.utxo_root.clone(),
                new_utxo_root: header.utxo_root.clone(),
                parent_reputation_root: header.reputation_root.clone(),
                new_reputation_root: header.reputation_root.clone(),
                parent_timetoke_root: header.timetoke_root.clone(),
                new_timetoke_root: header.timetoke_root.clone(),
                parent_zsi_root: header.zsi_root.clone(),
                new_zsi_root: header.zsi_root.clone(),
                parent_proof_root: header.proof_root.clone(),
                new_proof_root: header.proof_root.clone(),
                attested_identity_requests: Vec::new(),
                pruning_proof: pruning.clone(),
                block_hash: header.hash(),
                block_height: header.height,
                block_timestamp: header.timestamp,
            }),
            trace: ExecutionTrace { segments: Vec::new() },
            commitment_proof: CommitmentSchemeProofData::default(),
            fri_proof: FriProof::default(),
        }
    }

    fn compute_merkle_root(leaves: &mut Vec<[u8; 32]>) -> [u8; 32] {
        if leaves.is_empty() {
            return [0u8; 32];
        }
        while leaves.len() > 1 {
            let mut next = Vec::new();
            for chunk in leaves.chunks(2) {
                let mut hasher = Sha256::new();
                hasher.update(&chunk[0]);
                if chunk.len() == 2 {
                    hasher.update(&chunk[1]);
                } else {
                    hasher.update(&chunk[0]);
                }
                next.push(hasher.finalize().into());
            }
            *leaves = next;
        }
        leaves[0]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::test_helpers::setup;

    #[test]
    fn for_blocks_rejects_invalid_payload() {
        let context = setup();
        let err = context
            .daemon
            .for_blocks([context.block_two_hash], |_, _| {})
            .expect_err("invalid block should be rejected");
        assert!(err.to_string().contains("verify recursive proof"));
    }

    #[test]
    fn for_blocks_surfaces_reconstructed_block() {
        let context = setup();
        let mut captured = Vec::new();
        context
            .daemon
            .for_blocks([context.block_one_hash], |hash, block| {
                captured.push((hash, block));
            })
            .expect("fetch block");
        assert_eq!(captured.len(), 1);
        assert_eq!(captured[0].0, context.block_one_hash);
        assert_eq!(captured[0].1, context.expected_block_bytes);
    }

    #[test]
    fn find_transaction_returns_serialized_payload() {
        let context = setup();
        let (block, bytes) = context
            .daemon
            .find_transaction(context.transaction_id)
            .expect("transaction should be located");
        assert_eq!(block, context.block_one_hash);
        assert_eq!(bytes, context.expected_transaction_bytes);
    }
}
