use std::convert::TryFrom;

use anyhow::{Context, Result, anyhow};

use crate::vendor::electrs::chain::{Chain, NewHeader};
use crate::vendor::electrs::firewood_adapter::{FirewoodAdapter, RuntimeAdapters};
use crate::vendor::electrs::rpp_ledger::bitcoin::blockdata::{
    block::Header as LedgerBlockHeader, constants,
};
use crate::vendor::electrs::rpp_ledger::bitcoin::{BlockHash, Network, OutPoint, Script, Txid};
use crate::vendor::electrs::rpp_ledger::bitcoin_slices::bsl::Transaction as LedgerTransaction;
use crate::vendor::electrs::types::{SerBlock, bsl_txid, serialize_block, serialize_transaction};
use rpp::runtime::types::{
    Block as RuntimeBlock, BlockHeader as RuntimeBlockHeader, SignedTransaction,
};
use rpp_p2p::GossipTopic;
use sha2::{Digest, Sha512};
use tokio::sync::broadcast;

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
            let (header, _) = Self::convert_block(&block);
            Ok(header.block_hash())
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
    pub fn blocks_since(
        &self,
        height: usize,
    ) -> Result<Vec<(LedgerBlockHeader, Vec<LedgerTransaction>)>> {
        let start = height
            .checked_add(1)
            .ok_or_else(|| anyhow!("height overflow"))?;
        let tip = self.chain_tip_height()?;
        if (start as u64) > tip {
            return Ok(Vec::new());
        }

        self.collect_blocks(start as u64, tip)
    }

    /// Iterate over blocks matching the supplied hashes and invoke `func` with
    /// their serialized representation.
    pub(crate) fn for_blocks<B, F>(&self, blockhashes: B, mut func: F) -> Result<()>
    where
        B: IntoIterator<Item = BlockHash>,
        F: FnMut(BlockHash, SerBlock),
    {
        for blockhash in blockhashes {
            if let Some((header, transactions)) = self.find_block_by_hash(blockhash)? {
                let serialized = serialize_block(&transactions);
                func(header.block_hash(), serialized);
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
        let tip = self.chain_tip_height().ok()?;
        for height in 0..=tip {
            let block = self.fetch_block(height).ok()??;
            let (header, transactions) = block;
            for tx in &transactions {
                if bsl_txid(tx) == txid {
                    let bytes = serialize_transaction(tx).into_boxed_slice();
                    return Some((header.block_hash(), bytes));
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

    fn collect_blocks(
        &self,
        start: u64,
        end: u64,
    ) -> Result<Vec<(LedgerBlockHeader, Vec<LedgerTransaction>)>> {
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

    fn fetch_block(
        &self,
        height: u64,
    ) -> Result<Option<(LedgerBlockHeader, Vec<LedgerTransaction>)>> {
        let block = self
            .runtime
            .node()
            .get_block(height)
            .map_err(|err| anyhow!("load block {height}: {err}"))?;
        Ok(block.map(|block| Self::convert_block(&block)))
    }

    fn find_block_by_hash(
        &self,
        target: BlockHash,
    ) -> Result<Option<(LedgerBlockHeader, Vec<LedgerTransaction>)>> {
        let tip = self.chain_tip_height()?;
        for height in 0..=tip {
            if let Some(block) = self.fetch_block(height)? {
                if block.0.block_hash() == target {
                    return Ok(Some(block));
                }
            }
        }
        Ok(None)
    }

    fn convert_block(block: &RuntimeBlock) -> (LedgerBlockHeader, Vec<LedgerTransaction>) {
        let header = Self::convert_runtime_header(&block.header);
        let transactions = block
            .transactions
            .iter()
            .map(Self::convert_transaction)
            .collect();
        (header, transactions)
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
        let input_tag = format!("{}:{}", tx.id, tx.payload.nonce);
        let outpoint = OutPoint::new(Txid(Self::hash_to_array::<32>(input_tag.as_bytes())), 0);

        let to_script = format!("to:{}:{}", tx.payload.to, tx.payload.amount).into_bytes();
        let from_script = format!("from:{}:{}", tx.payload.from, tx.payload.fee).into_bytes();

        let mut memo = format!(
            "from={};to={};amount={};fee={};nonce={}",
            tx.payload.from, tx.payload.to, tx.payload.amount, tx.payload.fee, tx.payload.nonce
        )
        .into_bytes();
        if let Some(extra) = &tx.payload.memo {
            memo.extend_from_slice(b";memo=");
            memo.extend_from_slice(extra.as_bytes());
        }

        LedgerTransaction::new(
            vec![outpoint],
            vec![Script::new(to_script), Script::new(from_script)],
            memo,
        )
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
}
