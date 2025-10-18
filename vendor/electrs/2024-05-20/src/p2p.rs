use std::collections::{HashMap, HashSet};

use anyhow::{anyhow, Context, Result};
use serde_json;
use tokio::sync::broadcast;

use crate::vendor::electrs::chain::{Chain, NewHeader};
use crate::vendor::electrs::daemon::Daemon;
use crate::vendor::electrs::firewood_adapter::FirewoodAdapter;
use crate::vendor::electrs::metrics::{default_duration_buckets, Histogram, Metrics};
use crate::vendor::electrs::rpp_ledger::bitcoin::BlockHash;
use crate::vendor::electrs::types::{serialize_block, SerBlock};
use rpp_p2p::GossipTopic;

/// Lightweight connection facade mirroring the upstream electrs P2P interface.
///
/// Instead of relying on the Bitcoin P2P protocol this implementation streams
/// headers and blocks from the Firewood runtime. Gossip notifications are
/// delivered via the runtime's broadcast channels.
pub(crate) struct Connection<'a> {
    firewood: &'a FirewoodAdapter,
    gossip: broadcast::Receiver<Vec<u8>>,
    blocks_duration: Histogram,
}

impl<'a> Connection<'a> {
    /// Attach to the Firewood-backed runtime and prepare block metrics.
    pub(crate) fn connect(firewood: &'a FirewoodAdapter, metrics: &Metrics) -> Result<Self> {
        firewood
            .runtime()
            .ok_or_else(|| anyhow!("firewood runtime adapters not attached"))?;

        let blocks_duration = metrics.histogram_vec(
            "p2p_blocks_duration",
            "Time spent getting blocks via runtime reconstruction (in seconds)",
            "step",
            default_duration_buckets(),
        );

        let gossip = firewood
            .subscribe_gossip(GossipTopic::Blocks)
            .context("subscribe to block gossip")?;

        Ok(Self {
            firewood,
            gossip,
            blocks_duration,
        })
    }

    /// Stream new headers extending the supplied chain tip.
    pub(crate) fn get_new_headers(&mut self, chain: &Chain) -> Result<Vec<NewHeader>> {
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
            let converted = Daemon::convert_runtime_header(&header);
            headers.push(NewHeader::from((converted, height)));
        }

        Ok(headers)
    }

    /// Request and process blocks identified by their ledger hashes.
    pub(crate) fn for_blocks<B, F>(&mut self, blockhashes: B, mut func: F) -> Result<()>
    where
        B: IntoIterator<Item = BlockHash>,
        F: FnMut(BlockHash, SerBlock),
    {
        self.blocks_duration.observe_duration("total", || {
            let requested: Vec<BlockHash> = blockhashes.into_iter().collect();
            if requested.is_empty() {
                return Ok(());
            }

            let runtime = self
                .firewood
                .runtime()
                .ok_or_else(|| anyhow!("firewood runtime adapters not attached"))?;
            let status = runtime
                .node()
                .node_status()
                .map_err(|err| anyhow!("query node status: {err}"))?;
            let tip_height = status
                .tip
                .as_ref()
                .map(|tip| tip.height)
                .unwrap_or(status.height);

            let blocks = self
                .firewood
                .reconstruct_range(0, tip_height)
                .context("reconstruct runtime blocks")?;

            let verifier = runtime.proof_verifier();
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

            let mut remaining: HashSet<BlockHash> = requested.iter().copied().collect();
            let mut serialized: HashMap<BlockHash, SerBlock> = HashMap::new();
            for block in blocks {
                if remaining.is_empty() {
                    break;
                }
                let converted = Daemon::convert_block(&block);
                let hash = converted.ledger_header.block_hash();
                if remaining.remove(&hash) {
                    let bytes = serialize_block(&converted.ledger_transactions);
                    serialized.insert(hash, bytes);
                }
            }

            for hash in requested {
                let Some(bytes) = serialized.get(&hash) else {
                    return Err(anyhow!("failed to reconstruct block {hash}"));
                };
                func(hash, bytes.clone());
            }

            Ok(())
        })
    }

    /// Open a new block gossip subscription.
    pub(crate) fn new_block_notification(&self) -> broadcast::Receiver<Vec<u8>> {
        self.gossip.resubscribe()
    }
}
