use anyhow::{bail, Context, Result};
use std::collections::HashMap;

use hex::FromHex;
use log::warn;
use serde::ser::{Serialize, SerializeSeq, Serializer};

use rpp::runtime::config::QueueWeightsConfig;
use rpp::runtime::node::{MempoolStatus, PendingTransactionSummary};

use crate::vendor::electrs::daemon::Daemon;
use crate::vendor::electrs::metrics::{Gauge, Metrics};
use crate::vendor::electrs::rpp_ledger::bitcoin::{Script, Txid};
use crate::vendor::electrs::types::ScriptHash;

#[derive(Clone, Copy, Debug, Default)]
struct QueueWeight {
    priority: f64,
    fee: f64,
}

impl QueueWeight {
    fn from_summary(summary: &PendingTransactionSummary, weights: &QueueWeightsConfig) -> Self {
        let fee_component = weights.fee * summary.fee as f64;
        Self {
            priority: weights.priority,
            fee: fee_component,
        }
    }
}

#[derive(Clone, Debug)]
pub(crate) struct Entry {
    pub txid: Txid,
    pub scripthash: ScriptHash,
    pub fee: u64,
    pub queue_weight: QueueWeight,
}

impl Entry {
    fn from_summary(
        summary: &PendingTransactionSummary,
        weights: &QueueWeightsConfig,
    ) -> Result<Self> {
        let txid = decode_txid(&summary.hash)
            .with_context(|| format!("decode pending transaction hash: {}", summary.hash))?;
        let queue_weight = QueueWeight::from_summary(summary, weights);
        let scripthash = script_hash_from_address(&summary.to);
        Ok(Self {
            txid,
            scripthash,
            fee: summary.fee,
            queue_weight,
        })
    }
}

pub(crate) struct MempoolSyncUpdate {
    snapshot: MempoolStatus,
}

impl MempoolSyncUpdate {
    pub fn from_snapshot(snapshot: MempoolStatus) -> Self {
        Self { snapshot }
    }

    pub fn poll(daemon: &Daemon) -> Result<Self> {
        let snapshot = daemon
            .mempool_snapshot()
            .context("fetch runtime mempool snapshot")?;
        Ok(Self { snapshot })
    }
}

pub(crate) struct MempoolMetrics {
    transactions: Gauge,
    identities: Gauge,
    votes: Gauge,
    uptime: Gauge,
    priority_weight: Gauge,
    fee_weight: Gauge,
}

impl MempoolMetrics {
    fn new(metrics: &Metrics) -> Self {
        Self {
            transactions: metrics.gauge(
                "mempool_transactions",
                "Pending ledger transactions exposed via the runtime mempool",
                "category",
            ),
            identities: metrics.gauge(
                "mempool_identities",
                "Identity updates advertised by the runtime mempool",
                "category",
            ),
            votes: metrics.gauge(
                "mempool_votes",
                "Consensus votes surfaced by the runtime mempool",
                "category",
            ),
            uptime: metrics.gauge(
                "mempool_uptime_proofs",
                "Uptime proofs published to the runtime mempool",
                "category",
            ),
            priority_weight: metrics.gauge(
                "mempool_queue_priority_weight",
                "Aggregated queue priority weight of pending transactions",
                "component",
            ),
            fee_weight: metrics.gauge(
                "mempool_queue_fee_weight",
                "Aggregated fee weight of pending transactions",
                "component",
            ),
        }
    }

    fn observe(&self, status: &MempoolStatus, histogram: &QueueHistogram) {
        self.transactions
            .set("transactions", status.transactions.len() as f64);
        self.identities
            .set("identities", status.identities.len() as f64);
        self.votes.set("votes", status.votes.len() as f64);
        self.uptime
            .set("uptime", status.uptime_proofs.len() as f64);
        self.priority_weight
            .set("queue", histogram.priority_weight);
        self.fee_weight.set("queue", histogram.fee_weight);
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct QueueHistogram {
    priority_weight: f64,
    fee_weight: f64,
    entries: usize,
}

impl QueueHistogram {
    fn rebuild<I>(&mut self, weights: I)
    where
        I: IntoIterator<Item = QueueWeight>,
    {
        self.priority_weight = 0.0;
        self.fee_weight = 0.0;
        self.entries = 0;
        for weight in weights {
            self.priority_weight += weight.priority;
            self.fee_weight += weight.fee;
            self.entries += 1;
        }
    }

    pub fn priority(&self) -> f64 {
        self.priority_weight
    }

    pub fn fee(&self) -> f64 {
        self.fee_weight
    }

    pub fn total_entries(&self) -> usize {
        self.entries
    }
}

impl Serialize for QueueHistogram {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut seq = serializer.serialize_seq(Some(2))?;
        seq.serialize_element(&("priority", self.priority_weight))?;
        seq.serialize_element(&("fee", self.fee_weight))?;
        seq.end()
    }
}

pub(crate) struct Mempool {
    entries: HashMap<Txid, Entry>,
    histogram: QueueHistogram,
    metrics: MempoolMetrics,
    snapshot: Option<MempoolStatus>,
}

impl Mempool {
    pub fn new(metrics: &Metrics) -> Self {
        Self {
            entries: HashMap::new(),
            histogram: QueueHistogram::default(),
            metrics: MempoolMetrics::new(metrics),
            snapshot: None,
        }
    }

    pub fn snapshot(&self) -> Option<&MempoolStatus> {
        self.snapshot.as_ref()
    }

    pub fn histogram(&self) -> &QueueHistogram {
        &self.histogram
    }

    pub fn sync(&mut self, daemon: &Daemon) -> Result<()> {
        let update = MempoolSyncUpdate::poll(daemon)?;
        self.apply_sync_update(update);
        Ok(())
    }

    pub fn apply_sync_update(&mut self, update: MempoolSyncUpdate) {
        let snapshot = update.snapshot;
        let queue_weights = snapshot.queue_weights.clone();
        let mut entries = HashMap::with_capacity(snapshot.transactions.len());
        let mut weights = Vec::with_capacity(snapshot.transactions.len());

        for summary in &snapshot.transactions {
            match Entry::from_summary(summary, &queue_weights) {
                Ok(entry) => {
                    weights.push(entry.queue_weight);
                    entries.insert(entry.txid, entry);
                }
                Err(err) => {
                    warn!("skip malformed mempool transaction: {err}");
                }
            }
        }

        self.histogram.rebuild(weights);
        self.metrics.observe(&snapshot, &self.histogram);
        self.entries = entries;
        self.snapshot = Some(snapshot);
    }

    pub fn get(&self, txid: &Txid) -> Option<&Entry> {
        self.entries.get(txid)
    }
}

fn decode_txid(hash: &str) -> Result<Txid> {
    let bytes = Vec::from_hex(hash)?;
    if bytes.len() != 32 {
        anyhow::bail!("expected 32 byte transaction hash, received {} bytes", bytes.len());
    }
    let mut array = [0u8; 32];
    array.copy_from_slice(&bytes);
    Ok(Txid::from_bytes(array))
}

fn script_hash_from_address(address: &str) -> ScriptHash {
    // TODO: Replace this placeholder conversion once the ledger exposes
    //       canonical script encodings for account addresses.
    let script = Script::new(address.as_bytes().to_vec());
    ScriptHash::new(&script)
}

#[cfg(test)]
mod tests {
    use super::*;

    use rpp::runtime::config::QueueWeightsConfig;

    fn sample_summary(tag: u8, fee: u64) -> PendingTransactionSummary {
        PendingTransactionSummary {
            hash: hex::encode([tag; 32]),
            from: format!("from-{tag:02x}"),
            to: format!("to-{tag:02x}"),
            amount: u128::from(tag),
            fee,
            nonce: 0,
            proof: None,
            witness: None,
            proof_payload: None,
            #[cfg(feature = "backend-rpp-stark")]
            public_inputs_digest: None,
        }
    }

    #[test]
    fn entry_converts_summary() {
        let weights = QueueWeightsConfig::default();
        let summary = sample_summary(0xAA, 42);
        let entry = Entry::from_summary(&summary, &weights).expect("entry");

        assert_eq!(entry.fee, 42);
        assert_eq!(entry.queue_weight.priority, weights.priority);
        assert_eq!(entry.queue_weight.fee, weights.fee * 42.0);
        assert_eq!(entry.txid.as_bytes(), &[0xAA; 32]);
    }

    #[test]
    fn histogram_serializes_weights() {
        let mut histogram = QueueHistogram::default();
        histogram.rebuild([
            QueueWeight {
                priority: 0.7,
                fee: 30.0,
            },
            QueueWeight {
                priority: 0.7,
                fee: 12.0,
            },
        ]);

        let serialized = serde_json::to_value(histogram).expect("serialize histogram");
        assert_eq!(
            serialized,
            serde_json::json!([["priority", 1.4], ["fee", 42.0]])
        );
    }
}
