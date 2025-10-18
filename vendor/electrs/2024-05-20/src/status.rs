use std::collections::{HashMap, HashSet};

use anyhow::{anyhow, Context};
use serde::ser::{Serialize, SerializeStruct, Serializer};

#[cfg(feature = "backend-rpp-stark")]
use crate::zk::rpp_adapter::{Digest32, RppStarkHasher};

use crate::vendor::electrs::chain::Chain;
use crate::vendor::electrs::index::Index;
use crate::vendor::electrs::rpp_ledger::bitcoin::{
    hashes::sha256,
    OutPoint,
    BlockHash,
    Script,
    Txid,
};
use crate::vendor::electrs::rpp_ledger::bitcoin_slices::bsl::Transaction;
use crate::vendor::electrs::types::{ScriptHash, StatusDigest};
use rpp::runtime::node::{MempoolStatus, PendingTransactionSummary};

fn hex_string(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write;
        write!(&mut s, "{:02x}", byte).expect("write to string");
    }
    s
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, serde::Serialize)]
pub struct Balance {
    #[serde(rename = "confirmed")]
    confirmed_balance: u64,
    #[serde(rename = "unconfirmed")]
    mempool_delta: i64,
}

impl Balance {
    pub fn confirmed(&self) -> u64 {
        self.confirmed_balance
    }

    pub fn mempool_delta(&self) -> i64 {
        self.mempool_delta
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UnspentEntry {
    height: usize,
    tx_hash: Txid,
    tx_pos: u32,
    value: u64,
}

impl Serialize for UnspentEntry {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("UnspentEntry", 4)?;
        state.serialize_field("height", &self.height)?;
        state.serialize_field("tx_hash", &hex_string(self.tx_hash.as_bytes()))?;
        state.serialize_field("tx_pos", &self.tx_pos)?;
        state.serialize_field("value", &self.value)?;
        state.end()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Height {
    Confirmed { height: usize },
    Unconfirmed { has_unconfirmed_inputs: bool },
}

impl Height {
    fn as_i64(&self) -> i64 {
        match self {
            Self::Confirmed { height } => *height as i64,
            Self::Unconfirmed {
                has_unconfirmed_inputs: true,
            } => -1,
            Self::Unconfirmed {
                has_unconfirmed_inputs: false,
            } => 0,
        }
    }
}

impl Serialize for Height {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_i64(self.as_i64())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HistoryEntry {
    txid: Txid,
    height: Height,
    fee: Option<u64>,
}

impl HistoryEntry {
    fn confirmed(txid: Txid, height: usize, fee: Option<u64>) -> Self {
        Self {
            txid,
            height: Height::Confirmed { height },
            fee,
        }
    }

    fn unconfirmed(txid: Txid, has_unconfirmed_inputs: bool, fee: u64) -> Self {
        Self {
            txid,
            height: Height::Unconfirmed {
                has_unconfirmed_inputs,
            },
            fee: Some(fee),
        }
    }

    #[cfg(feature = "backend-rpp-stark")]
    fn hash(&self, hasher: &mut RppStarkHasher) {
        hasher.update(self.txid.as_bytes());
        hasher.update(&self.height.as_i64().to_le_bytes());
    }

    #[cfg(not(feature = "backend-rpp-stark"))]
    fn append_encoded(&self, output: &mut Vec<u8>) {
        output.extend_from_slice(self.txid.as_bytes());
        output.extend_from_slice(&self.height.as_i64().to_le_bytes());
    }
}

impl Serialize for HistoryEntry {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("HistoryEntry", 3)?;
        state.serialize_field("tx_hash", &hex_string(self.txid.as_bytes()))?;
        state.serialize_field("height", &self.height)?;
        if let Some(fee) = self.fee {
            state.serialize_field("fee", &fee)?;
        }
        state.end()
    }
}

#[derive(Clone, Debug)]
pub struct ScriptHashStatus {
    scripthash: ScriptHash,
    tip: BlockHash,
    history: Vec<HistoryEntry>,
    statushash: Option<StatusDigest>,
    confirmed_balance: u64,
    mempool_delta: i64,
    unspent: Vec<UnspentEntry>,
}

impl ScriptHashStatus {
    /// Create a new status tracker for the given script hash.
    pub fn new(scripthash: ScriptHash) -> Self {
        Self {
            scripthash,
            tip: BlockHash::default(),
            history: Vec::new(),
            statushash: None,
            confirmed_balance: 0,
            mempool_delta: 0,
            unspent: Vec::new(),
        }
    }

    /// Recompute the confirmed history for `script`.
    pub fn sync(
        &mut self,
        script: &Script,
        index: &Index,
        chain: &Chain,
        mempool: Option<&MempoolStatus>,
    ) -> anyhow::Result<()> {
        let confirmed = index.script_history(script);
        self.tip = chain.tip();
        let mut history = Vec::new();
        let mut seen: HashSet<(usize, Txid)> = HashSet::new();
        let mut ordered = Vec::new();
        let mut outputs: HashMap<OutPoint, (usize, u64)> = HashMap::new();
        let mut balance: u128 = 0;

        for (height, txid) in confirmed {
            if seen.insert((height, txid)) {
                ordered.push((height, txid));
            }
        }

        ordered.sort_by(|(left_height, left_txid), (right_height, right_txid)| {
            left_height
                .cmp(right_height)
                .then_with(|| left_txid.as_bytes().cmp(right_txid.as_bytes()))
        });

        for (height, txid) in ordered {
            let transaction = index
                .transaction_at(height, txid)?
                .with_context(|| anyhow!("transaction {txid:?} at height {height} missing"))?;
            process_confirmed_transaction(
                &transaction,
                height,
                txid,
                &self.scripthash,
                &mut outputs,
                &mut balance,
                &mut history,
            )?;
        }

        let mut unspent: Vec<UnspentEntry> = outputs
            .into_iter()
            .map(|(outpoint, (height, value))| UnspentEntry {
                height,
                tx_hash: outpoint.txid,
                tx_pos: outpoint.vout,
                value,
            })
            .collect();
        unspent.sort_by_key(|entry| (entry.height, entry.tx_pos));

        let mut mempool_delta: i128 = 0;
        if let Some(status) = mempool {
            let mut mempool_history = process_mempool(
                status,
                &self.scripthash,
                &mut mempool_delta,
            )?;
            history.append(&mut mempool_history);
        }

        self.confirmed_balance = balance.min(u128::from(u64::MAX)) as u64;
        self.mempool_delta = mempool_delta
            .clamp(i128::from(i64::MIN), i128::from(i64::MAX))
            as i64;
        self.unspent = unspent;
        self.history = history;
        self.statushash = compute_statushash(&self.history);
        Ok(())
    }

    /// Latest block hash observed while syncing the status.
    pub fn tip(&self) -> BlockHash {
        self.tip
    }

    /// Script hash being tracked.
    pub fn scripthash(&self) -> &ScriptHash {
        &self.scripthash
    }

    /// Access the computed history entries.
    pub fn get_history(&self) -> &[HistoryEntry] {
        &self.history
    }

    /// Compute the balance of tracked entries derived from confirmed history and
    /// observed mempool deltas.
    pub fn get_balance(&self, _chain: &Chain) -> Balance {
        Balance {
            confirmed_balance: self.confirmed_balance,
            mempool_delta: self.mempool_delta,
        }
    }

    /// List all confirmed unspent outputs for the tracked script hash.
    pub fn get_unspent(&self, _chain: &Chain) -> Vec<UnspentEntry> {
        self.unspent.clone()
    }

    /// Hash of the status history as defined by the Electrum protocol.
    pub fn statushash(&self) -> Option<StatusDigest> {
        self.statushash
    }
}

fn process_confirmed_transaction(
    transaction: &Transaction,
    height: usize,
    txid: Txid,
    scripthash: &ScriptHash,
    outputs: &mut HashMap<OutPoint, (usize, u64)>,
    balance: &mut u128,
    history: &mut Vec<HistoryEntry>,
) -> anyhow::Result<()> {
    let memo = parse_memo(transaction.memo());
    let fee = memo.as_ref().and_then(|memo| memo.fee);
    history.push(HistoryEntry::confirmed(txid, height, fee));

    for input in transaction.inputs() {
        if let Some((_, value)) = outputs.remove(input) {
            *balance = balance.saturating_sub(u128::from(value));
        }
    }

    for (index_pos, output) in transaction.outputs().iter().enumerate() {
        let output_hash = ScriptHash::new(output);
        if &output_hash != scripthash {
            continue;
        }
        if let Some(amount) = extract_value(output, memo.as_ref())? {
            *balance = balance.saturating_add(u128::from(amount));
            let outpoint = OutPoint::new(txid, index_pos as u32);
            outputs.insert(outpoint, (height, amount));
        }
    }

    Ok(())
}

fn process_mempool(
    status: &MempoolStatus,
    scripthash: &ScriptHash,
    delta: &mut i128,
) -> anyhow::Result<Vec<HistoryEntry>> {
    let mut history = Vec::new();
    for tx in &status.transactions {
        if let Some((entry, amount)) = mempool_entry(tx, scripthash)? {
            *delta += i128::from(amount);
            history.push(entry);
        }
    }
    Ok(history)
}

fn mempool_entry(
    tx: &PendingTransactionSummary,
    scripthash: &ScriptHash,
) -> anyhow::Result<Option<(HistoryEntry, u64)>> {
    let txid = decode_txid(&tx.hash);
    let script = Script::new(format!("to:{}:{}", tx.to, tx.amount).into_bytes());
    if ScriptHash::new(&script) != *scripthash {
        return Ok(None);
    }
    let amount = u64::try_from(tx.amount).context("mempool amount exceeds u64")?;
    let entry = HistoryEntry::unconfirmed(txid, false, tx.fee);
    Ok(Some((entry, amount)))
}

fn decode_txid(hash: &str) -> Txid {
    let trimmed = hash.trim_start_matches("0x");
    if let Ok(bytes) = hex::decode(trimmed) {
        if bytes.len() == 32 {
            let mut array = [0u8; 32];
            array.copy_from_slice(&bytes);
            return Txid::from_bytes(array);
        }
    }
    let digest = sha256::Hash::hash(hash.as_bytes()).into_inner();
    Txid::from_bytes(digest)
}

fn extract_value(script: &Script, memo: Option<&Memo>) -> anyhow::Result<Option<u64>> {
    let script_info = parse_script(script)?;
    match script_info {
        ScriptRole::To { amount, .. } => {
            let value = u64::try_from(amount).context("output amount exceeds u64")?;
            Ok(Some(value))
        }
        ScriptRole::From { .. } => {
            if let Some(memo) = memo {
                if let Some(amount) = memo.amount {
                    let total = amount
                        .checked_add(u128::from(memo.fee.unwrap_or(0)))
                        .ok_or_else(|| anyhow!("overflow computing memo total"))?;
                    let value = u64::try_from(total).context("memo total exceeds u64")?;
                    return Ok(Some(value));
                }
            }
            Ok(None)
        }
    }
}

fn parse_script(script: &Script) -> anyhow::Result<ScriptRole> {
    let text = std::str::from_utf8(script.as_bytes())
        .map_err(|err| anyhow!("invalid script encoding: {err}"))?;
    let mut parts = text.split(':');
    let kind = parts.next().unwrap_or_default();
    let address = parts
        .next()
        .ok_or_else(|| anyhow!("script missing address component"))?;
    let value = parts
        .next()
        .ok_or_else(|| anyhow!("script missing value component"))?;
    match kind {
        "to" => {
            let amount: u128 = value
                .parse()
                .map_err(|err| anyhow!("invalid to-script amount: {err}"))?;
            Ok(ScriptRole::To {
                address: address.to_string(),
                amount,
            })
        }
        "from" => {
            let fee: u64 = value
                .parse()
                .map_err(|err| anyhow!("invalid from-script fee: {err}"))?;
            Ok(ScriptRole::From {
                address: address.to_string(),
                fee,
            })
        }
        _ => Err(anyhow!("unsupported script kind")),
    }
}

#[derive(Clone, Debug)]
struct Memo {
    from: String,
    to: String,
    amount: Option<u128>,
    fee: Option<u64>,
}

fn parse_memo(memo: &[u8]) -> Option<Memo> {
    let text = std::str::from_utf8(memo).ok()?;
    let mut from = None;
    let mut to = None;
    let mut amount = None;
    let mut fee = None;

    for entry in text.split(';') {
        let mut parts = entry.splitn(2, '=');
        let key = parts.next()?;
        let value = parts.next().unwrap_or("");
        match key {
            "from" => from = Some(value.to_string()),
            "to" => to = Some(value.to_string()),
            "amount" => {
                if let Ok(parsed) = value.parse() {
                    amount = Some(parsed);
                }
            }
            "fee" => {
                if let Ok(parsed) = value.parse() {
                    fee = Some(parsed);
                }
            }
            _ => {}
        }
    }

    Some(Memo {
        from: from?,
        to: to?,
        amount,
        fee,
    })
}

#[derive(Clone, Debug)]
enum ScriptRole {
    To { address: String, amount: u128 },
    From { address: String, fee: u64 },
}

#[cfg(feature = "backend-rpp-stark")]
fn compute_statushash(history: &[HistoryEntry]) -> Option<StatusDigest> {
    if history.is_empty() {
        return None;
    }
    let mut hasher = RppStarkHasher::new();
    for entry in history {
        entry.hash(&mut hasher);
    }
    let digest: Digest32 = hasher.finalize();
    Some(StatusDigest::from_digest(digest))
}

#[cfg(not(feature = "backend-rpp-stark"))]
fn compute_statushash(history: &[HistoryEntry]) -> Option<StatusDigest> {
    if history.is_empty() {
        return None;
    }
    const TXID_BYTES: usize = 32;
    let mut encoded = Vec::with_capacity(history.len() * (TXID_BYTES + std::mem::size_of::<i64>()));
    for entry in history {
        entry.append_encoded(&mut encoded);
    }
    let digest = sha256::Hash::hash(&encoded).into_inner();
    Some(StatusDigest::from_bytes(digest))
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::fs;

    use hex::encode;
    use tempfile::TempDir;

    use crate::vendor::electrs::daemon::test_helpers::setup;
    use crate::vendor::electrs::index::Index;
    use crate::vendor::electrs::rpp_ledger::bitcoin::Network;
    use crate::vendor::electrs::tracker::Tracker;
    use rpp::runtime::config::QueueWeightsConfig;

    #[test]
    fn sync_derives_balance_and_unspent_outputs() {
        let temp_dir = TempDir::new().expect("tempdir");
        let index_path = temp_dir.path().join("index");
        fs::create_dir_all(&index_path).expect("index dir");

        let index = Index::open(&index_path, Network::Regtest).expect("open index");
        let mut tracker = Tracker::new(index);
        let context = setup();

        tracker.sync(&context.daemon).expect("sync tracker");

        let transaction = tracker
            .index()
            .transaction_at(1, context.transaction_id)
            .expect("transaction lookup")
            .expect("transaction present");
        let script = transaction.outputs().first().expect("output").clone();
        let scripthash = ScriptHash::new(&script);

        let mut status = ScriptHashStatus::new(scripthash);
        status
            .sync(&script, tracker.index(), tracker.chain(), None)
            .expect("sync status");

        let balance = status.get_balance(tracker.chain());
        assert!(balance.confirmed() > 0);
        assert_eq!(balance.mempool_delta(), 0);

        let unspent = status.get_unspent(tracker.chain());
        assert!(!unspent.is_empty());
        assert_eq!(unspent[0].value, balance.confirmed());

        let baseline = status.statushash();

        let script_text = std::str::from_utf8(script.as_bytes()).expect("script text");
        let mut parts = script_text.split(':');
        let _ = parts.next();
        let address = parts.next().expect("address");
        let amount = parts
            .next()
            .expect("amount")
            .parse::<u128>()
            .expect("parse amount");

        let pending = PendingTransactionSummary {
            hash: encode([3u8; 32]),
            from: "mempool-from".to_string(),
            to: address.to_string(),
            amount,
            fee: 7,
            nonce: 1,
        };
        let mempool = MempoolStatus {
            transactions: vec![pending],
            identities: Vec::new(),
            votes: Vec::new(),
            uptime_proofs: Vec::new(),
            queue_weights: QueueWeightsConfig::default(),
        };

        status
            .sync(&script, tracker.index(), tracker.chain(), Some(&mempool))
            .expect("sync with mempool");

        let updated = status.get_balance(tracker.chain());
        assert_eq!(updated.confirmed(), balance.confirmed());
        let expected_delta = i64::try_from(amount).expect("delta fits in i64");
        assert_eq!(updated.mempool_delta(), expected_delta);

        assert_ne!(baseline, status.statushash());
        assert!(status
            .get_history()
            .iter()
            .any(|entry| matches!(entry.height, Height::Unconfirmed { .. })));
    }
}
