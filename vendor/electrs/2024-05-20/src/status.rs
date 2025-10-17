use serde::ser::{Serialize, SerializeStruct, Serializer};
use sha2::{Digest, Sha256};

use crate::vendor::electrs::chain::Chain;
use crate::vendor::electrs::index::Index;
use crate::vendor::electrs::rpp_ledger::bitcoin::{
    hashes::sha256,
    BlockHash,
    Script,
    Txid,
};
use crate::vendor::electrs::types::{ScriptHash, StatusHash};

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
    fn confirmed(txid: Txid, height: usize) -> Self {
        Self {
            txid,
            height: Height::Confirmed { height },
            fee: None,
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

    fn hash(&self, hasher: &mut Sha256) {
        let s = format!(
            "{}:{}:",
            hex_string(self.txid.as_bytes()),
            self.height.as_i64()
        );
        hasher.update(s.as_bytes());
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
    statushash: Option<StatusHash>,
}

impl ScriptHashStatus {
    /// Create a new status tracker for the given script hash.
    pub fn new(scripthash: ScriptHash) -> Self {
        Self {
            scripthash,
            tip: BlockHash::default(),
            history: Vec::new(),
            statushash: None,
        }
    }

    /// Recompute the confirmed history for `script`.
    pub fn sync(&mut self, script: &Script, index: &Index, chain: &Chain) -> anyhow::Result<()> {
        let confirmed = index.script_history(script);
        self.tip = chain.tip();
        self.history = confirmed
            .into_iter()
            .map(|(height, txid)| HistoryEntry::confirmed(txid, height))
            .collect();
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

    /// Compute the balance of tracked entries. The placeholder backend does not
    /// maintain value information yet, so the result is always zeroed.
    pub fn get_balance(&self, _chain: &Chain) -> Balance {
        Balance::default()
    }

    /// List all unspent outputs for the tracked script hash. The current
    /// harness does not index per-output values, so this is empty.
    pub fn get_unspent(&self, _chain: &Chain) -> Vec<UnspentEntry> {
        Vec::new()
    }

    /// Hash of the status history as defined by the Electrum protocol.
    pub fn statushash(&self) -> Option<StatusHash> {
        self.statushash
    }
}

fn compute_statushash(history: &[HistoryEntry]) -> Option<StatusHash> {
    if history.is_empty() {
        return None;
    }
    let mut hasher = Sha256::new();
    for entry in history {
        entry.hash(&mut hasher);
    }
    let digest: [u8; 32] = hasher.finalize().into();
    let hash = sha256::Hash::from_slice(&digest).expect("valid sha256 length");
    Some(StatusHash(hash))
}
