use sha2::{Digest, Sha256};

use crate::vendor::electrs::rpp_ledger::bitcoin::{
    blockdata::block::Header as BlockHeader,
    consensus::encode::{deserialize, serialize},
    hashes::sha256,
    OutPoint,
    Script,
    Txid,
};
use crate::vendor::electrs::rpp_ledger::bitcoin_slices::bsl;

pub const HASH_PREFIX_LEN: usize = 8;
const HEIGHT_SIZE: usize = 4;

pub(crate) type HashPrefix = [u8; HASH_PREFIX_LEN];
pub(crate) type SerializedHashPrefixRow = [u8; HASH_PREFIX_ROW_SIZE];
type Height = u32;
pub(crate) type SerBlock = Vec<u8>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HashPrefixRow {
    prefix: HashPrefix,
    height: Height,
}

pub const HASH_PREFIX_ROW_SIZE: usize = HASH_PREFIX_LEN + HEIGHT_SIZE;

impl HashPrefixRow {
    pub fn to_db_row(&self) -> SerializedHashPrefixRow {
        let mut row = [0u8; HASH_PREFIX_ROW_SIZE];
        row[..HASH_PREFIX_LEN].copy_from_slice(&self.prefix);
        row[HASH_PREFIX_LEN..].copy_from_slice(&self.height.to_le_bytes());
        row
    }

    pub fn from_db_row(row: SerializedHashPrefixRow) -> Self {
        let mut prefix = [0u8; HASH_PREFIX_LEN];
        prefix.copy_from_slice(&row[..HASH_PREFIX_LEN]);
        let mut height_bytes = [0u8; HEIGHT_SIZE];
        height_bytes.copy_from_slice(&row[HASH_PREFIX_LEN..]);
        let height = Height::from_le_bytes(height_bytes);
        Self { prefix, height }
    }

    pub fn height(&self) -> usize {
        self.height as usize
    }

    pub fn prefix(&self) -> HashPrefix {
        self.prefix
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScriptHash(pub sha256::Hash);

impl ScriptHash {
    pub fn new(script: &Script) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(&(script.as_bytes().len() as u32).to_le_bytes());
        hasher.update(script.as_bytes());
        Self(sha256::Hash(hasher.finalize().into()))
    }

    fn prefix(&self) -> HashPrefix {
        let mut prefix = [0u8; HASH_PREFIX_LEN];
        prefix.copy_from_slice(&self.0.as_bytes()[..HASH_PREFIX_LEN]);
        prefix
    }
}

pub(crate) struct ScriptHashRow;

impl ScriptHashRow {
    pub(crate) fn scan_prefix(scripthash: ScriptHash) -> HashPrefix {
        scripthash.prefix()
    }

    pub(crate) fn row(scripthash: ScriptHash, height: usize) -> HashPrefixRow {
        HashPrefixRow {
            prefix: scripthash.prefix(),
            height: height as Height,
        }
    }
}

pub struct StatusHash(pub sha256::Hash);

fn spending_prefix(prev: OutPoint) -> HashPrefix {
    let mut hasher = Sha256::new();
    hasher.update(prev.txid.as_bytes());
    hasher.update(prev.vout.to_le_bytes());
    let digest: [u8; 32] = hasher.finalize().into();
    let mut prefix = [0u8; HASH_PREFIX_LEN];
    prefix.copy_from_slice(&digest[..HASH_PREFIX_LEN]);
    prefix
}

pub(crate) struct SpendingPrefixRow;

impl SpendingPrefixRow {
    pub(crate) fn scan_prefix(outpoint: OutPoint) -> HashPrefix {
        spending_prefix(outpoint)
    }

    pub(crate) fn row(outpoint: OutPoint, height: usize) -> HashPrefixRow {
        HashPrefixRow {
            prefix: spending_prefix(outpoint),
            height: height as Height,
        }
    }
}

fn txid_prefix(txid: &Txid) -> HashPrefix {
    let mut prefix = [0u8; HASH_PREFIX_LEN];
    prefix.copy_from_slice(&txid.as_bytes()[..HASH_PREFIX_LEN]);
    prefix
}

pub(crate) struct TxidRow;

impl TxidRow {
    pub(crate) fn scan_prefix(txid: Txid) -> HashPrefix {
        txid_prefix(&txid)
    }

    pub(crate) fn row(txid: Txid, height: usize) -> HashPrefixRow {
        HashPrefixRow {
            prefix: txid_prefix(&txid),
            height: height as Height,
        }
    }
}

pub(crate) type SerializedHeaderRow = [u8; HEADER_ROW_SIZE];

#[derive(Debug, Clone)]
pub struct HeaderRow {
    pub(crate) header: BlockHeader,
}

pub const HEADER_ROW_SIZE: usize = 232;

impl HeaderRow {
    pub fn new(header: BlockHeader) -> Self {
        Self { header }
    }

    pub fn to_db_row(&self) -> SerializedHeaderRow {
        let encoded = serialize(&self.header);
        let mut row = [0u8; HEADER_ROW_SIZE];
        row[..encoded.len()].copy_from_slice(&encoded);
        row
    }

    pub fn from_db_row(row: SerializedHeaderRow) -> Self {
        let header = deserialize(&row).expect("valid header row");
        Self { header }
    }
}

pub(crate) fn bsl_txid(tx: &bsl::Transaction) -> Txid {
    Txid(tx.txid_sha2().0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vendor::electrs::rpp_ledger::bitcoin::Script;

    #[test]
    fn hash_prefix_roundtrip() {
        let row = HashPrefixRow {
            prefix: [1, 2, 3, 4, 5, 6, 7, 8],
            height: 42,
        };
        let encoded = row.to_db_row();
        let decoded = HashPrefixRow::from_db_row(encoded);
        assert_eq!(decoded.prefix(), row.prefix());
        assert_eq!(decoded.height(), row.height());
    }

    #[test]
    fn script_hash_prefix() {
        let script = Script::new(vec![1, 2, 3]);
        let hash = ScriptHash::new(&script);
        assert_eq!(hash.prefix().len(), HASH_PREFIX_LEN);
    }
}
