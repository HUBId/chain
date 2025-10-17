use crate::vendor::electrs::rpp_ledger::bitcoin::{
    blockdata::block::Header as BlockHeader,
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
pub(crate) struct HashPrefixRow {
    prefix: HashPrefix,
    height: Height,
}

pub const HASH_PREFIX_ROW_SIZE: usize = HASH_PREFIX_LEN + HEIGHT_SIZE;

impl HashPrefixRow {
    pub(crate) fn to_db_row(&self) -> SerializedHashPrefixRow {
        todo!("vendor_electrs: implement serialization via rpp-ledger consensus encode");
    }

    pub(crate) fn from_db_row(_row: SerializedHashPrefixRow) -> Self {
        todo!("vendor_electrs: implement deserialization via rpp-ledger consensus encode");
    }

    pub fn height(&self) -> usize {
        self.height as usize
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScriptHash(pub sha256::Hash);

impl ScriptHash {
    pub fn new(_script: &Script) -> Self {
        todo!("vendor_electrs: compute script hash via rpp-ledger");
    }

    fn prefix(&self) -> HashPrefix {
        todo!("vendor_electrs: derive script hash prefix via rpp-ledger");
    }
}

pub(crate) struct ScriptHashRow;

impl ScriptHashRow {
    pub(crate) fn scan_prefix(_scripthash: ScriptHash) -> HashPrefix {
        todo!("vendor_electrs: scan script hash prefix via rpp-ledger");
    }

    pub(crate) fn row(_scripthash: ScriptHash, _height: usize) -> HashPrefixRow {
        HashPrefixRow {
            prefix: todo!("vendor_electrs: build script hash prefix row"),
            height: todo!("vendor_electrs: convert height for script hash row"),
        }
    }
}

pub struct StatusHash(pub sha256::Hash);

fn spending_prefix(_prev: OutPoint) -> HashPrefix {
    todo!("vendor_electrs: compute spending prefix via rpp-ledger");
}

pub(crate) struct SpendingPrefixRow;

impl SpendingPrefixRow {
    pub(crate) fn scan_prefix(_outpoint: OutPoint) -> HashPrefix {
        todo!("vendor_electrs: scan spending prefix via rpp-ledger");
    }

    pub(crate) fn row(_outpoint: OutPoint, _height: usize) -> HashPrefixRow {
        HashPrefixRow {
            prefix: todo!("vendor_electrs: build spending prefix row"),
            height: todo!("vendor_electrs: convert height for spending prefix row"),
        }
    }
}

fn txid_prefix(_txid: &Txid) -> HashPrefix {
    todo!("vendor_electrs: compute txid prefix via rpp-ledger");
}

pub(crate) struct TxidRow;

impl TxidRow {
    pub(crate) fn scan_prefix(_txid: Txid) -> HashPrefix {
        todo!("vendor_electrs: scan txid prefix via rpp-ledger");
    }

    pub(crate) fn row(_txid: Txid, _height: usize) -> HashPrefixRow {
        HashPrefixRow {
            prefix: todo!("vendor_electrs: build txid prefix row"),
            height: todo!("vendor_electrs: convert height for txid prefix row"),
        }
    }
}

pub(crate) type SerializedHeaderRow = [u8; HEADER_ROW_SIZE];

#[derive(Debug, Clone)]
pub(crate) struct HeaderRow {
    pub(crate) header: BlockHeader,
}

pub const HEADER_ROW_SIZE: usize = 80;

impl HeaderRow {
    pub(crate) fn new(header: BlockHeader) -> Self {
        Self { header }
    }

    pub(crate) fn to_db_row(&self) -> SerializedHeaderRow {
        todo!("vendor_electrs: encode header row via rpp-ledger");
    }

    pub(crate) fn from_db_row(_row: SerializedHeaderRow) -> Self {
        todo!("vendor_electrs: decode header row via rpp-ledger");
    }
}

pub(crate) fn bsl_txid(_tx: &bsl::Transaction) -> Txid {
    todo!("vendor_electrs: convert bsl transaction to txid via rpp-ledger");
}

#[cfg(test)]
mod tests {
    // TODO: Re-aktivieren, sobald rpp-ledger-Typen verfügbar sind.
}
