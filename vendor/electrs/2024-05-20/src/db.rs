use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

use crate::vendor::electrs::firewood_adapter::FirewoodAdapter;
use crate::vendor::electrs::rpp_ledger::bitcoin::blockdata::block::Header as BlockHeader;
use crate::vendor::electrs::rpp_ledger::bitcoin::{BlockHash, Txid};
use crate::vendor::electrs::types::{
    HashPrefix, HashPrefixRow, HeaderRow, SerBlock, SerializedHashPrefixRow,
    SerializedHeaderRow, HASH_PREFIX_ROW_SIZE,
};

const PREFIX_HEADER: u8 = b'h';
const PREFIX_BLOCK: u8 = b'b';
const PREFIX_SCRIPT: u8 = b's';
const PREFIX_SPENDING: u8 = b'p';
const PREFIX_TXID: u8 = b't';
const KEY_TIP: &[u8] = b"meta:tip";

#[derive(Default)]
pub struct WriteBatch {
    puts: Vec<(Vec<u8>, Vec<u8>)>,
    tip_row: Option<TipRow>,
}

impl WriteBatch {
    pub fn put_header(&mut self, height: usize, row: &HeaderRow) {
        let key = header_key(height);
        self.puts.push((key, row.to_db_row().to_vec()));
    }

    pub fn put_block(&mut self, height: usize, block: &SerBlock) {
        let key = block_key(height);
        self.puts.push((key, block.clone()));
    }

    pub fn put_script(&mut self, row: HashPrefixRow, txid: Txid) {
        let key = hash_prefix_key(PREFIX_SCRIPT, row);
        self.puts.push((key, txid.as_bytes().to_vec()));
    }

    pub fn put_spending(&mut self, row: HashPrefixRow, txid: Txid) {
        let key = hash_prefix_key(PREFIX_SPENDING, row);
        self.puts.push((key, txid.as_bytes().to_vec()));
    }

    pub fn put_txid(&mut self, row: HashPrefixRow, txid: Txid) {
        let key = hash_prefix_key(PREFIX_TXID, row);
        self.puts.push((key, txid.as_bytes().to_vec()));
    }

    pub fn set_tip(&mut self, height: usize, blockhash: BlockHash) {
        self.tip_row = Some(TipRow::new(height as u32, blockhash));
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TipRow {
    pub(crate) height: u32,
    pub(crate) blockhash: BlockHash,
}

impl TipRow {
    fn new(height: u32, blockhash: BlockHash) -> Self {
        Self { height, blockhash }
    }

    fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(4 + 32);
        buf.extend_from_slice(&self.height.to_le_bytes());
        buf.extend_from_slice(self.blockhash.as_bytes());
        buf
    }

    fn decode(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != 36 {
            return None;
        }
        let mut height_bytes = [0u8; 4];
        height_bytes.copy_from_slice(&bytes[..4]);
        let mut hash_bytes = [0u8; 32];
        hash_bytes.copy_from_slice(&bytes[4..]);
        Some(Self {
            height: u32::from_le_bytes(height_bytes),
            blockhash: BlockHash::from_bytes(hash_bytes),
        })
    }

    pub fn height(&self) -> usize {
        self.height as usize
    }
}

#[derive(Debug)]
pub struct Db {
    store: FirewoodAdapter,
    _path: PathBuf,
}

impl Db {
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        let store = FirewoodAdapter::open(path)?;
        Ok(Self {
            store,
            _path: path.to_path_buf(),
        })
    }

    pub fn read_tip(&self) -> Result<Option<TipRow>> {
        Ok(self.store.get(KEY_TIP).as_deref().and_then(TipRow::decode))
    }

    pub fn load_headers(&self) -> Result<Vec<(usize, BlockHeader)>> {
        let mut entries = self
            .store
            .scan_prefix(&[PREFIX_HEADER])
            .into_iter()
            .filter_map(|(key, value)| {
                if key.len() != 1 + std::mem::size_of::<u32>() {
                    return None;
                }
                let mut height_bytes = [0u8; 4];
                height_bytes.copy_from_slice(&key[1..]);
                let array: SerializedHeaderRow = value.try_into().ok()?;
                let header = HeaderRow::from_db_row(array).header;
                Some((u32::from_le_bytes(height_bytes) as usize, header))
            })
            .collect::<Vec<_>>();
        entries.sort_by_key(|(height, _)| *height);
        Ok(entries)
    }

    pub fn write(&mut self, mut batch: WriteBatch) -> Result<()> {
        for (key, value) in batch.puts.drain(..) {
            self.store.put(key, value);
        }
        if let Some(tip) = batch.tip_row.take() {
            self.store.put(KEY_TIP.to_vec(), tip.encode());
        }
        self.store.commit().context("commit write batch")?;
        Ok(())
    }

    pub fn scan_scripthash(
        &self,
        prefix: HashPrefix,
    ) -> Vec<(HashPrefixRow, Txid)> {
        self.scan_prefix(PREFIX_SCRIPT, prefix)
    }

    pub fn scan_spending(
        &self,
        prefix: HashPrefix,
    ) -> Vec<(HashPrefixRow, Txid)> {
        self.scan_prefix(PREFIX_SPENDING, prefix)
    }

    pub fn scan_txid(&self, prefix: HashPrefix) -> Vec<(HashPrefixRow, Txid)> {
        self.scan_prefix(PREFIX_TXID, prefix)
    }

    fn scan_prefix(&self, kind: u8, prefix: HashPrefix) -> Vec<(HashPrefixRow, Txid)> {
        let mut key_prefix = Vec::with_capacity(1 + prefix.len());
        key_prefix.push(kind);
        key_prefix.extend_from_slice(&prefix);
        self.store
            .scan_prefix(&key_prefix)
            .into_iter()
            .filter_map(|(key, value)| {
                if key.len() != 1 + HASH_PREFIX_ROW_SIZE {
                    return None;
                }
                let array: SerializedHashPrefixRow = key[1..].try_into().ok()?;
                let row = HashPrefixRow::from_db_row(array);
                let txid_bytes: [u8; 32] = value.try_into().ok()?;
                Some((row, Txid::from_bytes(txid_bytes)))
            })
            .collect()
    }

    pub fn get_block(&self, height: usize) -> Option<SerBlock> {
        self.store.get(&block_key(height))
    }
}

fn header_key(height: usize) -> Vec<u8> {
    let mut key = Vec::with_capacity(5);
    key.push(PREFIX_HEADER);
    key.extend_from_slice(&(height as u32).to_le_bytes());
    key
}

fn block_key(height: usize) -> Vec<u8> {
    let mut key = Vec::with_capacity(5);
    key.push(PREFIX_BLOCK);
    key.extend_from_slice(&(height as u32).to_le_bytes());
    key
}

fn hash_prefix_key(kind: u8, row: HashPrefixRow) -> Vec<u8> {
    let mut key = Vec::with_capacity(1 + HASH_PREFIX_ROW_SIZE);
    key.push(kind);
    key.extend_from_slice(&row.to_db_row());
    key
}
