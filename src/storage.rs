use std::convert::TryInto;
use std::path::Path;
use std::sync::Arc;

use parking_lot::Mutex;
use storage_firewood::kv::FirewoodKv;

use crate::errors::{ChainError, ChainResult};
use crate::types::{Account, Block, BlockMetadata, StoredBlock};

pub const STORAGE_SCHEMA_VERSION: u32 = 1;

const PREFIX_BLOCK: u8 = b'b';
const PREFIX_ACCOUNT: u8 = b'a';
const PREFIX_METADATA: u8 = b'm';
const TIP_HEIGHT_KEY: &[u8] = b"tip_height";
const TIP_HASH_KEY: &[u8] = b"tip_hash";
const TIP_TIMESTAMP_KEY: &[u8] = b"tip_timestamp";
pub(crate) const SCHEMA_VERSION_KEY: &[u8] = b"schema_version";

pub struct Storage {
    kv: Arc<Mutex<FirewoodKv>>,
}

impl Storage {
    pub fn open(path: &Path) -> ChainResult<Self> {
        let kv = FirewoodKv::open(path)?;
        let storage = Self {
            kv: Arc::new(Mutex::new(kv)),
        };
        storage.ensure_schema_supported()?;
        Ok(storage)
    }

    fn ensure_schema_supported(&self) -> ChainResult<()> {
        let version = self.read_schema_version()?;
        match version {
            Some(version) if version > STORAGE_SCHEMA_VERSION => Err(ChainError::Config(format!(
                "database schema version {version} is newer than supported {STORAGE_SCHEMA_VERSION}"
            ))),
            Some(version) if version < STORAGE_SCHEMA_VERSION => {
                Err(ChainError::MigrationRequired {
                    found: version,
                    required: STORAGE_SCHEMA_VERSION,
                })
            }
            Some(_) => Ok(()),
            None => {
                if self.is_empty()? {
                    self.write_schema_version(STORAGE_SCHEMA_VERSION)?;
                    Ok(())
                } else {
                    Err(ChainError::MigrationRequired {
                        found: 0,
                        required: STORAGE_SCHEMA_VERSION,
                    })
                }
            }
        }
    }

    fn is_empty(&self) -> ChainResult<bool> {
        let kv = self.kv.lock();
        if kv.scan_prefix(&[PREFIX_BLOCK]).next().is_some() {
            return Ok(false);
        }
        if kv.scan_prefix(&[PREFIX_ACCOUNT]).next().is_some() {
            return Ok(false);
        }
        if kv.get(&metadata_key(TIP_HEIGHT_KEY)).is_some() {
            return Ok(false);
        }
        Ok(true)
    }

    fn read_schema_version(&self) -> ChainResult<Option<u32>> {
        let kv = self.kv.lock();
        Self::read_schema_version_raw(&kv)
    }

    pub fn schema_version(&self) -> ChainResult<u32> {
        Ok(self
            .read_schema_version()?
            .unwrap_or(STORAGE_SCHEMA_VERSION))
    }

    fn write_schema_version(&self, version: u32) -> ChainResult<()> {
        let mut kv = self.kv.lock();
        Self::write_schema_version_raw(&mut kv, version)
    }

    pub(crate) fn write_schema_version_raw(kv: &mut FirewoodKv, version: u32) -> ChainResult<()> {
        kv.put(
            metadata_key(SCHEMA_VERSION_KEY),
            version.to_be_bytes().to_vec(),
        );
        kv.commit()?;
        Ok(())
    }

    pub(crate) fn read_schema_version_raw(kv: &FirewoodKv) -> ChainResult<Option<u32>> {
        match kv.get(&metadata_key(SCHEMA_VERSION_KEY)) {
            Some(bytes) => {
                let bytes: [u8; 4] = bytes
                    .as_slice()
                    .try_into()
                    .map_err(|_| ChainError::Config("invalid schema version encoding".into()))?;
                Ok(Some(u32::from_be_bytes(bytes)))
            }
            None => Ok(None),
        }
    }

    pub(crate) fn open_db(path: &Path) -> ChainResult<FirewoodKv> {
        FirewoodKv::open(path).map_err(ChainError::from)
    }

    pub fn store_block(&self, block: &Block) -> ChainResult<()> {
        let mut kv = self.kv.lock();
        let key = block_key(block.header.height);
        let record = StoredBlock::from_block(block);
        let data = bincode::serialize(&record)?;
        kv.put(key, data);
        kv.put(
            metadata_key(TIP_HEIGHT_KEY),
            block.header.height.to_be_bytes().to_vec(),
        );
        kv.put(metadata_key(TIP_HASH_KEY), block.hash.as_bytes().to_vec());
        kv.put(
            metadata_key(TIP_TIMESTAMP_KEY),
            block.header.timestamp.to_be_bytes().to_vec(),
        );
        kv.commit()?;
        Ok(())
    }

    pub fn read_block(&self, height: u64) -> ChainResult<Option<Block>> {
        let kv = self.kv.lock();
        let key = block_key(height);
        match kv.get(&key) {
            Some(value) => {
                let record: StoredBlock = bincode::deserialize(&value)?;
                Ok(Some(record.into_block()))
            }
            None => Ok(None),
        }
    }

    pub(crate) fn read_block_record(&self, height: u64) -> ChainResult<Option<StoredBlock>> {
        let kv = self.kv.lock();
        let key = block_key(height);
        match kv.get(&key) {
            Some(value) => Ok(Some(bincode::deserialize(&value)?)),
            None => Ok(None),
        }
    }

    pub fn load_blockchain(&self) -> ChainResult<Vec<Block>> {
        let kv = self.kv.lock();
        let entries: Vec<(Vec<u8>, Vec<u8>)> = kv.scan_prefix(&[PREFIX_BLOCK]).collect();
        drop(kv);
        let mut blocks = Vec::new();
        for (_key, value) in entries {
            let record: StoredBlock = bincode::deserialize(&value)?;
            blocks.push(record.into_block());
        }
        blocks.sort_by_key(|block| block.header.height);
        Ok(blocks)
    }

    pub(crate) fn load_block_records_from(&self, start: u64) -> ChainResult<Vec<StoredBlock>> {
        let kv = self.kv.lock();
        let entries: Vec<(Vec<u8>, Vec<u8>)> = kv.scan_prefix(&[PREFIX_BLOCK]).collect();
        drop(kv);
        let mut records = Vec::new();
        for (key, value) in entries {
            if key.len() != 1 + 8 {
                continue;
            }
            let height = u64::from_be_bytes(
                key[1..]
                    .try_into()
                    .map_err(|_| ChainError::Config("invalid block height encoding".into()))?,
            );
            if height < start {
                continue;
            }
            let record: StoredBlock = bincode::deserialize(&value)?;
            records.push(record);
        }
        records.sort_by_key(|record| record.height());
        Ok(records)
    }

    pub fn prune_block_payload(&self, height: u64) -> ChainResult<bool> {
        let mut kv = self.kv.lock();
        let key = block_key(height);
        let Some(value) = kv.get(&key) else {
            return Ok(false);
        };
        let mut record: StoredBlock = bincode::deserialize(&value)?;
        if record.payload.is_none() {
            return Ok(false);
        }
        record.prune_payload();
        let data = bincode::serialize(&record)?;
        kv.put(key, data);
        kv.commit()?;
        Ok(true)
    }

    pub fn persist_account(&self, account: &Account) -> ChainResult<()> {
        let mut kv = self.kv.lock();
        let data = bincode::serialize(account)?;
        kv.put(account_key(&account.address), data);
        kv.commit()?;
        Ok(())
    }

    pub fn read_account(&self, address: &str) -> ChainResult<Option<Account>> {
        let kv = self.kv.lock();
        match kv.get(&account_key(address)) {
            Some(value) => Ok(Some(bincode::deserialize(&value)?)),
            None => Ok(None),
        }
    }

    pub fn load_accounts(&self) -> ChainResult<Vec<Account>> {
        let kv = self.kv.lock();
        let entries: Vec<(Vec<u8>, Vec<u8>)> = kv.scan_prefix(&[PREFIX_ACCOUNT]).collect();
        drop(kv);
        let mut accounts = Vec::new();
        for (_key, value) in entries {
            accounts.push(bincode::deserialize::<Account>(&value)?);
        }
        accounts.sort_by(|a, b| a.address.cmp(&b.address));
        Ok(accounts)
    }

    pub fn tip(&self) -> ChainResult<Option<BlockMetadata>> {
        let kv = self.kv.lock();
        let Some(height_bytes) = kv.get(&metadata_key(TIP_HEIGHT_KEY)) else {
            return Ok(None);
        };
        let hash_bytes = kv
            .get(&metadata_key(TIP_HASH_KEY))
            .ok_or_else(|| ChainError::Config("missing tip hash".into()))?;
        let timestamp_bytes = kv
            .get(&metadata_key(TIP_TIMESTAMP_KEY))
            .ok_or_else(|| ChainError::Config("missing tip timestamp".into()))?;
        let height = u64::from_be_bytes(
            height_bytes
                .as_slice()
                .try_into()
                .map_err(|_| ChainError::Config("invalid tip height encoding".into()))?,
        );
        let hash = String::from_utf8(hash_bytes.to_vec())
            .map_err(|err| ChainError::Config(format!("invalid tip hash encoding: {err}")))?;
        let timestamp = u64::from_be_bytes(
            timestamp_bytes
                .as_slice()
                .try_into()
                .map_err(|_| ChainError::Config("invalid tip timestamp encoding".into()))?,
        );
        Ok(Some(BlockMetadata {
            height,
            hash,
            timestamp,
        }))
    }
}

impl Clone for Storage {
    fn clone(&self) -> Self {
        Self {
            kv: self.kv.clone(),
        }
    }
}

fn block_key(height: u64) -> Vec<u8> {
    let mut key = Vec::with_capacity(1 + 8);
    key.push(PREFIX_BLOCK);
    key.extend_from_slice(&height.to_be_bytes());
    key
}

fn account_key(address: &str) -> Vec<u8> {
    let mut key = Vec::with_capacity(1 + address.len());
    key.push(PREFIX_ACCOUNT);
    key.extend_from_slice(address.as_bytes());
    key
}

fn metadata_key(suffix: &[u8]) -> Vec<u8> {
    let mut key = Vec::with_capacity(1 + suffix.len());
    key.push(PREFIX_METADATA);
    key.extend_from_slice(suffix);
    key
}
