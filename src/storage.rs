use std::convert::TryInto;
use std::path::Path;
use std::sync::Arc;

use rocksdb::{
    BoundColumnFamily, ColumnFamilyDescriptor, DBWithThreadMode, Direction, IteratorMode,
    MultiThreaded, Options,
};

use crate::errors::{ChainError, ChainResult};
use crate::types::{Account, Block, BlockMetadata, StoredBlock};

pub const STORAGE_SCHEMA_VERSION: u32 = 1;

pub(crate) const CF_BLOCKS: &str = "blocks";
pub(crate) const CF_ACCOUNTS: &str = "accounts";
pub(crate) const CF_METADATA: &str = "metadata";
const TIP_HEIGHT_KEY: &[u8] = b"tip_height";
const TIP_HASH_KEY: &[u8] = b"tip_hash";
const TIP_TIMESTAMP_KEY: &[u8] = b"tip_timestamp";
pub(crate) const SCHEMA_VERSION_KEY: &[u8] = b"schema_version";

pub struct Storage {
    db: Arc<DBWithThreadMode<MultiThreaded>>,
}

impl Storage {
    pub fn open(path: &Path) -> ChainResult<Self> {
        let mut opts = Options::default();
        opts.create_if_missing(true);
        opts.create_missing_column_families(true);
        let cf_descriptors = vec![
            ColumnFamilyDescriptor::new(CF_BLOCKS, Options::default()),
            ColumnFamilyDescriptor::new(CF_ACCOUNTS, Options::default()),
            ColumnFamilyDescriptor::new(CF_METADATA, Options::default()),
        ];
        let db = DBWithThreadMode::open_cf_descriptors(&opts, path, cf_descriptors)?;
        let storage = Self { db: Arc::new(db) };
        storage.ensure_schema_supported()?;
        Ok(storage)
    }

    fn blocks_cf(&self) -> ChainResult<Arc<BoundColumnFamily<'_>>> {
        self.db
            .cf_handle(CF_BLOCKS)
            .ok_or_else(|| ChainError::Config("missing blocks column family".into()))
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
        let blocks_cf = self.blocks_cf()?;
        let mut block_iter = self.db.iterator_cf(&blocks_cf, IteratorMode::Start);
        if block_iter.next().transpose()?.is_some() {
            return Ok(false);
        }

        let accounts_cf = self.accounts_cf()?;
        let mut account_iter = self.db.iterator_cf(&accounts_cf, IteratorMode::Start);
        if account_iter.next().transpose()?.is_some() {
            return Ok(false);
        }

        let metadata_cf = self.metadata_cf()?;
        if self.db.get_cf(&metadata_cf, TIP_HEIGHT_KEY)?.is_some() {
            return Ok(false);
        }

        Ok(true)
    }

    fn read_schema_version(&self) -> ChainResult<Option<u32>> {
        Self::read_schema_version_raw(&self.db)
    }

    pub fn schema_version(&self) -> ChainResult<u32> {
        Ok(self
            .read_schema_version()?
            .unwrap_or(STORAGE_SCHEMA_VERSION))
    }

    fn write_schema_version(&self, version: u32) -> ChainResult<()> {
        Self::write_schema_version_raw(&self.db, version)
    }

    pub(crate) fn write_schema_version_raw(
        db: &DBWithThreadMode<MultiThreaded>,
        version: u32,
    ) -> ChainResult<()> {
        let metadata_cf = db
            .cf_handle(CF_METADATA)
            .ok_or_else(|| ChainError::Config("missing metadata column family".into()))?;
        db.put_cf(&metadata_cf, SCHEMA_VERSION_KEY, version.to_be_bytes())?;
        Ok(())
    }

    pub(crate) fn read_schema_version_raw(
        db: &DBWithThreadMode<MultiThreaded>,
    ) -> ChainResult<Option<u32>> {
        let metadata_cf = db
            .cf_handle(CF_METADATA)
            .ok_or_else(|| ChainError::Config("missing metadata column family".into()))?;
        match db.get_cf(&metadata_cf, SCHEMA_VERSION_KEY)? {
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

    pub(crate) fn open_db(path: &Path) -> ChainResult<DBWithThreadMode<MultiThreaded>> {
        let mut opts = Options::default();
        opts.create_if_missing(false);
        opts.create_missing_column_families(true);
        let cf_descriptors = vec![
            ColumnFamilyDescriptor::new(CF_BLOCKS, Options::default()),
            ColumnFamilyDescriptor::new(CF_ACCOUNTS, Options::default()),
            ColumnFamilyDescriptor::new(CF_METADATA, Options::default()),
        ];
        let db = DBWithThreadMode::open_cf_descriptors(&opts, path, cf_descriptors)?;
        Ok(db)
    }

    fn accounts_cf(&self) -> ChainResult<Arc<BoundColumnFamily<'_>>> {
        self.db
            .cf_handle(CF_ACCOUNTS)
            .ok_or_else(|| ChainError::Config("missing accounts column family".into()))
    }

    fn metadata_cf(&self) -> ChainResult<Arc<BoundColumnFamily<'_>>> {
        self.db
            .cf_handle(CF_METADATA)
            .ok_or_else(|| ChainError::Config("missing metadata column family".into()))
    }

    pub fn store_block(&self, block: &Block) -> ChainResult<()> {
        let cf = self.blocks_cf()?;
        let key = block.header.height.to_be_bytes();
        let record = StoredBlock::from_block(block);
        let data = bincode::serialize(&record)?;
        self.db.put_cf(&cf, key, data)?;
        let metadata_cf = self.metadata_cf()?;
        self.db.put_cf(
            &metadata_cf,
            TIP_HEIGHT_KEY,
            block.header.height.to_be_bytes(),
        )?;
        self.db
            .put_cf(&metadata_cf, TIP_HASH_KEY, block.hash.as_bytes())?;
        self.db.put_cf(
            &metadata_cf,
            TIP_TIMESTAMP_KEY,
            block.header.timestamp.to_be_bytes(),
        )?;
        Ok(())
    }

    pub fn read_block(&self, height: u64) -> ChainResult<Option<Block>> {
        let cf = self.blocks_cf()?;
        let key = height.to_be_bytes();
        match self.db.get_cf(&cf, key)? {
            Some(value) => {
                let record: StoredBlock = bincode::deserialize(&value)?;
                Ok(Some(record.into_block()))
            }
            None => Ok(None),
        }
    }

    pub(crate) fn read_block_record(&self, height: u64) -> ChainResult<Option<StoredBlock>> {
        let cf = self.blocks_cf()?;
        let key = height.to_be_bytes();
        match self.db.get_cf(&cf, key)? {
            Some(value) => Ok(Some(bincode::deserialize(&value)?)),
            None => Ok(None),
        }
    }

    pub fn load_blockchain(&self) -> ChainResult<Vec<Block>> {
        let cf = self.blocks_cf()?;
        let mut iterator = self.db.iterator_cf(&cf, IteratorMode::Start);
        let mut blocks = Vec::new();
        while let Some(entry) = iterator.next() {
            let (_key, value) = entry?;
            let record: StoredBlock = bincode::deserialize(&value)?;
            blocks.push(record.into_block());
        }
        blocks.sort_by_key(|block| block.header.height);
        Ok(blocks)
    }

    pub(crate) fn load_block_records_from(&self, start: u64) -> ChainResult<Vec<StoredBlock>> {
        let cf = self.blocks_cf()?;
        let mut iterator = self.db.iterator_cf(
            &cf,
            IteratorMode::From(&start.to_be_bytes(), Direction::Forward),
        );
        let mut records = Vec::new();
        while let Some(entry) = iterator.next() {
            let (key, value) = entry?;
            let height_bytes: [u8; 8] = key
                .as_ref()
                .try_into()
                .map_err(|_| ChainError::Config("invalid block height encoding".into()))?;
            let height = u64::from_be_bytes(height_bytes);
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
        let cf = self.blocks_cf()?;
        let key = height.to_be_bytes();
        let Some(value) = self.db.get_cf(&cf, key)? else {
            return Ok(false);
        };
        let mut record: StoredBlock = bincode::deserialize(&value)?;
        if record.payload.is_none() {
            return Ok(false);
        }
        record.prune_payload();
        let data = bincode::serialize(&record)?;
        self.db.put_cf(&cf, key, data)?;
        Ok(true)
    }

    pub fn persist_account(&self, account: &Account) -> ChainResult<()> {
        let cf = self.accounts_cf()?;
        let data = bincode::serialize(account)?;
        self.db.put_cf(&cf, account.address.as_bytes(), data)?;
        Ok(())
    }

    pub fn read_account(&self, address: &str) -> ChainResult<Option<Account>> {
        let cf = self.accounts_cf()?;
        match self.db.get_cf(&cf, address.as_bytes())? {
            Some(value) => Ok(Some(bincode::deserialize(&value)?)),
            None => Ok(None),
        }
    }

    pub fn load_accounts(&self) -> ChainResult<Vec<Account>> {
        let cf = self.accounts_cf()?;
        let mut iterator = self.db.iterator_cf(&cf, IteratorMode::Start);
        let mut accounts = Vec::new();
        while let Some(entry) = iterator.next() {
            let (_key, value) = entry?;
            accounts.push(bincode::deserialize::<Account>(&value)?);
        }
        accounts.sort_by(|a, b| a.address.cmp(&b.address));
        Ok(accounts)
    }

    pub fn tip(&self) -> ChainResult<Option<BlockMetadata>> {
        let cf = self.metadata_cf()?;
        let height_bytes = match self.db.get_cf(&cf, TIP_HEIGHT_KEY)? {
            Some(bytes) => bytes,
            None => return Ok(None),
        };
        let hash_bytes = self
            .db
            .get_cf(&cf, TIP_HASH_KEY)?
            .ok_or_else(|| ChainError::Config("missing tip hash".into()))?;
        let timestamp_bytes = self
            .db
            .get_cf(&cf, TIP_TIMESTAMP_KEY)?
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
            db: self.db.clone(),
        }
    }
}
