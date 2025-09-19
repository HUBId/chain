use std::convert::TryInto;
use std::path::Path;
use std::sync::Arc;

use rocksdb::{
    BoundColumnFamily, ColumnFamilyDescriptor, DBWithThreadMode, IteratorMode, MultiThreaded,
    Options,
};

use crate::errors::{ChainError, ChainResult};
use crate::types::{Account, Block, BlockMetadata};

const CF_BLOCKS: &str = "blocks";
const CF_ACCOUNTS: &str = "accounts";
const CF_METADATA: &str = "metadata";
const TIP_HEIGHT_KEY: &[u8] = b"tip_height";
const TIP_HASH_KEY: &[u8] = b"tip_hash";
const TIP_TIMESTAMP_KEY: &[u8] = b"tip_timestamp";

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
        Ok(Self { db: Arc::new(db) })
    }

    fn blocks_cf(&self) -> ChainResult<Arc<BoundColumnFamily<'_>>> {
        self.db
            .cf_handle(CF_BLOCKS)
            .ok_or_else(|| ChainError::Config("missing blocks column family".into()))
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
        let data = bincode::serialize(block)?;
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
            blocks.push(bincode::deserialize::<Block>(&value)?);
        }
        blocks.sort_by_key(|block| block.header.height);
        Ok(blocks)
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
