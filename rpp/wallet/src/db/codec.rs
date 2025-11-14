use std::borrow::Cow;

use bincode::Options;
use serde::{Deserialize, Serialize};
use serde_bytes::ByteBuf;
use thiserror::Error;

use crate::db::schema;
pub use crate::modes::watch_only::WatchOnlyRecord;

/// Canonical wallet address representation.
pub type Address = String;

/// Error surfaced when encoding or decoding wallet payloads fails.
#[derive(Debug, Error)]
pub enum CodecError {
    /// Wrapper around the underlying bincode error.
    #[error("serialization error: {0}")]
    Serialization(#[from] bincode::Error),
}

fn options() -> impl Options {
    bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .allow_trailing_bytes()
}

/// UTXO outpoint uniquely identified by transaction id and index.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct UtxoOutpoint {
    pub txid: [u8; 32],
    pub index: u32,
}

impl UtxoOutpoint {
    pub fn new(txid: [u8; 32], index: u32) -> Self {
        Self { txid, index }
    }
}

/// Wallet-tracked UTXO record.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct UtxoRecord<'a> {
    pub outpoint: UtxoOutpoint,
    pub owner: Address,
    pub value: u128,
    #[serde(borrow)]
    #[serde(with = "serde_bytes")]
    pub script: Cow<'a, [u8]>,
    pub timelock: Option<u64>,
}

impl<'a> UtxoRecord<'a> {
    pub fn new(
        outpoint: UtxoOutpoint,
        owner: Address,
        value: u128,
        script: Cow<'a, [u8]>,
        timelock: Option<u64>,
    ) -> Self {
        Self {
            outpoint,
            owner,
            value,
            script,
            timelock,
        }
    }

    pub fn into_owned(self) -> UtxoRecord<'static> {
        UtxoRecord {
            outpoint: self.outpoint,
            owner: self.owner,
            value: self.value,
            script: Cow::Owned(self.script.into_owned()),
            timelock: self.timelock,
        }
    }
}

/// Cached transaction entry stored in Firewood.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct TxCacheEntry<'a> {
    pub height: u64,
    pub timestamp_ms: u64,
    #[serde(borrow)]
    #[serde(with = "serde_bytes")]
    pub payload: Cow<'a, [u8]>,
}

impl<'a> TxCacheEntry<'a> {
    pub fn new(height: u64, timestamp_ms: u64, payload: Cow<'a, [u8]>) -> Self {
        Self {
            height,
            timestamp_ms,
            payload,
        }
    }

    pub fn into_owned(self) -> TxCacheEntry<'static> {
        TxCacheEntry {
            height: self.height,
            timestamp_ms: self.timestamp_ms,
            payload: Cow::Owned(self.payload.into_owned()),
        }
    }
}

/// Auxiliary metadata captured for a pending lock.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct PendingLockMetadata {
    #[serde(default)]
    pub backend: String,
    #[serde(default)]
    pub witness_bytes: u64,
    #[serde(default)]
    pub prove_duration_ms: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub proof_bytes: Option<u64>,
}

impl PendingLockMetadata {
    pub fn new(
        backend: String,
        witness_bytes: u64,
        prove_duration_ms: u64,
        proof_bytes: Option<u64>,
    ) -> Self {
        Self {
            backend,
            witness_bytes,
            prove_duration_ms,
            proof_bytes,
        }
    }
}

/// Metadata describing a pending lock entry held by the wallet.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct PendingLock {
    pub outpoint: UtxoOutpoint,
    pub locked_at_ms: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub spending_txid: Option<[u8; 32]>,
    #[serde(default)]
    pub metadata: PendingLockMetadata,
}

impl PendingLock {
    pub fn new(outpoint: UtxoOutpoint, locked_at_ms: u64, spending_txid: Option<[u8; 32]>) -> Self {
        Self {
            outpoint,
            locked_at_ms,
            spending_txid,
            metadata: PendingLockMetadata::default(),
        }
    }

    pub fn with_metadata(mut self, metadata: PendingLockMetadata) -> Self {
        self.metadata = metadata;
        self
    }
}

/// Persisted snapshot of admission or spending policies.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct PolicySnapshot {
    pub revision: u64,
    pub updated_at: u64,
    pub statements: Vec<String>,
}

impl PolicySnapshot {
    pub fn new(revision: u64, updated_at: u64, statements: Vec<String>) -> Self {
        Self {
            revision,
            updated_at,
            statements,
        }
    }
}

pub fn encode_address(address: &Address) -> Result<Vec<u8>, CodecError> {
    Ok(options().serialize(address)?)
}

pub fn decode_address(bytes: &[u8]) -> Result<Address, CodecError> {
    Ok(options().deserialize(bytes)?)
}

pub fn encode_utxo(record: &UtxoRecord<'_>) -> Result<Vec<u8>, CodecError> {
    Ok(options().serialize(record)?)
}

pub fn decode_utxo<'a>(bytes: &'a [u8]) -> Result<UtxoRecord<'a>, CodecError> {
    Ok(options().deserialize(bytes)?)
}

pub fn encode_tx_cache_entry(entry: &TxCacheEntry<'_>) -> Result<Vec<u8>, CodecError> {
    Ok(options().serialize(entry)?)
}

pub fn decode_tx_cache_entry<'a>(bytes: &'a [u8]) -> Result<TxCacheEntry<'a>, CodecError> {
    Ok(options().deserialize(bytes)?)
}

pub fn encode_watch_only(record: &WatchOnlyRecord) -> Result<Vec<u8>, CodecError> {
    Ok(options().serialize(record)?)
}

pub fn decode_watch_only(bytes: &[u8]) -> Result<WatchOnlyRecord, CodecError> {
    Ok(options().deserialize(bytes)?)
}

pub fn encode_policy_snapshot(snapshot: &PolicySnapshot) -> Result<Vec<u8>, CodecError> {
    Ok(options().serialize(snapshot)?)
}

pub fn decode_policy_snapshot(bytes: &[u8]) -> Result<PolicySnapshot, CodecError> {
    Ok(options().deserialize(bytes)?)
}

pub fn encode_schema_version(version: u32) -> Result<Vec<u8>, CodecError> {
    Ok(options().serialize(&version)?)
}

pub fn decode_schema_version(bytes: &[u8]) -> Result<u32, CodecError> {
    Ok(options().deserialize(bytes)?)
}

pub fn encode_checkpoint(height: u64) -> Result<Vec<u8>, CodecError> {
    Ok(options().serialize(&height)?)
}

pub fn decode_checkpoint(bytes: &[u8]) -> Result<u64, CodecError> {
    Ok(options().deserialize(bytes)?)
}

pub fn encode_key_material(material: &[u8]) -> Result<Vec<u8>, CodecError> {
    Ok(options().serialize(&ByteBuf::from(material))?)
}

pub fn decode_key_material(bytes: &[u8]) -> Result<Vec<u8>, CodecError> {
    let buf: ByteBuf = options().deserialize(bytes)?;
    Ok(buf.into_vec())
}

pub fn encode_pending_lock(lock: &PendingLock) -> Result<Vec<u8>, CodecError> {
    Ok(options().serialize(lock)?)
}

pub fn decode_pending_lock(bytes: &[u8]) -> Result<PendingLock, CodecError> {
    Ok(options().deserialize(bytes)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn address_roundtrip() {
        let address = "fw1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq3".to_string();
        let encoded = encode_address(&address).expect("encode");
        let decoded = decode_address(&encoded).expect("decode");
        assert_eq!(decoded, address);
    }

    #[test]
    fn utxo_roundtrip() {
        let record = UtxoRecord::new(
            UtxoOutpoint::new([1u8; 32], 7),
            "owner1".to_string(),
            42,
            Cow::Borrowed(&[0u8, 1, 2, 3]),
            Some(12),
        );
        let encoded = encode_utxo(&record).expect("encode utxo");
        let decoded = decode_utxo(&encoded).expect("decode utxo");
        assert_eq!(decoded.into_owned(), record.into_owned());
    }

    #[test]
    fn cache_roundtrip() {
        let entry = TxCacheEntry::new(42, 1234, Cow::Borrowed(&[9u8; 4]));
        let encoded = encode_tx_cache_entry(&entry).expect("encode entry");
        let decoded = decode_tx_cache_entry(&encoded).expect("decode entry");
        assert_eq!(decoded.into_owned(), entry.into_owned());
    }

    #[test]
    fn pending_lock_roundtrip() {
        let metadata = PendingLockMetadata::new("mock".into(), 42, 1_000, Some(512));
        let lock = PendingLock::new(
            UtxoOutpoint::new([2u8; 32], 11),
            1_650_000_000_000,
            Some([9u8; 32]),
        )
        .with_metadata(metadata);
        let encoded = encode_pending_lock(&lock).expect("encode lock");
        let decoded = decode_pending_lock(&encoded).expect("decode lock");
        assert_eq!(decoded, lock);
    }

    #[test]
    fn policy_roundtrip() {
        let snapshot = PolicySnapshot::new(2, 5, vec!["allow all".into(), "deny none".into()]);
        let encoded = encode_policy_snapshot(&snapshot).expect("encode snapshot");
        let decoded = decode_policy_snapshot(&encoded).expect("decode snapshot");
        assert_eq!(decoded, snapshot);
    }

    #[test]
    fn key_material_roundtrip() {
        let key = vec![1u8, 2, 3, 4, 5];
        let encoded = encode_key_material(&key).expect("encode key");
        let decoded = decode_key_material(&encoded).expect("decode key");
        assert_eq!(decoded, key);
    }

    #[test]
    fn schema_roundtrip() {
        let encoded = encode_schema_version(schema::SCHEMA_VERSION_LATEST).expect("encode schema");
        let decoded = decode_schema_version(&encoded).expect("decode schema");
        assert_eq!(decoded, schema::SCHEMA_VERSION_LATEST);
    }
}
