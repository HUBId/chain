use std::borrow::Cow;

use thiserror::Error;

/// Request payload for retrieving a sequence of block headers.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GetHeadersRequest {
    /// Inclusive start height.
    pub start_height: u64,
    /// Maximum number of headers to return.
    pub max: u32,
}

impl GetHeadersRequest {
    pub fn new(start_height: u64, max: u32) -> Self {
        Self { start_height, max }
    }
}

/// Response payload describing headers returned by the indexer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GetHeadersResponse {
    /// Height of the best chain tip known to the indexer.
    pub latest_height: u64,
    /// Sequence of headers streamed from the requested range.
    pub headers: Vec<IndexedHeader>,
}

impl GetHeadersResponse {
    pub fn new(latest_height: u64, headers: Vec<IndexedHeader>) -> Self {
        Self {
            latest_height,
            headers,
        }
    }
}

/// Single header entry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IndexedHeader {
    pub height: u64,
    pub block_hash: [u8; 32],
    pub previous_block_hash: [u8; 32],
    /// Serialized header bytes as emitted by the indexer backend.
    pub serialized: Vec<u8>,
}

impl IndexedHeader {
    pub fn new(
        height: u64,
        block_hash: [u8; 32],
        previous_block_hash: [u8; 32],
        serialized: Vec<u8>,
    ) -> Self {
        Self {
            height,
            block_hash,
            previous_block_hash,
            serialized,
        }
    }
}

/// Request payload for fetching the status of a script hash.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GetScripthashStatusRequest {
    pub scripthash: [u8; 32],
}

impl GetScripthashStatusRequest {
    pub fn new(scripthash: [u8; 32]) -> Self {
        Self { scripthash }
    }
}

/// Response describing the script hash status returned by the backend.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GetScripthashStatusResponse {
    /// Optional Electrum-compatible status hash string.
    pub status: Option<String>,
}

impl GetScripthashStatusResponse {
    pub fn new(status: Option<String>) -> Self {
        Self { status }
    }
}

/// Request payload for fetching UTXOs tracked for a given script hash.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ListScripthashUtxosRequest {
    pub scripthash: [u8; 32],
}

impl ListScripthashUtxosRequest {
    pub fn new(scripthash: [u8; 32]) -> Self {
        Self { scripthash }
    }
}

/// Response returned when the backend enumerates UTXOs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ListScripthashUtxosResponse {
    pub utxos: Vec<IndexedUtxo>,
}

impl ListScripthashUtxosResponse {
    pub fn new(utxos: Vec<IndexedUtxo>) -> Self {
        Self { utxos }
    }
}

/// UTXO payload returned by the indexer backend.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IndexedUtxo {
    pub outpoint: TxOutpoint,
    pub value: u64,
    pub script: Vec<u8>,
    pub height: Option<u64>,
}

impl IndexedUtxo {
    pub fn new(outpoint: TxOutpoint, value: u64, script: Vec<u8>, height: Option<u64>) -> Self {
        Self {
            outpoint,
            value,
            script,
            height,
        }
    }
}

/// Transaction outpoint descriptor.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct TxOutpoint {
    pub txid: [u8; 32],
    pub vout: u32,
}

impl TxOutpoint {
    pub fn new(txid: [u8; 32], vout: u32) -> Self {
        Self { txid, vout }
    }
}

/// Request payload for fetching a transaction.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GetTransactionRequest {
    pub txid: [u8; 32],
}

impl GetTransactionRequest {
    pub fn new(txid: [u8; 32]) -> Self {
        Self { txid }
    }
}

/// Response returned when fetching a transaction payload.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GetTransactionResponse {
    pub transaction: Option<TransactionPayload>,
}

impl GetTransactionResponse {
    pub fn new(transaction: Option<TransactionPayload>) -> Self {
        Self { transaction }
    }
}

/// Transaction payload returned by the backend.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TransactionPayload {
    pub txid: [u8; 32],
    pub height: Option<u64>,
    pub raw: Cow<'static, [u8]>,
}

impl TransactionPayload {
    pub fn new(txid: [u8; 32], height: Option<u64>, raw: Cow<'static, [u8]>) -> Self {
        Self { txid, height, raw }
    }
}

/// High-level trait describing the capabilities of an indexer client.
pub trait IndexerClient: Send + Sync {
    fn get_headers(
        &self,
        request: &GetHeadersRequest,
    ) -> Result<GetHeadersResponse, IndexerClientError>;
    fn get_scripthash_status(
        &self,
        request: &GetScripthashStatusRequest,
    ) -> Result<GetScripthashStatusResponse, IndexerClientError>;
    fn list_scripthash_utxos(
        &self,
        request: &ListScripthashUtxosRequest,
    ) -> Result<ListScripthashUtxosResponse, IndexerClientError>;
    fn get_transaction(
        &self,
        request: &GetTransactionRequest,
    ) -> Result<GetTransactionResponse, IndexerClientError>;
}

/// Errors produced by [`IndexerClient`] implementations.
#[derive(Debug, Error)]
pub enum IndexerClientError {
    #[error("backend error: {0}")]
    Backend(String),
}

#[cfg(feature = "vendor_electrs")]
use crate::vendor::electrs;

/// Simple Electrum-like stub that exposes deterministic responses for tests and
/// offline development. The implementation is intentionally minimal and relies
/// on the vendored Electrs shim to synthesise payloads that resemble the real
/// service.
#[cfg(feature = "vendor_electrs")]
#[derive(Clone, Debug, Default)]
pub struct ElectrsIndexerClient;

#[cfg(feature = "vendor_electrs")]
impl ElectrsIndexerClient {
    pub fn new() -> Self {
        Self
    }
}

#[cfg(feature = "vendor_electrs")]
impl IndexerClient for ElectrsIndexerClient {
    fn get_headers(
        &self,
        request: &GetHeadersRequest,
    ) -> Result<GetHeadersResponse, IndexerClientError> {
        use electrs::rpp_ledger::bitcoin::{
            blockdata::{block::Header, constants::genesis_block},
            consensus::encode,
            Network,
        };

        let max = request.max.max(1);
        let count = max.min(128) as u64;
        let start = request.start_height;
        let mut headers = Vec::new();
        let mut parent = genesis_block(Network::Regtest).header.block_hash();
        for offset in 0..count {
            let height = start + offset;
            let mut header = Header::default();
            header.parent = parent;
            header.timestamp = height;
            header.state_root = sha_tag(height);
            header.tx_root = sha_tag(height + 1);
            header.vrf_output = sha_tag(height + 2);
            header.stark_proof = [height as u8; 64];
            header.producer = sha_tag(height + 3);
            let block_hash = header.block_hash();
            let serialized = encode::serialize(&header);
            headers.push(IndexedHeader::new(
                height,
                *block_hash.as_bytes(),
                *header.parent.as_bytes(),
                serialized,
            ));
            parent = block_hash;
        }
        let latest_height = headers.last().map(|entry| entry.height).unwrap_or(start);
        Ok(GetHeadersResponse::new(latest_height, headers))
    }

    fn get_scripthash_status(
        &self,
        request: &GetScripthashStatusRequest,
    ) -> Result<GetScripthashStatusResponse, IndexerClientError> {
        let mut prefix = [0u8; 8];
        prefix.copy_from_slice(&request.scripthash[..8]);
        let tag = sha_tag(u64::from_le_bytes(prefix));
        let status = hex::encode(tag);
        Ok(GetScripthashStatusResponse::new(Some(status)))
    }

    fn list_scripthash_utxos(
        &self,
        request: &ListScripthashUtxosRequest,
    ) -> Result<ListScripthashUtxosResponse, IndexerClientError> {
        use electrs::rpp_ledger::bitcoin::{bitcoin_slices::bsl::Transaction, Script};

        let mut tx = Transaction::new(Vec::new(), Vec::new(), request.scripthash.to_vec());
        tx.push_output(Script::new(request.scripthash.to_vec()));
        let txid = tx.txid_sha2();
        let outpoint = TxOutpoint::new(*txid.as_bytes(), 0);
        let utxo = IndexedUtxo::new(outpoint, 50_000, request.scripthash.to_vec(), Some(0));
        Ok(ListScripthashUtxosResponse::new(vec![utxo]))
    }

    fn get_transaction(
        &self,
        request: &GetTransactionRequest,
    ) -> Result<GetTransactionResponse, IndexerClientError> {
        use electrs::rpp_ledger::bitcoin::{
            bitcoin_slices::bsl::Transaction, OutPoint, Script, Txid,
        };

        let input = OutPoint::new(Txid::from_bytes(request.txid), 0);
        let mut tx = Transaction::new(vec![input], Vec::new(), request.txid.to_vec());
        tx.push_output(Script::new(request.txid.to_vec()));
        let txid = tx.txid_sha2();
        let raw = txid.as_bytes().to_vec();
        let payload = TransactionPayload::new(*txid.as_bytes(), Some(0), Cow::Owned(raw));
        Ok(GetTransactionResponse::new(Some(payload)))
    }
}

#[cfg(feature = "vendor_electrs")]
fn sha_tag(tag: u64) -> [u8; 32] {
    use sha2::{Digest, Sha256};

    let mut hasher = Sha256::new();
    hasher.update(tag.to_le_bytes());
    hasher.finalize().into()
}
