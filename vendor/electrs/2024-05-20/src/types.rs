use core::fmt;

use serde::{Deserialize, Serialize};
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
use rpp::proofs::rpp::TransactionWitness;
use rpp::runtime::types::SignedTransaction;

#[cfg(feature = "backend-rpp-stark")]
use crate::zk::rpp_adapter::{
    compute_public_digest,
    encode_public_inputs,
    Digest32,
};
#[cfg(feature = "backend-rpp-stark")]
use prover_backend_interface::TxPublicInputs;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum LedgerScriptPayload {
    Recipient { to: String, amount: u128 },
    Sender { from: String, fee: u64 },
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct LedgerMemoPayload {
    pub nonce: u64,
    pub memo: Option<String>,
    pub signature: String,
    pub public_key: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct StoredTransactionMetadata {
    pub transaction: SignedTransaction,
    pub witness: Option<TransactionWitness>,
    pub rpp_stark_proof: Option<Vec<u8>>,
    #[cfg(feature = "backend-rpp-stark")]
    #[serde(default)]
    pub proof_audit: Option<RppStarkProofAudit>,
    #[cfg(feature = "backend-rpp-stark")]
    #[serde(default)]
    pub vrf_audit: Option<StoredVrfAudit>,
}

#[cfg(feature = "backend-rpp-stark")]
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct RppStarkProofAudit {
    pub envelope: String,
    pub report: RppStarkReportSummary,
}

#[cfg(feature = "backend-rpp-stark")]
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct RppStarkReportSummary {
    pub backend: String,
    pub verified: bool,
    pub params_ok: bool,
    pub public_ok: bool,
    pub merkle_ok: bool,
    pub fri_ok: bool,
    pub composition_ok: bool,
    pub total_bytes: u64,
    pub notes: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trace_query_indices: Option<Vec<u32>>,
}

#[cfg(feature = "backend-rpp-stark")]
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct StoredVrfAudit {
    pub input: VrfInputDescriptor,
    pub output: VrfOutputDescriptor,
}

#[cfg(feature = "backend-rpp-stark")]
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct VrfInputDescriptor {
    pub last_block_header: String,
    pub epoch: u64,
    pub tier_seed: String,
}

#[cfg(feature = "backend-rpp-stark")]
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct VrfOutputDescriptor {
    pub randomness: String,
    pub preoutput: String,
    pub proof: String,
}

pub fn encode_ledger_script(payload: &LedgerScriptPayload) -> Vec<u8> {
    serde_json::to_vec(payload).expect("serialize ledger script payload")
}

pub fn decode_ledger_script(bytes: &[u8]) -> Option<LedgerScriptPayload> {
    serde_json::from_slice(bytes).ok()
}

pub fn encode_ledger_memo(payload: &LedgerMemoPayload) -> Vec<u8> {
    serde_json::to_vec(payload).expect("serialize ledger memo payload")
}

pub fn decode_ledger_memo(bytes: &[u8]) -> Option<LedgerMemoPayload> {
    serde_json::from_slice(bytes).ok()
}

pub fn encode_transaction_metadata(metadata: &StoredTransactionMetadata) -> Vec<u8> {
    serde_json::to_vec(metadata).expect("serialize transaction metadata")
}

pub fn decode_transaction_metadata(bytes: &[u8]) -> Option<StoredTransactionMetadata> {
    serde_json::from_slice(bytes).ok()
}

pub fn serialize_transaction(tx: &bsl::Transaction) -> Vec<u8> {
    let mut buf = Vec::new();
    let inputs = tx.inputs();
    buf.extend_from_slice(&(inputs.len() as u32).to_le_bytes());
    for input in inputs {
        buf.extend_from_slice(input.txid.as_bytes());
        buf.extend_from_slice(&input.vout.to_le_bytes());
    }
    let outputs = tx.outputs();
    buf.extend_from_slice(&(outputs.len() as u32).to_le_bytes());
    for output in outputs {
        buf.extend_from_slice(&(output.as_bytes().len() as u32).to_le_bytes());
        buf.extend_from_slice(output.as_bytes());
    }
    let memo = tx.memo();
    buf.extend_from_slice(&(memo.len() as u32).to_le_bytes());
    buf.extend_from_slice(memo);
    buf
}

pub fn serialize_block(transactions: &[bsl::Transaction]) -> SerBlock {
    let mut buf = Vec::new();
    buf.extend_from_slice(&(transactions.len() as u32).to_le_bytes());
    for tx in transactions {
        buf.extend_from_slice(&serialize_transaction(tx));
    }
    buf
}

fn read_u32(input: &[u8], cursor: &mut usize) -> Option<u32> {
    if input.len().checked_sub(*cursor)? < 4 {
        return None;
    }
    let mut buf = [0u8; 4];
    buf.copy_from_slice(&input[*cursor..*cursor + 4]);
    *cursor += 4;
    Some(u32::from_le_bytes(buf))
}

fn read_bytes<'a>(input: &'a [u8], cursor: &mut usize, len: usize) -> Option<&'a [u8]> {
    if input.len().checked_sub(*cursor)? < len {
        return None;
    }
    let slice = &input[*cursor..*cursor + len];
    *cursor += len;
    Some(slice)
}

pub fn deserialize_transaction(bytes: &[u8]) -> Option<(bsl::Transaction, usize)> {
    let mut cursor = 0usize;
    let input_count = read_u32(bytes, &mut cursor)? as usize;
    let mut inputs = Vec::with_capacity(input_count);
    for _ in 0..input_count {
        let txid_bytes = read_bytes(bytes, &mut cursor, 32)?;
        let mut txid_array = [0u8; 32];
        txid_array.copy_from_slice(txid_bytes);
        let vout = read_u32(bytes, &mut cursor)?;
        inputs.push(OutPoint::new(Txid::from_bytes(txid_array), vout));
    }

    let output_count = read_u32(bytes, &mut cursor)? as usize;
    let mut outputs = Vec::with_capacity(output_count);
    for _ in 0..output_count {
        let len = read_u32(bytes, &mut cursor)? as usize;
        let data = read_bytes(bytes, &mut cursor, len)?;
        outputs.push(Script::new(data.to_vec()));
    }

    let memo_len = read_u32(bytes, &mut cursor)? as usize;
    let memo_bytes = read_bytes(bytes, &mut cursor, memo_len)?.to_vec();

    let tx = bsl::Transaction::new(inputs, outputs, memo_bytes);
    Some((tx, cursor))
}

pub fn deserialize_block(bytes: &[u8]) -> Option<Vec<bsl::Transaction>> {
    let mut cursor = 0usize;
    let count = read_u32(bytes, &mut cursor)? as usize;
    let mut transactions = Vec::with_capacity(count);
    for _ in 0..count {
        let (tx, consumed) = deserialize_transaction(&bytes[cursor..])?;
        cursor += consumed;
        transactions.push(tx);
    }
    if cursor == bytes.len() {
        Some(transactions)
    } else {
        None
    }
}

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

#[cfg(feature = "backend-rpp-stark")]
type StatusDigestInner = Digest32;
#[cfg(not(feature = "backend-rpp-stark"))]
type StatusDigestInner = [u8; 32];

/// Wrapper around the status digest value exposed over the Electrum API.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct StatusDigest(StatusDigestInner);

impl StatusDigest {
    /// Creates a digest from its raw bytes.
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        #[cfg(feature = "backend-rpp-stark")]
        {
            Self(Digest32::from(bytes))
        }

        #[cfg(not(feature = "backend-rpp-stark"))]
        {
            Self(bytes)
        }
    }

    /// Returns the digest as a lowercase hexadecimal string.
    pub fn to_hex(&self) -> String {
        hex::encode(self.as_bytes())
    }

    /// Borrows the digest bytes.
    pub fn as_bytes(&self) -> &[u8; 32] {
        #[cfg(feature = "backend-rpp-stark")]
        {
            self.0.as_bytes()
        }

        #[cfg(not(feature = "backend-rpp-stark"))]
        {
            &self.0
        }
    }

    /// Consumes the wrapper and returns the raw bytes.
    pub fn into_bytes(self) -> [u8; 32] {
        #[cfg(feature = "backend-rpp-stark")]
        {
            self.0.into_bytes()
        }

        #[cfg(not(feature = "backend-rpp-stark"))]
        {
            self.0
        }
    }

    #[cfg(feature = "backend-rpp-stark")]
    pub fn from_digest(digest: Digest32) -> Self {
        Self(digest)
    }

    #[cfg(feature = "backend-rpp-stark")]
    pub fn into_digest(self) -> Digest32 {
        self.0
    }

    #[cfg(feature = "backend-rpp-stark")]
    pub fn from_public_inputs(inputs: &TxPublicInputs) -> Self {
        let encoded = encode_public_inputs(inputs);
        let digest = compute_public_digest(&encoded);
        Self(digest)
    }
}

impl fmt::Debug for StatusDigest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "StatusDigest(0x{})", self.to_hex())
    }
}

impl fmt::Display for StatusDigest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

impl From<[u8; 32]> for StatusDigest {
    fn from(value: [u8; 32]) -> Self {
        Self::from_bytes(value)
    }
}

impl From<StatusDigest> for [u8; 32] {
    fn from(value: StatusDigest) -> Self {
        value.into_bytes()
    }
}

#[cfg(feature = "backend-rpp-stark")]
impl From<Digest32> for StatusDigest {
    fn from(value: Digest32) -> Self {
        Self::from_digest(value)
    }
}

#[cfg(feature = "backend-rpp-stark")]
impl From<StatusDigest> for Digest32 {
    fn from(value: StatusDigest) -> Self {
        value.into_digest()
    }
}

impl serde::Serialize for StatusDigest {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.to_hex())
    }
}

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
