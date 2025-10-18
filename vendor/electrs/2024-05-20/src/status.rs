use std::collections::{HashMap, HashSet};
#[cfg(feature = "backend-rpp-stark")]
use std::convert::TryFrom;

use anyhow::{anyhow, Context};
use serde::ser::{Serialize, SerializeStruct, Serializer};

#[cfg(feature = "backend-rpp-stark")]
use crate::zk::rpp_adapter::{compute_public_digest, Digest32, RppStarkHasher};
#[cfg(feature = "backend-rpp-stark")]
use crate::zk::rpp_verifier::{
    RppStarkVerificationReport, RppStarkVerifier, RppStarkVerifierError,
};
#[cfg(feature = "backend-rpp-stark")]
use crate::vendor::electrs::types::{
    RppStarkProofAudit, RppStarkReportSummary, StoredVrfAudit,
};

use crate::vendor::electrs::chain::Chain;
use crate::vendor::electrs::index::Index;
use crate::vendor::electrs::rpp_ledger::bitcoin::{
    hashes::sha256,
    OutPoint,
    BlockHash,
    Script,
    Txid,
};
use crate::vendor::electrs::rpp_ledger::bitcoin_slices::bsl::Transaction;
use crate::vendor::electrs::types::{
    decode_ledger_script, decode_transaction_metadata, encode_ledger_script, LedgerScriptPayload,
    ScriptHash, StatusDigest, StoredTransactionMetadata,
};
use rpp::runtime::node::{MempoolStatus, PendingTransactionSummary};
#[cfg(feature = "backend-rpp-stark")]
use rpp::{
    proofs::rpp::encode_transaction_witness,
    runtime::types::proofs::RppStarkProof,
};
#[cfg(feature = "backend-rpp-stark")]
use rpp_stark::backend::params_limit_to_node_bytes;
#[cfg(feature = "backend-rpp-stark")]
use rpp_stark::params::deserialize_params;
#[cfg(feature = "backend-rpp-stark")]
use rpp_stark::proof::envelope::ProofBuilder;
#[cfg(feature = "backend-rpp-stark")]
use rpp_stark::proof::types::Proof;

fn hex_string(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write;
        write!(&mut s, "{:02x}", byte).expect("write to string");
    }
    s
}

#[cfg(feature = "backend-rpp-stark")]
pub(crate) fn build_rpp_stark_audit(
    proof: &RppStarkProof,
) -> anyhow::Result<RppStarkProofAudit> {
    let params = proof.params();
    let public_inputs = proof.public_inputs();
    let payload = proof.proof();

    let stark_params = deserialize_params(params)
        .context("decode rpp-stark proof parameters")?;
    let node_limit = params_limit_to_node_bytes(&stark_params)
        .map_err(|err| anyhow!("map proof size limit: {err}"))?;

    let verifier = RppStarkVerifier::new();
    let report = match verifier.verify(params, public_inputs, payload, node_limit) {
        Ok(report) => report,
        Err(RppStarkVerifierError::VerificationFailed { report, .. }) => report,
        Err(err) => return Err(anyhow!("verify rpp-stark proof: {err}")),
    };

    let decoded = Proof::from_bytes(payload).context("decode rpp-stark proof envelope")?;
    let rebuilt = ProofBuilder::new(*stark_params.proof())
        .with_header(decoded.version(), decoded.params_hash().clone())
        .with_binding(
            *decoded.kind(),
            decoded.air_spec_id().clone(),
            decoded.public_inputs().to_vec(),
        )
        .with_openings_descriptor(decoded.openings().clone())
        .with_fri_handle(decoded.fri().clone())
        .with_telemetry_option(decoded.telemetry().clone())
        .build()
        .context("rebuild rpp-stark proof envelope")?
        .proof
        .to_bytes()
        .context("serialize rpp-stark proof envelope")?;

    Ok(RppStarkProofAudit {
        envelope: hex::encode(rebuilt),
        report: summarize_report(&report),
    })
}

#[cfg(feature = "backend-rpp-stark")]
fn summarize_report(report: &RppStarkVerificationReport) -> RppStarkReportSummary {
    let trace_indices = report
        .trace_query_indices()
        .map(|indices| indices.to_vec());
    RppStarkReportSummary {
        backend: report.backend().to_string(),
        verified: report.is_verified(),
        params_ok: report.params_ok(),
        public_ok: report.public_ok(),
        merkle_ok: report.merkle_ok(),
        fri_ok: report.fri_ok(),
        composition_ok: report.composition_ok(),
        total_bytes: report.total_bytes(),
        notes: report.notes().map(|note| note.to_string()),
        trace_query_indices: trace_indices,
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, serde::Serialize)]
pub struct Balance {
    #[serde(rename = "confirmed")]
    confirmed_balance: u64,
    #[serde(rename = "unconfirmed")]
    mempool_delta: i64,
}

impl Balance {
    pub fn confirmed(&self) -> u64 {
        self.confirmed_balance
    }

    pub fn mempool_delta(&self) -> i64 {
        self.mempool_delta
    }
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
    #[cfg(feature = "backend-rpp-stark")]
    digest: Option<StatusDigest>,
    #[cfg(feature = "backend-rpp-stark")]
    proof_audit: Option<RppStarkProofAudit>,
    #[cfg(feature = "backend-rpp-stark")]
    vrf_audit: Option<StoredVrfAudit>,
    double_spend: Option<bool>,
}

impl HistoryEntry {
    fn confirmed(
        txid: Txid,
        height: usize,
        fee: Option<u64>,
        #[cfg(feature = "backend-rpp-stark")] digest: Option<StatusDigest>,
        #[cfg(feature = "backend-rpp-stark")] proof_audit: Option<RppStarkProofAudit>,
        #[cfg(feature = "backend-rpp-stark")] vrf_audit: Option<StoredVrfAudit>,
        double_spend: Option<bool>,
    ) -> Self {
        Self {
            txid,
            height: Height::Confirmed { height },
            fee,
            #[cfg(feature = "backend-rpp-stark")]
            digest,
            #[cfg(feature = "backend-rpp-stark")]
            proof_audit,
            #[cfg(feature = "backend-rpp-stark")]
            vrf_audit,
            double_spend,
        }
    }

    fn unconfirmed(
        txid: Txid,
        has_unconfirmed_inputs: bool,
        fee: u64,
        #[cfg(feature = "backend-rpp-stark")] digest: Option<StatusDigest>,
        #[cfg(feature = "backend-rpp-stark")] proof_audit: Option<RppStarkProofAudit>,
        #[cfg(feature = "backend-rpp-stark")] vrf_audit: Option<StoredVrfAudit>,
        double_spend: Option<bool>,
    ) -> Self {
        Self {
            txid,
            height: Height::Unconfirmed {
                has_unconfirmed_inputs,
            },
            fee: Some(fee),
            #[cfg(feature = "backend-rpp-stark")]
            digest,
            #[cfg(feature = "backend-rpp-stark")]
            proof_audit,
            #[cfg(feature = "backend-rpp-stark")]
            vrf_audit,
            double_spend,
        }
    }

    #[cfg(feature = "backend-rpp-stark")]
    fn hash(&self, hasher: &mut RppStarkHasher) {
        hasher.update(self.txid.as_bytes());
        hasher.update(&self.height.as_i64().to_le_bytes());
    }

    #[cfg(feature = "backend-rpp-stark")]
    fn digest(&self) -> Option<&StatusDigest> {
        self.digest.as_ref()
    }

    #[cfg(not(feature = "backend-rpp-stark"))]
    fn append_encoded(&self, output: &mut Vec<u8>) {
        output.extend_from_slice(self.txid.as_bytes());
        output.extend_from_slice(&self.height.as_i64().to_le_bytes());
    }
}

impl Serialize for HistoryEntry {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("HistoryEntry", 5)?;
        state.serialize_field("tx_hash", &hex_string(self.txid.as_bytes()))?;
        state.serialize_field("height", &self.height)?;
        if let Some(fee) = self.fee {
            state.serialize_field("fee", &fee)?;
        }
        #[cfg(feature = "backend-rpp-stark")]
        if let Some(digest) = &self.digest {
            state.serialize_field("digest", digest)?;
        }
        #[cfg(feature = "backend-rpp-stark")]
        if let Some(proof) = &self.proof_audit {
            state.serialize_field("proof", proof)?;
        }
        #[cfg(feature = "backend-rpp-stark")]
        if let Some(vrf) = &self.vrf_audit {
            state.serialize_field("vrf", vrf)?;
        }
        if let Some(flag) = self.double_spend {
            state.serialize_field("double_spend", &flag)?;
        }
        state.end()
    }
}

#[derive(Clone, Debug)]
pub struct ScriptHashStatus {
    scripthash: ScriptHash,
    tip: BlockHash,
    history: Vec<HistoryEntry>,
    statushash: Option<StatusDigest>,
    confirmed_balance: u64,
    mempool_delta: i64,
    unspent: Vec<UnspentEntry>,
}

impl ScriptHashStatus {
    /// Create a new status tracker for the given script hash.
    pub fn new(scripthash: ScriptHash) -> Self {
        Self {
            scripthash,
            tip: BlockHash::default(),
            history: Vec::new(),
            statushash: None,
            confirmed_balance: 0,
            mempool_delta: 0,
            unspent: Vec::new(),
        }
    }

    /// Recompute the confirmed history for `script`.
    pub fn sync(
        &mut self,
        script: &Script,
        index: &Index,
        chain: &Chain,
        mempool: Option<&MempoolStatus>,
    ) -> anyhow::Result<()> {
        let confirmed = index.script_history(script);
        self.tip = chain.tip();
        let mut history = Vec::new();
        let mut seen: HashSet<(usize, Txid)> = HashSet::new();
        let mut ordered = Vec::new();
        let mut outputs: HashMap<OutPoint, (usize, u64)> = HashMap::new();
        let mut balance: u128 = 0;

        for (height, txid) in confirmed {
            if seen.insert((height, txid)) {
                ordered.push((height, txid));
            }
        }

        ordered.sort_by(|(left_height, left_txid), (right_height, right_txid)| {
            left_height
                .cmp(right_height)
                .then_with(|| left_txid.as_bytes().cmp(right_txid.as_bytes()))
        });

        for (height, txid) in ordered {
            let transaction = index
                .transaction_at(height, txid)?
                .with_context(|| anyhow!("transaction {txid:?} at height {height} missing"))?;
            let metadata = index
                .transaction_metadata_at(height, txid)
                .and_then(|bytes| decode_transaction_metadata(&bytes));
            process_confirmed_transaction(
                &transaction,
                metadata.as_ref(),
                height,
                txid,
                &self.scripthash,
                &mut outputs,
                &mut balance,
                &mut history,
            )?;
        }

        let mut unspent: Vec<UnspentEntry> = outputs
            .into_iter()
            .map(|(outpoint, (height, value))| UnspentEntry {
                height,
                tx_hash: outpoint.txid,
                tx_pos: outpoint.vout,
                value,
            })
            .collect();
        unspent.sort_by_key(|entry| (entry.height, entry.tx_pos));

        let mut mempool_delta: i128 = 0;
        if let Some(status) = mempool {
            let mut mempool_history = process_mempool(
                status,
                &self.scripthash,
                &mut mempool_delta,
            )?;
            history.append(&mut mempool_history);
        }

        self.confirmed_balance = balance.min(u128::from(u64::MAX)) as u64;
        self.mempool_delta = mempool_delta
            .clamp(i128::from(i64::MIN), i128::from(i64::MAX))
            as i64;
        self.unspent = unspent;
        self.history = history;
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

    /// Compute the balance of tracked entries derived from confirmed history and
    /// observed mempool deltas.
    pub fn get_balance(&self, _chain: &Chain) -> Balance {
        Balance {
            confirmed_balance: self.confirmed_balance,
            mempool_delta: self.mempool_delta,
        }
    }

    /// List all confirmed unspent outputs for the tracked script hash.
    pub fn get_unspent(&self, _chain: &Chain) -> Vec<UnspentEntry> {
        self.unspent.clone()
    }

    /// Hash of the status history as defined by the Electrum protocol.
    pub fn statushash(&self) -> Option<StatusDigest> {
        self.statushash
    }
}

fn process_confirmed_transaction(
    transaction: &Transaction,
    metadata: Option<&StoredTransactionMetadata>,
    height: usize,
    txid: Txid,
    scripthash: &ScriptHash,
    outputs: &mut HashMap<OutPoint, (usize, u64)>,
    balance: &mut u128,
    history: &mut Vec<HistoryEntry>,
) -> anyhow::Result<()> {
    let fee = metadata.map(|meta| meta.transaction.payload.fee);
    #[cfg(feature = "backend-rpp-stark")]
    let history_entry = {
        let digest = confirmed_entry_digest(metadata)?;
        let proof_audit = metadata.and_then(|meta| meta.proof_audit.clone());
        let vrf_audit = metadata.and_then(|meta| meta.vrf_audit.clone());
        HistoryEntry::confirmed(txid, height, fee, digest, proof_audit, vrf_audit, Some(false))
    };
    #[cfg(not(feature = "backend-rpp-stark"))]
    let history_entry = HistoryEntry::confirmed(txid, height, fee, Some(false));
    history.push(history_entry);

    for input in transaction.inputs() {
        if let Some((_, value)) = outputs.remove(input) {
            *balance = balance.saturating_sub(u128::from(value));
        }
    }

    for (index_pos, output) in transaction.outputs().iter().enumerate() {
        let output_hash = ScriptHash::new(output);
        if &output_hash != scripthash {
            continue;
        }
        if let Some(amount) = extract_amount(output)? {
            *balance = balance.saturating_add(u128::from(amount));
            let outpoint = OutPoint::new(txid, index_pos as u32);
            outputs.insert(outpoint, (height, amount));
        }
    }

    Ok(())
}

fn process_mempool(
    status: &MempoolStatus,
    scripthash: &ScriptHash,
    delta: &mut i128,
) -> anyhow::Result<Vec<HistoryEntry>> {
    let mut history = Vec::new();
    for tx in &status.transactions {
        if let Some((entry, amount)) = mempool_entry(tx, scripthash)? {
            *delta += i128::from(amount);
            history.push(entry);
        }
    }
    Ok(history)
}

fn mempool_entry(
    tx: &PendingTransactionSummary,
    scripthash: &ScriptHash,
) -> anyhow::Result<Option<(HistoryEntry, u64)>> {
    let txid = decode_txid(&tx.hash);
    let script = Script::new(encode_ledger_script(&LedgerScriptPayload::Recipient {
        to: tx.to.clone(),
        amount: tx.amount,
    }));
    if ScriptHash::new(&script) != *scripthash {
        return Ok(None);
    }
    let amount = u64::try_from(tx.amount).context("mempool amount exceeds u64")?;
    #[cfg(feature = "backend-rpp-stark")]
    let entry = {
        let digest = mempool_entry_digest(tx)?;
        HistoryEntry::unconfirmed(txid, false, tx.fee, digest, None, None, Some(false))
    };
    #[cfg(not(feature = "backend-rpp-stark"))]
    let entry = HistoryEntry::unconfirmed(txid, false, tx.fee, Some(false));
    Ok(Some((entry, amount)))
}

fn decode_txid(hash: &str) -> Txid {
    let trimmed = hash.trim_start_matches("0x");
    if let Ok(bytes) = hex::decode(trimmed) {
        if bytes.len() == 32 {
            let mut array = [0u8; 32];
            array.copy_from_slice(&bytes);
            return Txid::from_bytes(array);
        }
    }
    let digest = sha256::Hash::hash(hash.as_bytes()).into_inner();
    Txid::from_bytes(digest)
}

fn extract_amount(script: &Script) -> anyhow::Result<Option<u64>> {
    match decode_ledger_script(script.as_bytes()) {
        Some(LedgerScriptPayload::Recipient { amount, .. }) => {
            let value = u64::try_from(amount).context("output amount exceeds u64")?;
            Ok(Some(value))
        }
        Some(LedgerScriptPayload::Sender { .. }) | None => Ok(None),
    }
}

#[cfg(feature = "backend-rpp-stark")]
fn compute_statushash(history: &[HistoryEntry]) -> Option<StatusDigest> {
    if history.is_empty() {
        return None;
    }
    let mut hasher = RppStarkHasher::new();
    for entry in history {
        match entry.digest() {
            Some(digest) => hasher.update(digest.as_bytes()),
            None => hasher.update(&[0u8; 32]),
        }
    }
    let digest: Digest32 = hasher.finalize();
    Some(StatusDigest::from_digest(digest))
}

#[cfg(not(feature = "backend-rpp-stark"))]
fn compute_statushash(history: &[HistoryEntry]) -> Option<StatusDigest> {
    if history.is_empty() {
        return None;
    }
    const TXID_BYTES: usize = 32;
    let mut encoded = Vec::with_capacity(history.len() * (TXID_BYTES + std::mem::size_of::<i64>()));
    for entry in history {
        entry.append_encoded(&mut encoded);
    }
    let digest = sha256::Hash::hash(&encoded).into_inner();
    Some(StatusDigest::from_bytes(digest))
}

#[cfg(feature = "backend-rpp-stark")]
fn confirmed_entry_digest(
    metadata: Option<&StoredTransactionMetadata>,
) -> anyhow::Result<Option<StatusDigest>> {
    let Some(metadata) = metadata else {
        return Ok(None);
    };
    let Some(witness) = metadata.witness.as_ref() else {
        return Ok(None);
    };
    let witness_bytes = encode_transaction_witness(witness)
        .map_err(|err| anyhow!("encode transaction witness payload: {err}"))?;
    let Some(proof_bytes) = metadata.rpp_stark_proof.as_deref() else {
        return Ok(None);
    };
    let public_digest = parse_public_inputs_digest(proof_bytes)?;
    Ok(Some(hash_entry_components(Some(&witness_bytes), public_digest)))
}

#[cfg(feature = "backend-rpp-stark")]
fn mempool_entry_digest(tx: &PendingTransactionSummary) -> anyhow::Result<Option<StatusDigest>> {
    let Some(hex_digest) = tx.public_inputs_digest.as_deref() else {
        return Ok(None);
    };
    let public_digest = Digest32::from_hex(hex_digest)
        .map_err(|err| anyhow!("decode mempool public input digest: {err}"))?;
    Ok(Some(hash_entry_components(None, public_digest)))
}

#[cfg(feature = "backend-rpp-stark")]
fn parse_public_inputs_digest(bytes: &[u8]) -> anyhow::Result<Digest32> {
    let proof: RppStarkProof = serde_json::from_slice(bytes)
        .context("decode stored rpp-stark proof payload")?;
    Ok(compute_public_digest(proof.public_inputs()))
}

#[cfg(feature = "backend-rpp-stark")]
fn hash_entry_components(
    witness_bytes: Option<&[u8]>,
    public_digest: Digest32,
) -> StatusDigest {
    let witness_bytes = witness_bytes.unwrap_or(&[]);
    let witness_len = u32::try_from(witness_bytes.len()).unwrap_or(u32::MAX);
    let mut hasher = RppStarkHasher::new();
    hasher.update(&witness_len.to_le_bytes());
    hasher.update(witness_bytes);
    hasher.update(public_digest.as_bytes());
    StatusDigest::from_digest(hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::fs;

    use hex::encode;
    use tempfile::TempDir;

    use crate::vendor::electrs::daemon::test_helpers::setup;
    use crate::vendor::electrs::index::Index;
    use crate::vendor::electrs::rpp_ledger::bitcoin::Network;
    use crate::vendor::electrs::tracker::Tracker;
    use rpp::runtime::config::QueueWeightsConfig;

    #[test]
    fn sync_derives_balance_and_unspent_outputs() {
        let temp_dir = TempDir::new().expect("tempdir");
        let index_path = temp_dir.path().join("index");
        fs::create_dir_all(&index_path).expect("index dir");

        let index = Index::open(&index_path, Network::Regtest).expect("open index");
        let mut tracker = Tracker::new(index);
        let context = setup();

        tracker.sync(&context.daemon).expect("sync tracker");

        let transaction = tracker
            .index()
            .transaction_at(1, context.transaction_id)
            .expect("transaction lookup")
            .expect("transaction present");
        let script = transaction.outputs().first().expect("output").clone();
        let scripthash = ScriptHash::new(&script);

        let mut status = ScriptHashStatus::new(scripthash);
        status
            .sync(&script, tracker.index(), tracker.chain(), None)
            .expect("sync status");

        let balance = status.get_balance(tracker.chain());
        assert!(balance.confirmed() > 0);
        assert_eq!(balance.mempool_delta(), 0);

        let unspent = status.get_unspent(tracker.chain());
        assert!(!unspent.is_empty());
        assert_eq!(unspent[0].value, balance.confirmed());

        let baseline = status.statushash();

        let script_text = std::str::from_utf8(script.as_bytes()).expect("script text");
        let mut parts = script_text.split(':');
        let _ = parts.next();
        let address = parts.next().expect("address");
        let amount = parts
            .next()
            .expect("amount")
            .parse::<u128>()
            .expect("parse amount");

        let pending = PendingTransactionSummary {
            hash: encode([3u8; 32]),
            from: "mempool-from".to_string(),
            to: address.to_string(),
            amount,
            fee: 7,
            nonce: 1,
            #[cfg(feature = "backend-rpp-stark")]
            public_inputs_digest: None,
        };
        let mempool = MempoolStatus {
            transactions: vec![pending],
            identities: Vec::new(),
            votes: Vec::new(),
            uptime_proofs: Vec::new(),
            queue_weights: QueueWeightsConfig::default(),
        };

        status
            .sync(&script, tracker.index(), tracker.chain(), Some(&mempool))
            .expect("sync with mempool");

        let updated = status.get_balance(tracker.chain());
        assert_eq!(updated.confirmed(), balance.confirmed());
        let expected_delta = i64::try_from(amount).expect("delta fits in i64");
        assert_eq!(updated.mempool_delta(), expected_delta);

        assert_ne!(baseline, status.statushash());
        assert!(status
            .get_history()
            .iter()
            .any(|entry| matches!(entry.height, Height::Unconfirmed { .. })));
    }
}
