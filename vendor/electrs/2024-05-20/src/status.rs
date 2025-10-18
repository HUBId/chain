use std::collections::{HashMap, HashSet};
#[cfg(feature = "backend-rpp-stark")]
use std::convert::TryFrom;
#[cfg(feature = "backend-rpp-stark")]
use std::fmt;

use anyhow::{anyhow, Context};
use serde::ser::{Serialize, SerializeStruct, Serializer};
#[cfg(feature = "backend-rpp-stark")]
use log::warn;

#[cfg(feature = "backend-rpp-stark")]
use crate::zk::rpp_adapter::{compute_public_digest, Digest32, RppStarkHasher};
#[cfg(feature = "backend-rpp-stark")]
use crate::zk::rpp_verifier::{
    RppStarkVerificationReport, RppStarkVerifier, RppStarkVerifierError,
};
#[cfg(feature = "backend-rpp-stark")]
use crate::vendor::electrs::types::{
    RppStarkProofAudit, RppStarkReportSummary, StoredVrfAudit, VrfInputDescriptor,
    VrfOutputDescriptor,
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
    decode_ledger_script, decode_transaction_metadata, encode_ledger_script,
    encode_transaction_metadata, LedgerScriptPayload, ScriptHash, StatusDigest,
    StoredTransactionMetadata,
};
use rpp::runtime::node::{MempoolStatus, PendingTransactionSummary};
#[cfg(feature = "backend-rpp-stark")]
use rpp::{
    proofs::rpp::{
        encode_transaction_witness, TransactionUtxoSnapshot, TransactionWitness, UtxoOutpoint,
    },
    runtime::types::proofs::{ChainProof, ProofPayload, RppStarkProof},
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
    #[cfg(feature = "backend-rpp-stark")]
    conflict: Option<HistoryConflictReason>,
    double_spend: Option<bool>,
}

#[cfg(feature = "backend-rpp-stark")]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum HistoryConflictReason {
    MissingData { detail: String },
    VerificationMismatch { detail: String },
}

#[cfg(feature = "backend-rpp-stark")]
impl HistoryConflictReason {
    fn kind(&self) -> &'static str {
        match self {
            Self::MissingData { .. } => "missing_data",
            Self::VerificationMismatch { .. } => "verification_mismatch",
        }
    }

    fn detail(&self) -> &str {
        match self {
            Self::MissingData { detail } | Self::VerificationMismatch { detail } => detail,
        }
    }
}

#[cfg(feature = "backend-rpp-stark")]
impl fmt::Display for HistoryConflictReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.kind(), self.detail())
    }
}

#[cfg(feature = "backend-rpp-stark")]
impl Serialize for HistoryConflictReason {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("HistoryConflictReason", 2)?;
        state.serialize_field("kind", self.kind())?;
        state.serialize_field("detail", self.detail())?;
        state.end()
    }
}

#[cfg(feature = "backend-rpp-stark")]
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
pub struct HistoryEntryWithMetadata {
    pub entry: HistoryEntry,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub digest: Option<StatusDigest>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proof: Option<RppStarkProofAudit>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vrf: Option<StoredVrfAudit>,
}

impl HistoryEntry {
    fn confirmed(
        txid: Txid,
        height: usize,
        fee: Option<u64>,
        #[cfg(feature = "backend-rpp-stark")] digest: Option<StatusDigest>,
        #[cfg(feature = "backend-rpp-stark")] proof_audit: Option<RppStarkProofAudit>,
        #[cfg(feature = "backend-rpp-stark")] vrf_audit: Option<StoredVrfAudit>,
        #[cfg(feature = "backend-rpp-stark")] conflict: Option<HistoryConflictReason>,
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
            #[cfg(feature = "backend-rpp-stark")]
            conflict,
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
        #[cfg(feature = "backend-rpp-stark")] conflict: Option<HistoryConflictReason>,
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
            #[cfg(feature = "backend-rpp-stark")]
            conflict,
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

    #[cfg(feature = "backend-rpp-stark")]
    fn proof_audit(&self) -> Option<&RppStarkProofAudit> {
        self.proof_audit.as_ref()
    }

    #[cfg(feature = "backend-rpp-stark")]
    fn vrf_audit(&self) -> Option<&StoredVrfAudit> {
        self.vrf_audit.as_ref()
    }

    #[cfg(feature = "backend-rpp-stark")]
    fn conflict(&self) -> Option<&HistoryConflictReason> {
        self.conflict.as_ref()
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
        #[cfg(feature = "backend-rpp-stark")]
        if let Some(conflict) = &self.conflict {
            state.serialize_field("conflict", conflict)?;
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

        let mut mempool_delta: i128 = 0;
        if let Some(status) = mempool {
            let processed_entries = process_mempool(
                status,
                &self.scripthash,
                &outputs,
            )?;
            for (entry, credit) in processed_entries {
                if let Some(amount) = credit {
                    mempool_delta += i128::from(amount);
                }
                history.push(entry);
            }
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

    #[cfg(feature = "backend-rpp-stark")]
    pub fn history_with_digests(&self) -> Vec<HistoryEntryWithMetadata> {
        self.history
            .iter()
            .map(|entry| HistoryEntryWithMetadata {
                entry: entry.clone(),
                digest: entry.digest.clone(),
                proof: entry.proof_audit().cloned(),
                vrf: entry.vrf_audit().cloned(),
            })
            .collect()
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
        self.status_digest()
    }

    /// Digest of the status history including RPP metadata when enabled.
    pub fn status_digest(&self) -> Option<StatusDigest> {
        self.statushash
    }

    #[cfg(feature = "backend-rpp-stark")]
    pub fn proof_envelopes(&self) -> Vec<Option<String>> {
        self.history
            .iter()
            .map(|entry| {
                entry
                    .proof_audit()
                    .map(|audit| audit.envelope.clone())
            })
            .collect()
    }

    #[cfg(feature = "backend-rpp-stark")]
    pub fn vrf_audits(&self) -> Vec<Option<StoredVrfAudit>> {
        self.history
            .iter()
            .map(|entry| entry.vrf_audit().cloned())
            .collect()
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
        HistoryEntry::confirmed(txid, height, fee, digest, proof_audit, vrf_audit, None, Some(false))
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
    confirmed_unspent: &HashMap<OutPoint, (usize, u64)>,
) -> anyhow::Result<Vec<(HistoryEntry, Option<u64>)>> {
    let mut entries = Vec::new();
    for tx in &status.transactions {
        if let Some((entry, credit)) = mempool_entry(tx, scripthash, confirmed_unspent)? {
            entries.push((entry, credit));
        }
    }
    Ok(entries)
}

fn mempool_entry(
    tx: &PendingTransactionSummary,
    scripthash: &ScriptHash,
    confirmed_unspent: &HashMap<OutPoint, (usize, u64)>,
) -> anyhow::Result<Option<(HistoryEntry, Option<u64>)>> {
    #[cfg(not(feature = "backend-rpp-stark"))]
    let _ = confirmed_unspent;
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
    let (digest, double_spend, credit, conflict) = match verify_pending_transaction(
        tx,
        scripthash,
        confirmed_unspent,
    )? {
        PendingVerificationResult::Verified(verification) => {
            let credit = if verification.double_spend {
                None
            } else {
                Some(amount)
            };
            (
                verification.digest,
                Some(verification.double_spend),
                credit,
                None,
            )
        }
        PendingVerificationResult::Conflict(conflict) => {
            warn!(
                "mempool transaction {} flagged during verification: {}",
                tx.hash,
                conflict
            );
            (None, Some(true), None, Some(conflict))
        }
    };
    #[cfg(not(feature = "backend-rpp-stark"))]
    let credit = Some(amount);
    #[cfg(not(feature = "backend-rpp-stark"))]
    let entry = HistoryEntry::unconfirmed(txid, false, tx.fee, Some(false));
    #[cfg(feature = "backend-rpp-stark")]
    let entry = HistoryEntry::unconfirmed(txid, false, tx.fee, digest, None, None, double_spend, conflict);
    #[cfg(feature = "backend-rpp-stark")]
    return Ok(Some((entry, credit)));
    #[cfg(not(feature = "backend-rpp-stark"))]
    Ok(Some((entry, credit)))
}

#[cfg(feature = "backend-rpp-stark")]
struct PendingWitnessVerification {
    digest: Option<StatusDigest>,
    double_spend: bool,
}

#[cfg(feature = "backend-rpp-stark")]
enum PendingVerificationResult {
    Verified(PendingWitnessVerification),
    Conflict(HistoryConflictReason),
}

#[cfg(feature = "backend-rpp-stark")]
fn verify_pending_transaction(
    tx: &PendingTransactionSummary,
    scripthash: &ScriptHash,
    confirmed_unspent: &HashMap<OutPoint, (usize, u64)>,
) -> anyhow::Result<PendingVerificationResult> {
    let witness = match extract_pending_witness(tx)? {
        Some(witness) => witness,
        None => {
            return Ok(PendingVerificationResult::Conflict(
                HistoryConflictReason::MissingData {
                    detail: "transaction witness missing".to_string(),
                },
            ));
        }
    };

    let tracked_outpoints = collect_tracked_outpoints(&witness, scripthash)?;
    let double_spend = tracked_outpoints
        .iter()
        .any(|outpoint| !confirmed_unspent.contains_key(outpoint));

    let public_digest = match extract_public_inputs_digest(tx) {
        Ok(digest) => digest,
        Err(conflict) => return Ok(PendingVerificationResult::Conflict(conflict)),
    };

    let witness_bytes = match encode_transaction_witness(&witness) {
        Ok(bytes) => bytes,
        Err(err) => {
            return Ok(PendingVerificationResult::Conflict(
                HistoryConflictReason::VerificationMismatch {
                    detail: format!("encode transaction witness payload: {err}"),
                },
            ));
        }
    };

    let digest = hash_entry_components(Some(&witness_bytes), public_digest);

    Ok(PendingVerificationResult::Verified(PendingWitnessVerification {
        digest: Some(digest),
        double_spend,
    }))
}

#[cfg(feature = "backend-rpp-stark")]
fn extract_pending_witness(
    tx: &PendingTransactionSummary,
) -> anyhow::Result<Option<TransactionWitness>> {
    if let Some(witness) = tx.witness.clone() {
        return Ok(Some(witness));
    }

    if let Some(payload) = tx.proof_payload.as_ref() {
        if let ProofPayload::Transaction(witness) = payload {
            return Ok(Some(witness.clone()));
        }
    }

    if let Some(ChainProof::Stwo(stwo)) = tx.proof.as_ref() {
        if let ProofPayload::Transaction(witness) = &stwo.payload {
            return Ok(Some(witness.clone()));
        }
    }

    Ok(None)
}

#[cfg(feature = "backend-rpp-stark")]
fn extract_public_inputs_digest(
    tx: &PendingTransactionSummary,
) -> Result<Digest32, HistoryConflictReason> {
    if let Some(hex_digest) = tx.public_inputs_digest.as_deref() {
        return Digest32::from_hex(hex_digest).map_err(|err| {
            HistoryConflictReason::VerificationMismatch {
                detail: format!("decode mempool public input digest: {err}"),
            }
        });
    }

    if let Some(ChainProof::RppStark(proof)) = tx.proof.as_ref() {
        return Ok(compute_public_digest(proof.public_inputs()));
    }

    Err(HistoryConflictReason::MissingData {
        detail: "public inputs digest missing".to_string(),
    })
}

#[cfg(feature = "backend-rpp-stark")]
fn collect_tracked_outpoints(
    witness: &TransactionWitness,
    scripthash: &ScriptHash,
) -> anyhow::Result<Vec<OutPoint>> {
    let mut outpoints = Vec::new();
    for snapshot in witness
        .sender_utxos_before
        .iter()
        .chain(witness.recipient_utxos_before.iter())
    {
        if let Some(outpoint) = match_tracked_outpoint(snapshot, scripthash)? {
            outpoints.push(outpoint);
        }
    }
    Ok(outpoints)
}

#[cfg(feature = "backend-rpp-stark")]
fn match_tracked_outpoint(
    snapshot: &TransactionUtxoSnapshot,
    scripthash: &ScriptHash,
) -> anyhow::Result<Option<OutPoint>> {
    let script = Script::new(encode_ledger_script(&LedgerScriptPayload::Recipient {
        to: snapshot.utxo.owner.clone(),
        amount: snapshot.utxo.amount,
    }));
    if ScriptHash::new(&script) != *scripthash {
        return Ok(None);
    }

    let outpoint = convert_outpoint(&snapshot.outpoint);
    Ok(Some(outpoint))
}

#[cfg(feature = "backend-rpp-stark")]
fn convert_outpoint(outpoint: &UtxoOutpoint) -> OutPoint {
    OutPoint::new(Txid::from_bytes(outpoint.tx_id), outpoint.index)
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

    use crate::vendor::electrs::index::Index;
    use crate::vendor::electrs::rpp_ledger::bitcoin::Network;
    use crate::vendor::electrs::tracker::Tracker;
    use rpp::runtime::config::QueueWeightsConfig;
    #[cfg(feature = "backend-rpp-stark")]
    use crate::vendor::electrs::rpp_ledger::bitcoin::{
        blockdata::block::Header as BlockHeader, OutPoint, Script, Txid,
    };
    #[cfg(feature = "backend-rpp-stark")]
    use crate::vendor::electrs::types::LedgerScriptPayload;
    #[cfg(feature = "backend-rpp-stark")]
    use crate::zk::rpp_adapter::{compute_public_digest, Digest32};
    #[cfg(feature = "backend-rpp-stark")]
    use rpp::proofs::rpp::{
        AccountBalanceWitness, TransactionUtxoSnapshot, TransactionWitness, UtxoOutpoint,
    };
    #[cfg(feature = "backend-rpp-stark")]
    use rpp::runtime::types::proofs::{ChainProof, RppStarkProof};
    #[cfg(feature = "backend-rpp-stark")]
    use rpp::runtime::types::transaction::Transaction as RuntimeTransaction;
    #[cfg(feature = "backend-rpp-stark")]
    use rpp::storage::state::utxo::StoredUtxo;
    #[cfg(feature = "backend-rpp-stark")]
    use uuid::Uuid;

    #[cfg(feature = "backend-rpp-stark")]
    fn sample_header(parent: BlockHash, height: u32) -> BlockHeader {
        BlockHeader::new(
            parent,
            [height as u8; 32],
            [height.wrapping_add(1) as u8; 32],
            [height.wrapping_add(2) as u8; 32],
            [height.wrapping_add(3) as u8; 64],
            [height.wrapping_add(4) as u8; 32],
            height as u64,
        )
    }

    #[cfg(feature = "backend-rpp-stark")]
    #[test]
    fn sync_exports_rpp_stark_metadata() {
        let temp_dir = TempDir::new().expect("tempdir");
        let index_path = temp_dir.path().join("index");
        fs::create_dir_all(&index_path).expect("index dir");

        let mut index = Index::open(&index_path, Network::Regtest).expect("open index");
        let parent = index.chain().tip();
        let header = sample_header(parent, 1);

        let recipient = "rpp-recipient";
        let amount = 123u128;
        let fee = 7u64;
        let script = Script::new(encode_ledger_script(&LedgerScriptPayload::Recipient {
            to: recipient.to_string(),
            amount,
        }));
        let tx_inputs = vec![OutPoint::new(Txid::from_bytes([0x10; 32]), 0)];
        let tx = Transaction::new(tx_inputs, vec![script.clone()], Vec::new());
        let txid = crate::vendor::electrs::types::bsl_txid(&tx);
        let mut txid_bytes = [0u8; 32];
        txid_bytes.copy_from_slice(txid.as_bytes());
        let witness = sample_transaction_witness(txid_bytes, 0, recipient, amount, fee);

        let proof = RppStarkProof::new(vec![0xAA, 0xBB], vec![0xCC, 0xDD], vec![0xEE, 0xFF]);
        let proof_bytes = serde_json::to_vec(&proof).expect("encode proof");
        let witness_bytes = encode_transaction_witness(&witness).expect("witness bytes");
        let public_digest = compute_public_digest(proof.public_inputs());
        let expected_digest = hash_entry_components(Some(&witness_bytes), public_digest);

        let proof_audit = RppStarkProofAudit {
            envelope: "feedface".into(),
            report: RppStarkReportSummary {
                backend: "rpp-stark".into(),
                verified: true,
                params_ok: true,
                public_ok: true,
                merkle_ok: true,
                fri_ok: true,
                composition_ok: true,
                total_bytes: proof_bytes.len() as u64,
                notes: Some("verified".into()),
                trace_query_indices: Some(vec![1, 2, 3]),
            },
        };
        let vrf_audit = StoredVrfAudit {
            input: VrfInputDescriptor {
                last_block_header: "0xfeed".into(),
                epoch: 42,
                tier_seed: "0xdead".into(),
            },
            output: VrfOutputDescriptor {
                randomness: "0xbeef".into(),
                preoutput: "0xcafe".into(),
                proof: "0xabba".into(),
            },
        };

        let runtime_tx = RuntimeTransaction::new(
            "sender".into(),
            recipient.into(),
            amount,
            fee,
            1,
            None,
        );
        let signed = rpp::runtime::types::SignedTransaction {
            id: Uuid::nil(),
            payload: runtime_tx,
            signature: "signature".into(),
            public_key: "public-key".into(),
        };
        let metadata = StoredTransactionMetadata {
            transaction: signed,
            witness: Some(witness.clone()),
            rpp_stark_proof: Some(proof_bytes.clone()),
            proof_audit: Some(proof_audit.clone()),
            vrf_audit: Some(vrf_audit.clone()),
        };
        let metadata_bytes = encode_transaction_metadata(&metadata);

        index
            .index_block(header, &[tx.clone()], Some(&vec![Some(metadata_bytes)]))
            .expect("index block with metadata");

        let tracker = Tracker::new(index);
        let scripthash = ScriptHash::new(&script);
        let mut status = ScriptHashStatus::new(scripthash);
        status
            .sync(&script, tracker.index(), tracker.chain(), None)
            .expect("sync status");

        let digest = tracker
            .get_status_digest(&status)
            .expect("status digest computed");
        assert_eq!(digest, expected_digest);

        let history = tracker.get_history_with_digests(&status);
        assert_eq!(history.len(), 1, "confirmed history entry expected");
        let entry = &history[0];
        assert_eq!(entry.entry.txid, txid);
        assert_eq!(entry.digest, Some(expected_digest));
        assert_eq!(entry.proof, Some(proof_audit.clone()));
        assert_eq!(entry.vrf, Some(vrf_audit.clone()));

        let proof_envelopes = tracker.get_proof_envelopes(&status);
        assert_eq!(proof_envelopes, vec![Some(proof_audit.envelope.clone())]);

        let vrf_audits = tracker.get_vrf_audits(&status);
        assert_eq!(vrf_audits, vec![Some(vrf_audit)]);
    }

    #[cfg(feature = "backend-rpp-stark")]
    fn sample_transaction_witness(
        tx_id: [u8; 32],
        utxo_index: u32,
        recipient: &str,
        amount: u128,
        fee: u64,
    ) -> TransactionWitness {
        let recipient_snapshot = TransactionUtxoSnapshot::new(
            UtxoOutpoint { tx_id, index: utxo_index },
            StoredUtxo::new(recipient.to_string(), amount),
        );
        let sender_before = AccountBalanceWitness::new("sender".to_string(), amount + u128::from(fee), 1);
        let sender_after = AccountBalanceWitness::new("sender".to_string(), u128::from(fee), 2);
        let recipient_before = Some(AccountBalanceWitness::new(recipient.to_string(), 0, 0));
        let recipient_after = AccountBalanceWitness::new(recipient.to_string(), amount, 1);
        TransactionWitness::new(
            tx_id,
            fee,
            sender_before,
            sender_after,
            recipient_before,
            recipient_after,
            vec![recipient_snapshot.clone()],
            Vec::new(),
            vec![recipient_snapshot],
            vec![TransactionUtxoSnapshot::new(
                UtxoOutpoint {
                    tx_id: [0x44; 32],
                    index: 0,
                },
                StoredUtxo::new(recipient.to_string(), amount),
            )],
        )
    }

    #[cfg(feature = "backend-rpp-stark")]
    fn sample_pending_transaction(
        scripthash: &ScriptHash,
        tx_hash: [u8; 32],
        witness: TransactionWitness,
        digest: Digest32,
        amount: u128,
        proof: Option<ChainProof>,
    ) -> PendingTransactionSummary {
        let address = witness.recipient_after.address.clone();
        let script = Script::new(encode_ledger_script(&LedgerScriptPayload::Recipient {
            to: address.clone(),
            amount,
        }));
        assert_eq!(&ScriptHash::new(&script), scripthash, "script hash mismatch");
        PendingTransactionSummary {
            hash: encode(tx_hash),
            from: "sender".to_string(),
            to: address,
            amount,
            fee: witness.fee,
            nonce: 1,
            proof,
            witness: Some(witness),
            proof_payload: None,
            public_inputs_digest: Some(digest.to_hex()),
        }
    }

    #[cfg(feature = "backend-rpp-stark")]
    fn sample_rpp_chain_proof() -> (ChainProof, Digest32) {
        let public_inputs = vec![0x21, 0x43, 0x65];
        let digest = compute_public_digest(&public_inputs);
        let proof = ChainProof::RppStark(RppStarkProof::new(
            vec![0x10, 0x32],
            public_inputs,
            vec![0x54, 0x76, 0x98],
        ));
        (proof, digest)
    }

    #[cfg(feature = "backend-rpp-stark")]
    fn confirmed_outpoints_map(
        tx_id: [u8; 32],
        index: u32,
        amount: u64,
    ) -> HashMap<OutPoint, (usize, u64)> {
        let mut confirmed = HashMap::new();
        confirmed.insert(
            OutPoint::new(Txid::from_bytes(tx_id), index),
            (0usize, amount),
        );
        confirmed
    }

    #[cfg(feature = "backend-rpp-stark")]
    fn process_single_transaction(
        summary: PendingTransactionSummary,
        scripthash: &ScriptHash,
        confirmed: &HashMap<OutPoint, (usize, u64)>,
    ) -> (HistoryEntry, Option<u64>) {
        let mempool = MempoolStatus {
            transactions: vec![summary],
            identities: Vec::new(),
            votes: Vec::new(),
            uptime_proofs: Vec::new(),
            queue_weights: QueueWeightsConfig::default(),
        };
        let entries = process_mempool(&mempool, scripthash, confirmed).expect("process mempool");
        assert_eq!(entries.len(), 1, "unexpected entry count");
        entries.into_iter().next().unwrap()
    }

    #[cfg(feature = "backend-rpp-stark")]
    #[test]
    fn process_mempool_marks_verified_witness_as_safe() {
        let amount = 42u128;
        let scripthash_script = Script::new(encode_ledger_script(&LedgerScriptPayload::Recipient {
            to: "recipient".to_string(),
            amount,
        }));
        let scripthash = ScriptHash::new(&scripthash_script);
        let tx_id = [0x11; 32];
        let digest = Digest32::from([0xAA; 32]);
        let witness = sample_transaction_witness(tx_id, 0, "recipient", amount, 7);
        let pending = sample_pending_transaction(
            &scripthash,
            tx_id,
            witness.clone(),
            digest,
            amount,
            None,
        );
        let confirmed = confirmed_outpoints_map(tx_id, 0, amount as u64);

        let (entry, credit) = process_single_transaction(pending, &scripthash, &confirmed);
        let witness_bytes = encode_transaction_witness(&witness).expect("encode witness");
        let expected_digest = hash_entry_components(Some(&witness_bytes), digest);

        assert_eq!(credit, Some(amount as u64));
        assert_eq!(entry.double_spend, Some(false));
        assert!(entry.conflict().is_none(), "unexpected conflict: {:?}", entry.conflict());
        assert_eq!(entry.digest(), Some(&expected_digest));
    }

    #[cfg(feature = "backend-rpp-stark")]
    #[test]
    fn process_mempool_flags_double_spend_on_missing_utxo() {
        let amount = 75u128;
        let scripthash_script = Script::new(encode_ledger_script(&LedgerScriptPayload::Recipient {
            to: "recipient".to_string(),
            amount,
        }));
        let scripthash = ScriptHash::new(&scripthash_script);
        let tx_id = [0x22; 32];
        let digest = Digest32::from([0xBB; 32]);
        let witness = sample_transaction_witness(tx_id, 0, "recipient", amount, 5);
        let pending = sample_pending_transaction(
            &scripthash,
            tx_id,
            witness.clone(),
            digest,
            amount,
            None,
        );
        let confirmed = HashMap::new();

        let (entry, credit) = process_single_transaction(pending, &scripthash, &confirmed);
        let witness_bytes = encode_transaction_witness(&witness).expect("encode witness");
        let expected_digest = hash_entry_components(Some(&witness_bytes), digest);

        assert!(credit.is_none(), "double-spend credit should be withheld");
        assert_eq!(entry.double_spend, Some(true));
        assert!(entry.conflict().is_none(), "unexpected conflict: {:?}", entry.conflict());
        assert_eq!(entry.digest(), Some(&expected_digest));
    }

    #[cfg(feature = "backend-rpp-stark")]
    #[test]
    fn process_mempool_accepts_valid_double_spend_proof() {
        let amount = 64u128;
        let scripthash_script = Script::new(encode_ledger_script(&LedgerScriptPayload::Recipient {
            to: "recipient".to_string(),
            amount,
        }));
        let scripthash = ScriptHash::new(&scripthash_script);
        let tx_id = [0x44; 32];
        let (proof, digest) = sample_rpp_chain_proof();
        let witness = sample_transaction_witness(tx_id, 0, "recipient", amount, 4);
        let mut pending = sample_pending_transaction(
            &scripthash,
            tx_id,
            witness.clone(),
            digest,
            amount,
            Some(proof),
        );
        pending.public_inputs_digest = None;
        let confirmed = confirmed_outpoints_map(tx_id, 0, amount as u64);

        let (entry, credit) = process_single_transaction(pending, &scripthash, &confirmed);
        let witness_bytes = encode_transaction_witness(&witness).expect("encode witness");
        let expected_digest = hash_entry_components(Some(&witness_bytes), digest);

        assert_eq!(credit, Some(amount as u64));
        assert_eq!(entry.double_spend, Some(false));
        assert!(entry.conflict().is_none());
        assert_eq!(entry.digest(), Some(&expected_digest));
        assert!(entry.proof_audit().is_none());
        assert!(entry.vrf_audit().is_none());
    }

    #[cfg(feature = "backend-rpp-stark")]
    #[test]
    fn process_mempool_rejects_invalid_double_spend_proof() {
        let amount = 91u128;
        let scripthash_script = Script::new(encode_ledger_script(&LedgerScriptPayload::Recipient {
            to: "recipient".to_string(),
            amount,
        }));
        let scripthash = ScriptHash::new(&scripthash_script);
        let tx_id = [0x55; 32];
        let (proof, digest) = sample_rpp_chain_proof();
        let witness = sample_transaction_witness(tx_id, 0, "recipient", amount, 5);
        let mut pending = sample_pending_transaction(
            &scripthash,
            tx_id,
            witness,
            digest,
            amount,
            Some(proof),
        );
        pending.public_inputs_digest = Some("not-a-hex-digest".into());
        let confirmed = confirmed_outpoints_map(tx_id, 0, amount as u64);

        let (entry, credit) = process_single_transaction(pending, &scripthash, &confirmed);
        assert!(credit.is_none());
        assert_eq!(entry.double_spend, Some(true));
        let conflict = entry.conflict().expect("conflict expected");
        assert!(matches!(
            conflict,
            HistoryConflictReason::VerificationMismatch { .. }
        ));
        if let HistoryConflictReason::VerificationMismatch { detail } = conflict {
            assert!(detail.contains("decode mempool public input digest"));
        }
        assert!(entry.digest().is_none());
    }

    #[cfg(feature = "backend-rpp-stark")]
    #[test]
    fn process_mempool_reports_conflict_when_digest_missing() {
        let amount = 18u128;
        let scripthash_script = Script::new(encode_ledger_script(&LedgerScriptPayload::Recipient {
            to: "recipient".to_string(),
            amount,
        }));
        let scripthash = ScriptHash::new(&scripthash_script);
        let tx_id = [0x33; 32];
        let witness = sample_transaction_witness(tx_id, 0, "recipient", amount, 3);
        let mut pending = sample_pending_transaction(
            &scripthash,
            tx_id,
            witness,
            Digest32::from([0u8; 32]),
            amount,
            None,
        );
        pending.public_inputs_digest = None;
        let confirmed = HashMap::new();

        let (entry, credit) = process_single_transaction(pending, &scripthash, &confirmed);
        assert!(credit.is_none());
        assert_eq!(entry.double_spend, Some(true));
        let conflict = entry.conflict().expect("conflict expected");
        assert!(matches!(conflict, HistoryConflictReason::MissingData { .. }));
        if let HistoryConflictReason::MissingData { detail } = conflict {
            assert_eq!(detail, "public inputs digest missing");
        }
        assert!(entry.digest().is_none());
    }
}
