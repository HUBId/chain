//! STWO adapter that converts wallet drafts into circuit witnesses.

use std::time::{SystemTime, UNIX_EPOCH};

use crate::engine::{DraftOutput, DraftTransaction, SpendModel};
use crate::proofs::validate_transaction_witness;
use metrics::counter;
use prover_backend_interface::{Blake2sHasher, ProofSystemKind, WitnessBytes, WitnessHeader};
use prover_stwo_backend::backend::io::decode_tx_witness;
use prover_stwo_backend::official::circuit::transaction::TransactionWitness;
use prover_stwo_backend::reputation::{ReputationProfile, ReputationWeights, Tier};
use prover_stwo_backend::types::{Account, SignedTransaction, Stake, Transaction};
use zeroize::Zeroize;

use super::prover::ProverJobManager;
use super::{ProverError, WitnessPlan};

/// Helper translating wallet drafts into STWO witnesses.
pub struct StwoWitnessAdapter {
    witness_cap: u64,
}

impl StwoWitnessAdapter {
    pub fn new(witness_cap: u64) -> Self {
        Self { witness_cap }
    }

    pub fn prepare_witness(
        &self,
        manager: &ProverJobManager,
        draft: &DraftTransaction,
    ) -> Result<WitnessPlan, ProverError> {
        let (witness_bytes, witness_len) = build_stwo_witness(draft)?;
        manager.ensure_witness_capacity("stwo", witness_len, Some(self.witness_cap))?;
        counter!("wallet.prover.stwo.witness.prepared").increment(1);
        Ok(WitnessPlan::with_parts(
            witness_bytes,
            std::time::Instant::now(),
        ))
    }
}

fn build_stwo_witness(draft: &DraftTransaction) -> Result<(WitnessBytes, usize), ProverError> {
    use std::convert::TryInto;

    let signed_tx = build_signed_transaction(draft)?;
    let sender_address = signed_tx.payload.from.clone();
    let recipient_address = signed_tx.payload.to.clone();

    let mut sender_account = Account::new(
        sender_address.clone(),
        draft.total_input_value(),
        Stake::default(),
    );
    sender_account.nonce = signed_tx.payload.nonce.checked_sub(1).unwrap_or_default();
    sender_account.reputation = ReputationProfile::new(&signed_tx.public_key);
    sender_account.reputation.zsi.validated = true;
    sender_account
        .reputation
        .recompute_score(&ReputationWeights::default(), signed_tx.payload.timestamp);
    sender_account
        .reputation
        .update_decay_reference(signed_tx.payload.timestamp);

    let receiver_account = DraftOutput::primary(draft)
        .map(|output| Account::new(recipient_address.clone(), output.value, Stake::default()))
        .map(|mut account| {
            account.reputation = ReputationProfile::new(&signed_tx.public_key);
            account.reputation.wallet_commitment = Some(recipient_address.clone());
            account.reputation.zsi.validated = true;
            account
                .reputation
                .recompute_score(&ReputationWeights::default(), signed_tx.payload.timestamp);
            account
                .reputation
                .update_decay_reference(signed_tx.payload.timestamp);
            account
        });

    let witness = TransactionWitness {
        signed_tx,
        sender_account,
        receiver_account,
        required_tier: Tier::Tl1,
        reputation_weights: ReputationWeights::default(),
    };
    validate_transaction_witness(&witness)
        .map_err(|err| ProverError::Serialization(err.to_string()))?;

    let header = WitnessHeader::new(ProofSystemKind::Stwo, "tx");
    let witness_bytes = WitnessBytes::encode(&header, &witness)?;
    let len = witness_bytes.as_slice().len();

    // Ensure we can decode the witness we emit without exposing raw payloads in logs.
    let _ = decode_tx_witness(&witness_bytes).map_err(ProverError::from)?;

    Ok((witness_bytes, len))
}

fn build_signed_transaction(draft: &DraftTransaction) -> Result<SignedTransaction, ProverError> {
    use ed25519_dalek::SigningKey;

    let mut encoded =
        bincode::serialize(draft).map_err(|err| ProverError::Serialization(err.to_string()))?;
    let mut entropy: [u8; 32] = Blake2sHasher::hash(&encoded).into();
    encoded.zeroize();
    debug_assert_zeroized(&encoded);

    let signing_key = SigningKey::from_bytes(&entropy);
    let verifying_key = signing_key.verifying_key();
    let sender_address = wallet_address_from_public_key(&verifying_key);
    let (recipient_address, amount) = select_recipient(draft);
    let nonce_seed: [u8; 8] = entropy[0..8].try_into().expect("slice length 8");
    let nonce = u64::from_le_bytes(nonce_seed).max(1);
    let timestamp_seed: [u8; 8] = entropy[8..16].try_into().expect("slice length 8");
    let timestamp = derive_timestamp(timestamp_seed);
    let fee = u64::try_from(draft.fee)
        .map_err(|_| ProverError::Serialization("draft fee exceeds u64".into()))?;

    let payload = Transaction {
        from: sender_address.clone(),
        to: recipient_address,
        amount,
        fee,
        nonce,
        memo: None,
        timestamp,
    };
    let signature = signing_key.sign(&payload.canonical_bytes());
    entropy.zeroize();
    debug_assert_zeroized(&entropy);
    Ok(SignedTransaction::new(payload, signature, &verifying_key))
}

fn select_recipient(draft: &DraftTransaction) -> (String, u128) {
    let recipients: Vec<_> = draft
        .outputs
        .iter()
        .filter(|output| !output.change)
        .collect();
    let address = recipients
        .first()
        .or_else(|| draft.outputs.first())
        .map(|output| output.address.clone())
        .unwrap_or_else(|| "wallet.recipient".to_string());
    let amount = recipients
        .iter()
        .map(|output| output.value)
        .max()
        .or_else(|| draft.spend_model.amount())
        .unwrap_or_default();
    (address, amount)
}

fn derive_timestamp(seed: [u8; 8]) -> u64 {
    let candidate = u64::from_le_bytes(seed);
    if candidate == 0 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    } else {
        1_700_000_000u64.saturating_add(candidate % 1_000_000)
    }
}

fn wallet_address_from_public_key(key: &ed25519_dalek::VerifyingKey) -> String {
    let hash: [u8; 32] = Blake2sHasher::hash(key.as_bytes()).into();
    hex::encode(hash)
}

fn debug_assert_zeroized(buf: &[u8]) {
    debug_assert!(
        buf.iter().all(|byte| *byte == 0),
        "sensitive prover buffer should be zeroized",
    );
}

impl DraftOutput {
    fn primary(draft: &DraftTransaction) -> Option<&DraftOutput> {
        draft
            .outputs
            .iter()
            .find(|output| !output.change)
            .or_else(|| draft.outputs.first())
    }
}

impl From<prover_stwo_backend::BackendError> for ProverError {
    fn from(err: prover_stwo_backend::BackendError) -> Self {
        ProverError::Backend(err.into())
    }
}
