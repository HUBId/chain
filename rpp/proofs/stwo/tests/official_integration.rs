#![cfg(feature = "backend-stwo")]

#[allow(unused_imports)]
use super::*;

use crate::crypto::address_from_public_key;
use crate::proof_system::{ProofProver, ProofVerifier};
use crate::reputation::Tier;
use crate::storage::Storage;
#[allow(unused_imports)]
use crate::stwo::air::{AirDefinition, AirExpression, ConstraintDomain};
#[allow(unused_imports)]
use crate::stwo::circuit::ExecutionTrace;
#[allow(unused_imports)]
use crate::stwo::fri::FriProver;
#[allow(unused_imports)]
use crate::stwo::official_adapter::{BlueprintComponent, Component, ComponentProver};
#[allow(unused_imports)]
use crate::stwo::params::{FieldElement, StarkParameters};
use crate::stwo::proof::StarkProof;
use crate::stwo::prover::WalletProver;
use crate::stwo::verifier::NodeVerifier;
use crate::types::{Account, ChainProof, SignedTransaction, Stake, Transaction};
use ed25519_dalek::{Keypair, Signer};
use once_cell::sync::Lazy;
use rand::{SeedableRng, rngs::StdRng};
use std::fs;
use std::path::PathBuf;
use tempfile::tempdir;

#[derive(Clone)]
pub(super) struct RecordedTransaction {
    pub signed_transaction: SignedTransaction,
    pub proof: ChainProof,
}

pub(super) static RECORDED_TRANSACTION: Lazy<RecordedTransaction> = Lazy::new(|| {
    let tx = sample_transaction();
    let temp_dir = tempdir().expect("temporary directory");
    let storage = Storage::open(temp_dir.path()).expect("open storage");
    let (sender_account, _) = populate_wallet_state(&storage, &tx);

    assert!(
        tx.payload.timestamp >= sender_account.reputation.last_decay_timestamp,
        "transaction timestamp must respect sender decay window",
    );
    assert_eq!(
        tx.payload.nonce,
        sender_account.nonce + 1,
        "transaction nonce must advance sender state",
    );

    let prover = WalletProver::new(&storage)
        .with_parameters(StarkParameters::blueprint_default())
        .with_minimum_tier(Tier::Tl1);

    let witness = prover
        .derive_transaction_witness(&tx)
        .expect("derive transaction witness");
    let proof = prover
        .prove_transaction(witness)
        .expect("prove transaction");

    assert!(matches!(proof, ChainProof::Stwo(_)), "expected STWO proof");

    RecordedTransaction {
        signed_transaction: tx,
        proof,
    }
});

pub(super) fn recorded_transaction_proof() -> RecordedTransaction {
    RECORDED_TRANSACTION.clone()
}

fn sample_transaction() -> SignedTransaction {
    let mut rng = StdRng::from_seed([0x42; 32]);
    let keypair = Keypair::generate(&mut rng);
    let sender = address_from_public_key(&keypair.public);
    let receiver = hex::encode([0x11u8; 32]);
    let payload = Transaction {
        from: sender,
        to: receiver,
        amount: 75,
        fee: 5,
        nonce: 3,
        memo: Some("official integration".into()),
        timestamp: 1_717_171_717,
    };
    let signature = keypair.sign(&payload.canonical_bytes());
    SignedTransaction::new(payload, signature, &keypair.public)
}

fn populate_wallet_state(storage: &Storage, tx: &SignedTransaction) -> (Account, Account) {
    let sender_balance = tx
        .payload
        .amount
        .saturating_add(tx.payload.fee as u128)
        .saturating_add(1_000);
    let mut sender_account =
        Account::new(tx.payload.from.clone(), sender_balance, Stake::default());
    sender_account.nonce = tx.payload.nonce - 1;
    sender_account.reputation.tier = Tier::Tl3;
    sender_account.reputation.last_decay_timestamp = tx.payload.timestamp;
    sender_account.reputation.zsi.validated = true;
    sender_account.reputation.timetokes.last_decay_timestamp = tx.payload.timestamp;

    let mut receiver_account = Account::new(tx.payload.to.clone(), 500, Stake::default());
    receiver_account.reputation.tier = Tier::Tl1;
    receiver_account.reputation.last_decay_timestamp = tx.payload.timestamp;
    receiver_account.reputation.zsi.validated = true;
    receiver_account.reputation.timetokes.last_decay_timestamp = tx.payload.timestamp;

    storage
        .persist_account(&sender_account)
        .expect("persist sender account");
    storage
        .persist_account(&receiver_account)
        .expect("persist receiver account");

    let mut expected = vec![sender_account.clone(), receiver_account.clone()];
    expected.sort_by(|a, b| a.address.cmp(&b.address));

    let loaded = storage.load_accounts().expect("load accounts");
    assert_eq!(
        serde_json::to_value(&loaded).expect("serialize loaded accounts"),
        serde_json::to_value(&expected).expect("serialize expected accounts"),
        "persisted accounts should round-trip deterministically",
    );

    (sender_account, receiver_account)
}

#[test]
fn wallet_state_round_trip_is_deterministic() {
    let fixture = recorded_transaction_proof();
    let temp_dir = tempdir().expect("temporary directory");
    let storage = Storage::open(temp_dir.path()).expect("open storage");
    let _ = populate_wallet_state(&storage, &fixture.signed_transaction);
}

#[test]
fn recorded_transaction_proof_generation_succeeds() {
    let fixture = recorded_transaction_proof();
    let verifier = NodeVerifier::new();
    verifier
        .verify_transaction(&fixture.proof)
        .expect("transaction proof should verify");

    match &fixture.proof {
        ChainProof::Stwo(proof) => dump_valid_proof_fixture(proof),
        _ => panic!("expected STWO proof"),
    }
}

fn dump_valid_proof_fixture(proof: &StarkProof) {
    const ENV_FLAG: &str = "STWO_DUMP_VALID_PROOF";
    if std::env::var_os(ENV_FLAG).is_none() {
        return;
    }

    let mut output_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    output_path.push("rpp/proofs/stwo/tests/vectors/valid_proof.json");

    if let Some(parent) = output_path.parent() {
        fs::create_dir_all(parent).expect("create proof fixture directory");
    }

    let serialized = serde_json::to_string_pretty(proof).expect("serialize STWO proof fixture");
    fs::write(&output_path, serialized).expect("write STWO proof fixture");
}
