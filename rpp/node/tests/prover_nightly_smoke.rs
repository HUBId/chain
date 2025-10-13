#![cfg(feature = "prover-stwo")]

rustversion::not_nightly! {
    compile_error!(
        "STWO Prover requires Rust nightly (portable_simd / array_chunks etc.). Build without these features or use Nightly."
    );
}

use bincode;
use ed25519_dalek::{Keypair, Signer};
use rand::{rngs::StdRng, SeedableRng};
use rpp_chain::crypto::address_from_public_key;
use rpp_chain::reputation::Tier;
use rpp_chain::storage::Storage;
use rpp_chain::types::{Account, ChainProof, SignedTransaction, Stake, Transaction};
use tempfile::tempdir;

use crate::validation::dispatch_transaction_validation;

fn sample_transaction() -> SignedTransaction {
    let mut rng = StdRng::from_seed([0xAB; 32]);
    let keypair = Keypair::generate(&mut rng);
    let sender = address_from_public_key(&keypair.public);
    let receiver = hex::encode([0xCD; 32]);
    let payload = Transaction {
        from: sender,
        to: receiver,
        amount: 42,
        fee: 3,
        nonce: 7,
        memo: Some("nightly-smoke".into()),
        timestamp: 1_717_171_717,
    };
    let signature = keypair.sign(&payload.canonical_bytes());
    SignedTransaction::new(payload, signature, &keypair.public)
}

fn populate_storage(storage: &Storage, tx: &SignedTransaction) {
    let mut sender_account = Account::new(tx.payload.from.clone(), 10_000, Stake::default());
    sender_account.nonce = tx.payload.nonce - 1;
    sender_account.reputation.tier = Tier::Tl3;
    sender_account.reputation.last_decay_timestamp = tx.payload.timestamp;
    sender_account.reputation.zsi.validated = true;
    sender_account.reputation.timetokes.last_decay_timestamp = tx.payload.timestamp;

    let mut receiver_account = Account::new(tx.payload.to.clone(), 512, Stake::default());
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
}

rustversion::nightly! {
    #[test]
    fn prove_and_verify_ok() {
        let tx = sample_transaction();
        let temp = tempdir().expect("temporary directory");
        let storage = Storage::open(temp.path()).expect("open storage");
        populate_storage(&storage, &tx);

        let proof = dispatch_transaction_validation(&storage, &tx, None)
            .expect("dispatch should succeed")
            .expect("stwo proof present");

        let stwo_proof = proof.expect_stwo().expect("extract stwo proof");
        let serialized = bincode::serialize(stwo_proof).expect("serialize stwo proof");
        assert!(serialized.len() > 1024, "proof serialization should be non-empty");
    }

    #[test]
    fn prove_repeatable() {
        let tx = sample_transaction();
        let temp = tempdir().expect("temporary directory");
        let storage = Storage::open(temp.path()).expect("open storage");
        populate_storage(&storage, &tx);

        let first = dispatch_transaction_validation(&storage, &tx, None)
            .expect("first dispatch");
        let second = dispatch_transaction_validation(&storage, &tx, None)
            .expect("second dispatch");

        let first_bytes = serialized_proof_bytes(&first.expect("first proof"));
        let second_bytes = serialized_proof_bytes(&second.expect("second proof"));
        assert_eq!(first_bytes, second_bytes, "proof generation must be deterministic");
    }
}

fn serialized_proof_bytes(proof: &ChainProof) -> Vec<u8> {
    let stwo = proof.expect_stwo().expect("extract stwo proof");
    bincode::serialize(stwo).expect("serialize stwo proof")
}
