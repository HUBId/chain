use super::*;
use crate::crypto::address_from_public_key;
use crate::errors::ChainError;
use ed25519_dalek::{PublicKey, Signer, SigningKey};
use proptest::prelude::*;
use proptest::string::string_regex;

fn proptest_config() -> ProptestConfig {
    let cases = std::env::var("PROPTEST_CASES")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(64);
    ProptestConfig {
        cases,
        ..ProptestConfig::default()
    }
}

fn signing_key_from_seed(seed: [u8; 32]) -> SigningKey {
    SigningKey::from_bytes(&seed)
}

prop_compose! {
    fn arb_memo()(memo in string_regex("[ -~]{0,64}").unwrap()) -> Option<String> {
        if memo.is_empty() { None } else { Some(memo) }
    }
}

prop_compose! {
    fn arb_transaction()(seed in prop::array::uniform32(any::<u8>()),
                         to in string_regex("0x[0-9a-f]{8,64}").unwrap(),
                         amount in 0u128..1_000_000_000_000u128,
                         fee in 0u64..1_000_000u64,
                         nonce in any::<u64>(),
                         memo in arb_memo(),
                         timestamp in any::<u64>())
        -> (SigningKey, Transaction)
    {
        let signing = signing_key_from_seed(seed);
        let public = PublicKey::from(&signing);
        let from = address_from_public_key(&public);
        let payload = Transaction {
            from,
            to,
            amount,
            fee,
            nonce,
            memo,
            timestamp,
        };
        (signing, payload)
    }
}

proptest! {
    #![proptest_config(proptest_config())]
    fn signed_transaction_roundtrip((signing, payload) in arb_transaction()) {
        let public = PublicKey::from(&signing);
        let signature = signing.sign(&payload.canonical_bytes());
        let signed = SignedTransaction::new(payload.clone(), signature, &public);

        signed.verify().expect("valid signature must verify");

        let payload_json = serde_json::to_string(&payload).expect("serialize payload");
        let decoded: Transaction = serde_json::from_str(&payload_json).expect("deserialize payload");
        assert_eq!(decoded, payload);

        let signed_json = serde_json::to_string(&signed).expect("serialize signed transaction");
        let decoded_signed: SignedTransaction = serde_json::from_str(&signed_json).expect("deserialize signed");
        assert_eq!(decoded_signed, signed);

        let envelope = TransactionEnvelope::new(signed.clone());
        assert_eq!(envelope.hash, hex::encode(payload.hash()));
    }
}

proptest! {
    #![proptest_config(proptest_config())]
    fn signed_transaction_reports_public_key_errors((signing, payload) in arb_transaction()) {
        let public = PublicKey::from(&signing);
        let signature = signing.sign(&payload.canonical_bytes());
        let mut signed = SignedTransaction::new(payload.clone(), signature, &public);
        signed.public_key = "zz".repeat(32);

        match signed.verify() {
            Err(ChainError::Transaction(message)) => {
                assert!(message.contains("invalid public key"));
            }
            other => panic!("unexpected verification result: {other:?}"),
        }
    }
}
