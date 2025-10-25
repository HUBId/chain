use super::*;
use crate::errors::ChainError;
use proptest::prelude::*;
use proptest::string::string_regex;

fn proptest_config() -> ProptestConfig {
    let cases = std::env::var("PROPTEST_CASES")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(32);
    ProptestConfig {
        cases,
        ..ProptestConfig::default()
    }
}

prop_compose! {
    fn arb_hex_digest()(bytes in prop::array::uniform32(any::<u8>())) -> String {
        hex::encode(bytes)
    }
}

prop_compose! {
    fn arb_decimal_string()(value in 0u128..1_000_000_000_000u128) -> String {
        value.to_string()
    }
}

prop_compose! {
    fn arb_pruning_fixture()(height in 0u64..1_000,
                             prev_hash in arb_hex_digest(),
                             prev_state in arb_hex_digest(),
                             pruned_tx in arb_hex_digest(),
                             resulting in arb_hex_digest(),
                             tx_root in arb_hex_digest(),
                             utxo_root in arb_hex_digest(),
                             reputation_root in arb_hex_digest(),
                             timetoke_root in arb_hex_digest(),
                             zsi_root in arb_hex_digest(),
                             proof_root in arb_hex_digest(),
                             total_stake in arb_decimal_string(),
                             randomness in arb_decimal_string(),
                             vrf_public_key in arb_hex_digest(),
                             vrf_preoutput in arb_hex_digest(),
                             vrf_proof in string_regex("[0-9a-f]{128}").unwrap(),
                             proposer in string_regex("0x[0-9a-f]{40}").unwrap(),
                             leader_tier in string_regex("TL[1-5]").unwrap(),
                             leader_timetoke in any::<u64>(),
                             timestamp in any::<u64>())
        -> (PruningProof, BlockHeader)
    {
        let proof = PruningProof::new(
            height,
            prev_hash.clone(),
            prev_state.clone(),
            pruned_tx.clone(),
            resulting.clone(),
        );
        let header = BlockHeader {
            height: height + 1,
            previous_hash: prev_hash,
            tx_root,
            state_root: resulting,
            utxo_root,
            reputation_root,
            timetoke_root,
            zsi_root,
            proof_root,
            total_stake,
            randomness,
            vrf_public_key,
            vrf_preoutput,
            vrf_proof,
            timestamp,
            proposer,
            leader_tier,
            leader_timetoke,
        };
        (proof, header)
    }
}

proptest! {
    #![proptest_config(proptest_config())]
    fn pruning_proof_roundtrip((proof, header) in arb_pruning_fixture()) {
        let json = serde_json::to_string(&proof).expect("serialize pruning proof");
        let decoded: PruningProof = serde_json::from_str(&json).expect("deserialize pruning proof");
        assert_eq!(decoded, proof);
        decoded.verify(None, &header).expect("valid pruning proof must verify");
    }
}

proptest! {
    #![proptest_config(proptest_config())]
    fn pruning_proof_detects_previous_hash_mismatch((mut proof, header) in arb_pruning_fixture()) {
        proof.previous_block_hash.push('0');
        match proof.verify(None, &header) {
            Err(ChainError::Crypto(message)) => {
                assert!(message.contains("previous hash"));
            }
            other => panic!("unexpected verification result: {other:?}"),
        }
    }
}

proptest! {
    #![proptest_config(proptest_config())]
    fn parse_natural_accepts_decimals(value in arb_decimal_string()) {
        let parsed = parse_natural(&value).expect("decimal strings must parse");
        assert_eq!(parsed.to_string(), value);
    }
}

proptest! {
    #![proptest_config(proptest_config())]
    fn parse_natural_rejects_invalid(text in string_regex("[a-f]{1,8}").unwrap()) {
        match parse_natural(&text) {
            Err(ChainError::Crypto(message)) => {
                assert!(message.contains("invalid natural encoding"));
            }
            other => panic!("unexpected parse result: {other:?}"),
        }
    }
}
