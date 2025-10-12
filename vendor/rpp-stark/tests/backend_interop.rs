#![cfg(feature = "backend-rpp-stark")]

use std::convert::TryInto;
use std::fs;
use std::path::Path;

use rpp_stark::backend::{
    ensure_proof_size_consistency, node_limit_to_params_kb, params_limit_to_node_bytes,
    ChainDigest, ChainFelt, ChainHasher, Digest, Felt, Hasher, ProofSizeMappingError,
};
use rpp_stark::field::prime_field::FieldElement;
use rpp_stark::params::StarkParamsBuilder;
use serde::Deserialize;

#[derive(Debug)]
struct HashVectorFixture {
    leaves: Vec<Vec<u8>>,
    root: [u8; Digest::LENGTH],
}

#[derive(Deserialize)]
struct HashVectorFixtureRaw {
    leaves: Vec<String>,
    root: String,
}

fn decode_hex(input: &str) -> Result<Vec<u8>, String> {
    if input.len() % 2 != 0 {
        return Err(format!("hex payload has odd length: {}", input.len()));
    }
    let mut out = Vec::with_capacity(input.len() / 2);
    let bytes = input.as_bytes();
    for chunk in bytes.chunks(2) {
        let high = (chunk[0] as char)
            .to_digit(16)
            .ok_or_else(|| format!("invalid hex char '{}' in {}", chunk[0] as char, input))?;
        let low = (chunk[1] as char)
            .to_digit(16)
            .ok_or_else(|| format!("invalid hex char '{}' in {}", chunk[1] as char, input))?;
        out.push(((high << 4) | low) as u8);
    }
    Ok(out)
}

fn load_fixture(base: &Path) -> Result<HashVectorFixture, String> {
    let json_path = base.join("hash_vectors.json");
    let bin_path = base.join("hash_vectors.bin");

    let json_data = fs::read_to_string(&json_path)
        .map_err(|err| format!("failed to read {json_path:?}: {err}"))?;
    let fixture: HashVectorFixtureRaw = serde_json::from_str(&json_data)
        .map_err(|err| format!("failed to decode fixture JSON: {err}"))?;

    let leaves = fixture
        .leaves
        .iter()
        .map(|entry| decode_hex(entry))
        .collect::<Result<Vec<_>, _>>()?;

    let root_bytes = decode_hex(&fixture.root)?;
    if root_bytes.len() != Digest::LENGTH {
        return Err(format!(
            "expected {}-byte root, got {}",
            Digest::LENGTH,
            root_bytes.len()
        ));
    }
    let root: [u8; Digest::LENGTH] = root_bytes
        .as_slice()
        .try_into()
        .expect("length checked above");

    if let Ok(bin_root) = fs::read(&bin_path) {
        if bin_root.len() == Digest::LENGTH && bin_root.as_slice() != root {
            return Err("binary and JSON root mismatch".to_string());
        }
    }

    Ok(HashVectorFixture { leaves, root })
}

#[test]
fn felt_roundtrip_matches_field_encoding() {
    let element = FieldElement(123_456_789);
    let felt = Felt::from_field(element).expect("canonical element must wrap");
    let bytes = felt.to_chain_bytes().expect("canonical element serialises");
    let roundtrip = Felt::from_chain_bytes(&bytes).expect("bytes must decode");
    assert_eq!(roundtrip.as_field(), &element);
}

#[test]
fn chain_hasher_matches_stwo_fixture() {
    let fixture = load_fixture(Path::new("tests/fixtures/stwo")).expect("fixture must load");
    let mut flattened = Vec::new();
    for leaf in &fixture.leaves {
        flattened.extend_from_slice(leaf);
    }

    assert_eq!(
        Hasher::domain_tag(),
        rpp_stark::hash::config::BLAKE2S_COMMITMENT_DOMAIN_TAG
    );

    let mut hasher = Hasher::new();
    for leaf in &fixture.leaves {
        ChainHasher::update(&mut hasher, leaf);
    }
    let digest = ChainHasher::finalize(hasher);
    assert_eq!(digest.as_chain_bytes(), &fixture.root);
    assert_eq!(digest.as_chain_bytes().len(), Digest::LENGTH);

    // Direct hashing of the flattened payload should match the streamed digest.
    let mut direct = Hasher::new();
    ChainHasher::update(&mut direct, &flattened);
    let direct_digest = ChainHasher::finalize(direct);
    assert_eq!(direct_digest.into_chain_bytes(), fixture.root);

    // Applying the domain tag explicitly matches the convenience constructor.
    let mut tagged = Hasher::new();
    ChainHasher::absorb_domain_tag(&mut tagged);
    ChainHasher::update(&mut tagged, &flattened);
    let tagged_digest = ChainHasher::finalize(tagged);

    let mut ctor_tagged = Hasher::new_with_domain_tag();
    ChainHasher::update(&mut ctor_tagged, &flattened);
    let ctor_digest = ChainHasher::finalize(ctor_tagged);
    assert_eq!(tagged_digest.as_chain_bytes(), ctor_digest.as_chain_bytes());
}

#[test]
fn proof_size_mapping_roundtrip() {
    let node_limit_bytes = 1_500_000u32;
    let expected_kb = node_limit_to_params_kb(node_limit_bytes);

    let mut builder = StarkParamsBuilder::new();
    builder.proof.max_size_kb = expected_kb;
    let params = builder.build().expect("builder must yield params");

    ensure_proof_size_consistency(&params, node_limit_bytes)
        .expect("mapping should consider rounding semantics");

    let params_bytes = params_limit_to_node_bytes(&params).expect("bytes should fit");
    assert!(params_bytes >= node_limit_bytes);
    assert!(params_bytes - node_limit_bytes < 1024);
}

#[test]
fn proof_size_mapping_detects_mismatch() {
    let node_limit_bytes = 1_500_000u32;
    let mut builder = StarkParamsBuilder::new();
    builder.proof.max_size_kb = node_limit_to_params_kb(node_limit_bytes) - 1;
    let params = builder.build().expect("builder must yield params");

    let err = ensure_proof_size_consistency(&params, node_limit_bytes)
        .expect_err("mismatch should be detected");
    assert_eq!(
        err,
        ProofSizeMappingError::Mismatch {
            params_kb: params.proof().max_size_kb,
            expected_kb: node_limit_to_params_kb(node_limit_bytes),
        }
    );
}

#[test]
fn proof_size_mapping_overflow_is_reported() {
    let mut builder = StarkParamsBuilder::new();
    builder.proof.max_size_kb = u32::MAX;
    let params = builder.build().expect("builder must yield params");

    let err = params_limit_to_node_bytes(&params).expect_err("overflow must be flagged");
    assert_eq!(
        err,
        ProofSizeMappingError::Overflow {
            max_size_kb: u32::MAX
        }
    );
}
