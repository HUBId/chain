#![cfg(feature = "prover-stwo")]

use prover_stwo_backend::official::aggregation::{RecursiveAggregator, StateCommitmentSnapshot};
use prover_stwo_backend::official::circuit::recursive::{PrefixedDigest, RecursiveCircuit};
use prover_stwo_backend::official::params::{FieldElement, StarkParameters};
use rpp_pruning::{TaggedDigest, DIGEST_LENGTH, ENVELOPE_TAG, PROOF_SEGMENT_TAG};

fn sample_prefixed_digest(tag: &[u8; 4], value: u8) -> PrefixedDigest {
    TaggedDigest::new(*tag, [value; DIGEST_LENGTH]).prefixed_bytes()
}

#[test]
fn recursive_commitment_matches_expected_digest() {
    let aggregator = RecursiveAggregator::with_blueprint();
    let binding = sample_prefixed_digest(ENVELOPE_TAG, 0x11);
    let segments = vec![
        sample_prefixed_digest(PROOF_SEGMENT_TAG, 0x22),
        sample_prefixed_digest(PROOF_SEGMENT_TAG, 0x23),
    ];
    let state_roots = StateCommitmentSnapshot::from_header_fields(
        "aa".repeat(32),
        "bb".repeat(32),
        "cc".repeat(32),
        "dd".repeat(32),
        "ee".repeat(32),
        "ff".repeat(32),
    );
    let commitment = aggregator.aggregate_commitment(
        None,
        &["10".repeat(32)],
        &["20".repeat(32), "21".repeat(32)],
        &["30".repeat(32)],
        &["40".repeat(32)],
        "50".repeat(32).as_str(),
        &state_roots,
        &binding,
        &segments,
        42,
    );

    let parameters = StarkParameters::blueprint_default();
    let hasher = parameters.poseidon_hasher();
    let zero = FieldElement::zero(parameters.modulus());

    let mut activity = zero.clone();
    for item in ["10".repeat(32)]
        .into_iter()
        .chain(["20".repeat(32), "21".repeat(32)])
        .chain(["30".repeat(32)])
        .chain(["40".repeat(32)])
    {
        let element = string_to_field(&parameters, &item);
        activity = hasher.hash(&[activity.clone(), element, zero.clone()]);
    }

    let pruning_fold = RecursiveCircuit::fold_pruning_digests(&hasher, &parameters, &binding, &segments)
        .expect("fold pruning digests");

    let state_digest = hasher.hash(&[
        string_to_field(&parameters, "50".repeat(32).as_str()),
        string_to_field(&parameters, &state_roots.global_state_root),
        string_to_field(&parameters, &state_roots.utxo_root),
        string_to_field(&parameters, &state_roots.reputation_root),
        string_to_field(&parameters, &state_roots.timetoke_root),
        string_to_field(&parameters, &state_roots.zsi_root),
        string_to_field(&parameters, &state_roots.proof_root),
        parameters.element_from_u64(42),
    ]);

    let manual = hasher.hash(&[zero, state_digest, pruning_fold, activity]);
    assert_eq!(commitment.to_hex(), manual.to_hex());
}

#[test]
fn pruning_fold_respects_segment_order() {
    let parameters = StarkParameters::blueprint_default();
    let aggregator = RecursiveAggregator::with_blueprint();
    let mut segments = vec![
        sample_prefixed_digest(PROOF_SEGMENT_TAG, 0x31),
        sample_prefixed_digest(PROOF_SEGMENT_TAG, 0x32),
    ];
    segments.swap(0, 1);
    let binding = sample_prefixed_digest(ENVELOPE_TAG, 0x44);
    let snapshot = StateCommitmentSnapshot::from_header_fields(
        "01".repeat(32),
        "02".repeat(32),
        "03".repeat(32),
        "04".repeat(32),
        "05".repeat(32),
        "06".repeat(32),
    );

    let ordered = aggregator.aggregate_commitment(
        None,
        &[],
        &[],
        &[],
        &[],
        "07".repeat(32).as_str(),
        &snapshot,
        &binding,
        &segments,
        7,
    );

    let mut sorted_segments = segments.clone();
    sorted_segments.sort();
    let reordered = aggregator.aggregate_commitment(
        None,
        &[],
        &[],
        &[],
        &[],
        "07".repeat(32).as_str(),
        &snapshot,
        &binding,
        &sorted_segments,
        7,
    );

    assert_eq!(
        ordered.to_hex(),
        reordered.to_hex(),
        "reordering commitments should not change the folded digest",
    );
    assert_eq!(ordered.modulus(), parameters.modulus());
}

fn string_to_field(parameters: &StarkParameters, value: &str) -> FieldElement {
    let bytes = hex::decode(value).unwrap_or_else(|_| value.as_bytes().to_vec());
    parameters.element_from_bytes(&bytes)
}
