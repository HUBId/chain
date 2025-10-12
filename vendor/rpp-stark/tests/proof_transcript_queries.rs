#[path = "fail_matrix/fixture.rs"]
mod fail_matrix_fixture;

use fail_matrix_fixture::FailMatrixFixture;
use rpp_stark::config::ProofKind;
use rpp_stark::field::FieldElement;
use rpp_stark::hash::blake3::FiatShamirChallengeRules;
use rpp_stark::hash::deterministic::{Blake2sXof, Hash, Hasher};
use rpp_stark::proof::params::canonical_stark_params;
use rpp_stark::proof::ser::serialize_public_inputs;
use rpp_stark::proof::transcript::{Transcript, TranscriptBlockContext, TranscriptHeader};
use rpp_stark::proof::types::{PROOF_ALPHA_VECTOR_LEN, PROOF_MIN_OOD_POINTS};

#[test]
fn queries_local_generation_matches_openings() {
    let fixture = FailMatrixFixture::new();
    let proof = fixture.proof();
    let context = fixture.verifier_context();
    let public_inputs = fixture.public_inputs();

    // Ensure we're working with the expected proof kind.
    let proof_kind = *proof.kind();
    assert_eq!(proof_kind, ProofKind::Tx, "fixture kind");

    let air_spec_id = context.profile.air_spec_ids.get(proof_kind).clone();

    let mut transcript = Transcript::new(TranscriptHeader {
        version: context.common_ids.transcript_version_id.clone(),
        poseidon_param_id: context.profile.poseidon_param_id.clone(),
        air_spec_id: air_spec_id.clone(),
        proof_kind,
        params_hash: context.param_digest.clone(),
    })
    .expect("transcript header");

    let public_inputs_bytes =
        serialize_public_inputs(&public_inputs).expect("serialize public inputs");
    transcript
        .absorb_public_inputs(&public_inputs_bytes)
        .expect("absorb public inputs");

    let trace_commit = proof.trace_commit().bytes;
    let composition_commit = proof.composition_commit().map(|commit| commit.bytes);
    transcript
        .absorb_commitment_roots(trace_commit, composition_commit)
        .expect("absorb commitments");
    transcript
        .absorb_air_spec_id(air_spec_id)
        .expect("absorb air spec");
    transcript
        .absorb_block_context(None::<TranscriptBlockContext>)
        .expect("absorb block context");

    let mut challenges = transcript.finalize().expect("finalize transcript");
    let _alpha = challenges
        .draw_alpha_vector(PROOF_ALPHA_VECTOR_LEN)
        .expect("alpha vector");
    let _ood_points = challenges
        .draw_ood_points(PROOF_MIN_OOD_POINTS)
        .expect("ood points");
    let _ood_seed = challenges.draw_ood_seed().expect("ood seed");
    let fri_seed = challenges.draw_fri_seed().expect("fri seed");

    for (layer_index, _) in proof.merkle().fri_layer_roots().iter().enumerate() {
        let _ = challenges
            .draw_fri_eta(layer_index)
            .expect("fri eta challenge");
    }

    let _ = challenges.draw_query_seed().expect("query seed");

    let stark_params = canonical_stark_params(&context.profile);
    let query_count = stark_params.fri().queries as usize;
    let expected = derive_fri_query_indices(fri_seed, proof.fri_proof(), query_count);

    let openings_indices = proof.openings().trace().indices().to_vec();
    assert_eq!(
        expected, openings_indices,
        "transcript-derived indices match openings"
    );
}

fn derive_fri_query_indices(
    fri_seed: [u8; 32],
    fri_proof: &rpp_stark::fri::FriProof,
    query_count: usize,
) -> Vec<u32> {
    assert_eq!(
        fri_proof.fold_challenges.len(),
        fri_proof.layer_roots.len(),
        "fold challenge count must match layer roots"
    );

    let mut state = fri_seed;
    for (layer_index, root) in fri_proof.layer_roots.iter().enumerate() {
        state = hash_layer_state(&state, layer_index, root);
        let (challenge, new_state) = draw_fri_eta(&state, layer_index);
        state = new_state;
        let derived_eta = field_from_hash(&challenge);
        assert_eq!(
            derived_eta, fri_proof.fold_challenges[layer_index],
            "fold challenge must match transcript"
        );
    }

    state = hash_label(&state, b"RPP-FS/FINAL", &fri_proof.final_polynomial_digest);
    let query_seed = hash_label(&state, b"RPP-FS/QUERY-SEED", &[]);

    sample_query_positions(query_seed, query_count, fri_proof.initial_domain_size)
}

fn hash_layer_state(state: &[u8; 32], layer_index: usize, root: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Hasher::new();
    hasher.update(state);
    hasher.update(&(layer_index as u64).to_le_bytes());
    hasher.update(root);
    into_bytes(hasher.finalize())
}

fn draw_fri_eta(state: &[u8; 32], layer_index: usize) -> ([u8; 32], [u8; 32]) {
    let label = format!("{}ETA-{layer_index}", FiatShamirChallengeRules::SALT_PREFIX);
    let mut hasher = Hasher::new();
    hasher.update(state);
    hasher.update(label.as_bytes());
    let challenge = into_bytes(hasher.finalize());

    let mut state_hasher = Hasher::new();
    state_hasher.update(&challenge);
    let next_state = into_bytes(state_hasher.finalize());
    (challenge, next_state)
}

fn hash_label(state: &[u8; 32], label: &[u8], payload: &[u8]) -> [u8; 32] {
    let mut hasher = Hasher::new();
    hasher.update(state);
    hasher.update(label);
    hasher.update(payload);
    into_bytes(hasher.finalize())
}

fn sample_query_positions(query_seed: [u8; 32], count: usize, domain_size: usize) -> Vec<u32> {
    assert!(domain_size > 0, "domain size must be positive");
    let target = core::cmp::min(count, domain_size);
    let mut seen = vec![false; domain_size];
    let mut indices = Vec::with_capacity(target);
    let mut xof = Blake2sXof::new(&query_seed);

    while indices.len() < target {
        let word = xof.next_u64().expect("xof output");
        let position = (word % (domain_size as u64)) as usize;
        if !seen[position] {
            seen[position] = true;
            indices.push(position as u32);
        }
    }

    indices.sort_unstable();
    indices
}

fn field_from_hash(bytes: &[u8; 32]) -> FieldElement {
    let mut acc = 0u128;
    for chunk in bytes.chunks(8).take(4) {
        let mut buf = [0u8; 8];
        buf[..chunk.len()].copy_from_slice(chunk);
        let value = u64::from_le_bytes(buf);
        acc = (acc << 64) ^ value as u128;
        acc %= FieldElement::MODULUS.value as u128;
    }
    FieldElement(acc as u64)
}

fn into_bytes(hash: Hash) -> [u8; 32] {
    hash.into_bytes()
}
