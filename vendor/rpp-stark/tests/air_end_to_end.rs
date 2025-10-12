use std::convert::TryInto;

use rpp_stark::air::composition::{
    compose, CompositionCommitment, CompositionParams, ConstraintGroup,
};
use rpp_stark::air::example::{LfsrAir, LfsrPublicInputs};
use rpp_stark::air::traits::{Air, TraceBuilder};
use rpp_stark::air::types::TraceRole;
use rpp_stark::fft::lde::{LowDegreeExtender, PROFILE_X8};
use rpp_stark::field::prime_field::{CanonicalSerialize, FieldElementOps};
use rpp_stark::field::FieldElement;
use rpp_stark::fri::{fri_prove, fri_verify, FriError, FriProof};
use rpp_stark::hash::merkle::DIGEST_SIZE;
use rpp_stark::merkle::{DeterministicMerkleHasher, Digest, Leaf, MerkleCommit, MerkleTree};
use rpp_stark::params::{HashKind, StarkParams, StarkParamsBuilder};
use rpp_stark::transcript::{Transcript, TranscriptContext, TranscriptLabel};
use rpp_stark::utils::serialization::DigestBytes;

const LFSR_ALPHA: u64 = 5;
const LFSR_BETA: u64 = 7;

#[derive(Clone)]
struct LfsrFriFixture {
    params: StarkParams,
    inputs: LfsrPublicInputs,
    trace_root: Digest,
    composition_root: Digest,
    commitment: CompositionCommitment,
    proof: FriProof,
    trace_challenge: FieldElement,
}

#[test]
fn fri_pipeline_accepts_honest_lfsr_proof() {
    let fixture = build_fixture();

    let mut verifier_transcript = prepare_verifier_transcript(&fixture);
    let verifier_trace_challenge = verifier_transcript
        .challenge_field(TranscriptLabel::TraceChallengeA)
        .expect("trace challenge");
    assert_eq!(fixture.trace_challenge, verifier_trace_challenge);
    verifier_transcript
        .absorb_digest(
            TranscriptLabel::CompRoot,
            &digest_from_merkle(&fixture.composition_root),
        )
        .expect("absorb comp root");
    let comp_alpha = verifier_transcript
        .challenge_field(TranscriptLabel::CompChallengeA)
        .expect("comp alpha");
    assert_eq!(fixture.commitment.alphas[0], comp_alpha);

    fri_verify(&fixture.proof, &fixture.params, &mut verifier_transcript)
        .expect("honest proof must verify");
}

#[test]
fn fri_pipeline_rejects_alpha_tampering() {
    let fixture = build_fixture();
    let mut verifier_transcript = prepare_verifier_transcript(&fixture);
    let _ = verifier_transcript
        .challenge_field(TranscriptLabel::TraceChallengeA)
        .expect("trace challenge");
    verifier_transcript
        .absorb_digest(
            TranscriptLabel::CompRoot,
            &digest_from_merkle(&fixture.composition_root),
        )
        .expect("absorb comp root");
    let _ = verifier_transcript
        .challenge_field(TranscriptLabel::CompChallengeA)
        .expect("comp alpha");

    let mut tampered = fixture.proof.clone();
    tampered.fold_challenges[0] = tampered.fold_challenges[0].add(&FieldElement::ONE);

    let err = fri_verify(&tampered, &fixture.params, &mut verifier_transcript)
        .expect_err("tampered alpha must be rejected");
    assert!(
        matches!(err, FriError::InvalidStructure(reason) if reason == "fold challenge mismatch")
    );
}

#[test]
fn fri_pipeline_rejects_merkle_path_tampering() {
    let fixture = build_fixture();
    let mut verifier_transcript = prepare_verifier_transcript(&fixture);
    let _ = verifier_transcript
        .challenge_field(TranscriptLabel::TraceChallengeA)
        .expect("trace challenge");
    verifier_transcript
        .absorb_digest(
            TranscriptLabel::CompRoot,
            &digest_from_merkle(&fixture.composition_root),
        )
        .expect("absorb comp root");
    let _ = verifier_transcript
        .challenge_field(TranscriptLabel::CompChallengeA)
        .expect("comp alpha");

    let mut tampered = fixture.proof.clone();
    tampered.queries[0].layers[0].path[0].siblings[0] = [0u8; DIGEST_SIZE];

    let err = fri_verify(&tampered, &fixture.params, &mut verifier_transcript)
        .expect_err("tampered merkle path must be rejected");
    assert!(
        matches!(
            err,
            FriError::FoldingConstraintViolated { layer: 0 }
                | FriError::InvalidStructure(_)
                | FriError::PathInvalid { layer: 0, .. }
        ),
        "unexpected error: {err:?}"
    );
}

#[test]
fn fri_pipeline_rejects_trace_root_tampering() {
    let fixture = build_fixture();
    let mut transcript = Transcript::new(&fixture.params, TranscriptContext::StarkMain);
    transcript
        .absorb_digest(
            TranscriptLabel::PublicInputsDigest,
            &DigestBytes {
                bytes: fixture
                    .inputs
                    .digest()
                    .expect("fixture inputs must be canonical"),
            },
        )
        .expect("absorb public inputs");
    let mut tampered_trace_root = digest_from_merkle(&fixture.trace_root);
    tampered_trace_root.bytes[0] ^= 0xff;
    transcript
        .absorb_digest(TranscriptLabel::TraceRoot, &tampered_trace_root)
        .expect("absorb tampered trace root");
    let _ = transcript
        .challenge_field(TranscriptLabel::TraceChallengeA)
        .expect("trace challenge");
    transcript
        .absorb_digest(
            TranscriptLabel::CompRoot,
            &digest_from_merkle(&fixture.composition_root),
        )
        .expect("absorb comp root");
    let _ = transcript
        .challenge_field(TranscriptLabel::CompChallengeA)
        .expect("comp alpha");

    let err = fri_verify(&fixture.proof, &fixture.params, &mut transcript)
        .expect_err("tampered trace root must be rejected");
    assert!(
        matches!(err, FriError::InvalidStructure(reason) if reason == "fold challenge mismatch")
    );
}

fn build_fixture() -> LfsrFriFixture {
    let mut builder = StarkParamsBuilder::new();
    builder.hash = HashKind::Blake2s { digest_size: 32 };
    builder.fri.queries = 64;
    builder.fri.domain_log2 = 9;
    builder.fri.num_layers = 7;
    let params = builder.build().expect("valid params");

    let inputs = LfsrPublicInputs::new(FieldElement::from(3u64), 64).expect("inputs");
    let air = LfsrAir::new(inputs.clone());
    let schema = air.trace_schema().expect("trace schema");

    let trace_column = lfsr_trace_values(&inputs);
    let mut trace_builder = air.new_trace_builder().expect("trace builder");
    trace_builder
        .add_column(TraceRole::Main, trace_column.clone())
        .expect("add trace column");
    let trace_data = trace_builder
        .build(schema.degree_bounds)
        .expect("build trace data");
    assert_eq!(trace_data.num_columns(), 1);

    let trace_rows = trace_column.len();
    let extender = LowDegreeExtender::new(trace_rows, 1, &PROFILE_X8);
    let extended_trace = extender.extend_trace(&trace_column);

    let trace_leaves = pack_leaves(&extended_trace, params.merkle().leaf_width as usize);
    let (trace_root, _trace_aux) = <MerkleTree<DeterministicMerkleHasher> as MerkleCommit>::commit(
        &params,
        trace_leaves.into_iter(),
    )
    .expect("trace commitment");

    let domain_size = 1usize << params.fri().domain_log2 as usize;
    let evaluations = transition_evaluations(&trace_column, domain_size);
    let composition_leaves = pack_leaves(&evaluations, params.merkle().leaf_width as usize);
    let (composition_root, _composition_aux) =
        <MerkleTree<DeterministicMerkleHasher> as MerkleCommit>::commit(
            &params,
            composition_leaves.into_iter(),
        )
        .expect("composition commitment");

    let mut transcript = Transcript::new(&params, TranscriptContext::StarkMain);
    transcript
        .absorb_digest(
            TranscriptLabel::PublicInputsDigest,
            &DigestBytes {
                bytes: inputs.digest().expect("fixture inputs must be canonical"),
            },
        )
        .expect("absorb public inputs");
    transcript
        .absorb_digest(TranscriptLabel::TraceRoot, &digest_from_merkle(&trace_root))
        .expect("absorb trace root");
    let trace_challenge = transcript
        .challenge_field(TranscriptLabel::TraceChallengeA)
        .expect("trace challenge");
    transcript
        .absorb_digest(
            TranscriptLabel::CompRoot,
            &digest_from_merkle(&composition_root),
        )
        .expect("absorb composition root");

    let evaluations_group = ConstraintGroup::new(
        "lfsr-transition",
        TraceRole::Main,
        1,
        vec![evaluations.clone()],
    );
    let (composition, commitment) = compose(
        &air,
        CompositionParams {
            stark: &params,
            transcript: &mut transcript,
            degree_bounds: schema.degree_bounds,
            groups: &[evaluations_group],
        },
    )
    .expect("compose transition constraints");
    assert_eq!(commitment.root, composition_root);
    assert_eq!(composition, evaluations);

    let proof = fri_prove(&composition, &params, &mut transcript).expect("fri proof");

    LfsrFriFixture {
        params,
        inputs,
        trace_root,
        composition_root,
        commitment,
        proof,
        trace_challenge,
    }
}

fn lfsr_trace_values(inputs: &LfsrPublicInputs) -> Vec<FieldElement> {
    let mut column = Vec::with_capacity(inputs.length);
    let mut state = inputs.seed;
    column.push(state);
    let alpha = FieldElement::from(LFSR_ALPHA);
    let beta = FieldElement::from(LFSR_BETA);
    for _ in 1..inputs.length {
        state = state.mul(&alpha).add(&beta);
        column.push(state);
    }
    column
}

fn transition_evaluations(trace_column: &[FieldElement], domain_size: usize) -> Vec<FieldElement> {
    let alpha = FieldElement::from(LFSR_ALPHA);
    let beta = FieldElement::from(LFSR_BETA);
    let mut evaluations = vec![FieldElement::ZERO; domain_size];
    for i in 0..(trace_column.len() - 1) {
        let current = trace_column[i];
        let next = trace_column[i + 1];
        let expected = current.mul(&alpha).add(&beta);
        evaluations[i] = next.sub(&expected);
    }
    evaluations
}

fn pack_leaves(values: &[FieldElement], leaf_width: usize) -> Vec<Leaf> {
    assert!(leaf_width > 0, "leaf width must be positive");
    assert_eq!(
        values.len() % leaf_width,
        0,
        "evaluations must align with leaf width"
    );
    values
        .chunks(leaf_width)
        .map(|chunk| {
            let mut bytes = Vec::with_capacity(leaf_width * FieldElement::BYTE_LENGTH);
            for felt in chunk {
                let le = felt.to_bytes().expect("fixture values are canonical");
                bytes.extend_from_slice(&le);
            }
            Leaf::new(bytes)
        })
        .collect()
}

fn prepare_verifier_transcript(fixture: &LfsrFriFixture) -> Transcript {
    let mut transcript = Transcript::new(&fixture.params, TranscriptContext::StarkMain);
    transcript
        .absorb_digest(
            TranscriptLabel::PublicInputsDigest,
            &DigestBytes {
                bytes: fixture
                    .inputs
                    .digest()
                    .expect("fixture inputs must be canonical"),
            },
        )
        .expect("absorb public inputs");
    transcript
        .absorb_digest(
            TranscriptLabel::TraceRoot,
            &digest_from_merkle(&fixture.trace_root),
        )
        .expect("absorb trace root");
    transcript
}

fn digest_from_merkle(root: &Digest) -> DigestBytes {
    let bytes: [u8; DIGEST_SIZE] = root.as_bytes().try_into().expect("digest width");
    DigestBytes { bytes }
}
