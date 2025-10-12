use std::convert::TryInto;

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use rpp_stark::air::composition::{compose, CompositionParams, ConstraintGroup};
use rpp_stark::air::example::{LfsrAir, LfsrPublicInputs};
use rpp_stark::air::traits::Air;
use rpp_stark::air::types::{DegreeBounds, TraceRole};
use rpp_stark::field::prime_field::{CanonicalSerialize, FieldElementOps};
use rpp_stark::field::FieldElement;
use rpp_stark::merkle::{DeterministicMerkleHasher, Digest, Leaf, MerkleCommit, MerkleTree};
use rpp_stark::params::{HashKind, StarkParams, StarkParamsBuilder};
use rpp_stark::transcript::{Transcript, TranscriptContext, TranscriptLabel};
use rpp_stark::utils::serialization::DigestBytes;

const LFSR_ALPHA: u64 = 5;
const LFSR_BETA: u64 = 7;
const LFSR_SEED: u64 = 3;
const TRACE_LENGTHS: [usize; 4] = [256, 1024, 4096, 16_384];

struct TransitionFixture {
    trace: Vec<FieldElement>,
    domain_size: usize,
}

struct CompositionFixture {
    air: LfsrAir,
    inputs: LfsrPublicInputs,
    params: StarkParams,
    degree_bounds: DegreeBounds,
    groups: Vec<ConstraintGroup>,
    composition_root: Digest,
    domain_size: usize,
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
                let le = felt.to_bytes().expect("benchmark inputs must be canonical");
                bytes.extend_from_slice(&le);
            }
            Leaf::new(bytes)
        })
        .collect()
}

fn build_transition_fixture(length: usize) -> TransitionFixture {
    let inputs = LfsrPublicInputs::new(FieldElement::from(LFSR_SEED), length).expect("inputs");
    let trace = lfsr_trace_values(&inputs);
    TransitionFixture {
        trace,
        domain_size: length,
    }
}

fn build_composition_fixture(length: usize) -> CompositionFixture {
    let inputs = LfsrPublicInputs::new(FieldElement::from(LFSR_SEED), length).expect("inputs");
    let air = LfsrAir::new(inputs.clone());
    let schema = air.trace_schema().expect("trace schema");

    let trace_column = lfsr_trace_values(&inputs);
    let domain_size = length;
    let evaluations = transition_evaluations(&trace_column, domain_size);

    let mut builder = StarkParamsBuilder::new();
    builder.hash = HashKind::Blake2s { digest_size: 32 };
    builder.fri.domain_log2 = length.trailing_zeros() as u16;
    let params = builder.build().expect("valid params");

    let leaves = pack_leaves(&evaluations, params.merkle().leaf_width as usize);
    let (composition_root, _aux) = <MerkleTree<DeterministicMerkleHasher> as MerkleCommit>::commit(
        &params,
        leaves.into_iter(),
    )
    .expect("composition commitment");

    let group = ConstraintGroup::new("lfsr-transition", TraceRole::Main, 1, vec![evaluations]);

    CompositionFixture {
        air,
        inputs,
        params,
        degree_bounds: schema.degree_bounds,
        groups: vec![group],
        composition_root,
        domain_size,
    }
}

fn stage_transcript(
    params: &StarkParams,
    inputs: &LfsrPublicInputs,
    composition_root: &Digest,
) -> Transcript {
    let mut transcript = Transcript::new(params, TranscriptContext::StarkMain);
    transcript
        .absorb_digest(
            TranscriptLabel::PublicInputsDigest,
            &DigestBytes {
                bytes: inputs
                    .digest()
                    .expect("fixture public inputs must be canonical"),
            },
        )
        .expect("absorb public inputs");
    let zero_digest = DigestBytes { bytes: [0u8; 32] };
    transcript
        .absorb_digest(TranscriptLabel::TraceRoot, &zero_digest)
        .expect("absorb trace root");
    let _ = transcript
        .challenge_field(TranscriptLabel::TraceChallengeA)
        .expect("trace challenge");
    transcript
        .absorb_digest(
            TranscriptLabel::CompRoot,
            &digest_from_merkle(composition_root),
        )
        .expect("absorb composition root");
    transcript
}

fn digest_from_merkle(root: &Digest) -> DigestBytes {
    let bytes: [u8; 32] = root.as_bytes().try_into().expect("digest width");
    DigestBytes { bytes }
}

fn bench_transition_evaluation(c: &mut Criterion) {
    let fixtures: Vec<_> = TRACE_LENGTHS
        .iter()
        .map(|&length| build_transition_fixture(length))
        .collect();

    let mut group = c.benchmark_group("air_transition_evaluation");

    for fixture in &fixtures {
        let label = format!("n{}", fixture.trace.len());
        group.throughput(Throughput::Elements((fixture.trace.len() - 1) as u64));
        group.bench_with_input(BenchmarkId::new("evaluate", &label), fixture, |b, input| {
            b.iter(|| {
                black_box(transition_evaluations(&input.trace, input.domain_size));
            });
        });
    }

    group.finish();
}

fn bench_composition_throughput(c: &mut Criterion) {
    let fixtures: Vec<_> = TRACE_LENGTHS
        .iter()
        .map(|&length| build_composition_fixture(length))
        .collect();

    let mut group = c.benchmark_group("air_composition_throughput");

    for fixture in &fixtures {
        let label = format!("n{}", fixture.domain_size);
        group.throughput(Throughput::Elements(fixture.domain_size as u64));
        group.bench_with_input(BenchmarkId::new("compose", &label), fixture, |b, input| {
            b.iter(|| {
                let mut transcript =
                    stage_transcript(&input.params, &input.inputs, &input.composition_root);
                black_box(
                    compose(
                        &input.air,
                        CompositionParams {
                            stark: &input.params,
                            transcript: &mut transcript,
                            degree_bounds: input.degree_bounds,
                            groups: input.groups.as_slice(),
                        },
                    )
                    .expect("compose transition constraints"),
                );
            });
        });
    }

    group.finish();
}

criterion_group!(
    air_benches,
    bench_transition_evaluation,
    bench_composition_throughput
);
criterion_main!(air_benches);
