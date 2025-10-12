use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use rpp_stark::field::FieldElement;
use rpp_stark::fri::{
    binary_fold, coset_shift_schedule, derive_query_plan_id, fri_prove, fri_verify, FriLayer,
    FriParamsView, FriSecurityLevel,
};
use rpp_stark::params::{BuiltinProfile, StarkParams, StarkParamsBuilder};
use rpp_stark::transcript::{Transcript, TranscriptContext, TranscriptLabel};
use rpp_stark::utils::serialization::DigestBytes;

#[derive(Clone)]
struct LayerInput {
    index: usize,
    coset_shift: FieldElement,
    values: Vec<FieldElement>,
}

struct LayerSchedule {
    _view: FriParamsView,
    layers: Vec<LayerInput>,
}

fn sample_params(level: FriSecurityLevel) -> StarkParams {
    let mut builder = match level {
        FriSecurityLevel::HiSec => {
            StarkParamsBuilder::from_profile(BuiltinProfile::PROFILE_HISEC_X16)
        }
        _ => StarkParamsBuilder::from_profile(BuiltinProfile::PROFILE_X8),
    };
    builder.fri.queries = level.query_budget() as u16;
    builder.fri.domain_log2 = 20;
    builder.build().expect("valid parameters")
}

fn sample_evaluations(size: usize) -> Vec<FieldElement> {
    (0..size)
        .map(|i| FieldElement::from((i as u64) + 1))
        .collect()
}

fn stage_transcript_for_fri(params: &StarkParams) -> Transcript {
    let mut transcript = Transcript::new(params, TranscriptContext::StarkMain);
    let zero = DigestBytes { bytes: [0u8; 32] };
    transcript
        .absorb_digest(TranscriptLabel::PublicInputsDigest, &zero)
        .expect("public digest");
    transcript
        .absorb_digest(TranscriptLabel::TraceRoot, &zero)
        .expect("trace root");
    let _ = transcript
        .challenge_field(TranscriptLabel::TraceChallengeA)
        .expect("trace challenge");
    transcript
        .absorb_digest(TranscriptLabel::CompRoot, &zero)
        .expect("composition root");
    let _ = transcript
        .challenge_field(TranscriptLabel::CompChallengeA)
        .expect("composition challenge");
    transcript.fork(TranscriptContext::Fri)
}

fn build_layer_schedule(params: &StarkParams) -> LayerSchedule {
    let query_count = params.fri().queries as usize;
    let security_level = FriSecurityLevel::from_query_count(query_count)
        .expect("parameters must use a supported query count");
    let query_plan = derive_query_plan_id(security_level, params);
    let view = FriParamsView::from_params(params, security_level, query_plan);
    let coset_shifts = coset_shift_schedule(params, view.num_layers());
    let mut layers = Vec::with_capacity(coset_shifts.len());
    let mut current = sample_evaluations(view.initial_domain_size());

    for (layer_index, coset_shift) in coset_shifts.into_iter().enumerate() {
        let values = current.clone();
        let eta = FieldElement::from((layer_index as u64) + 7);
        current = binary_fold(&values, eta, coset_shift);
        layers.push(LayerInput {
            index: layer_index,
            coset_shift,
            values,
        });
    }

    LayerSchedule {
        _view: view,
        layers,
    }
}

fn bench_layer_commitment(c: &mut Criterion) {
    let params = sample_params(FriSecurityLevel::Standard);
    let schedule = build_layer_schedule(&params);
    let mut group = c.benchmark_group("fri_layer_commitment");

    for layer in &schedule.layers {
        let label = format!("layer{}_n{}", layer.index, layer.values.len());
        group.throughput(Throughput::Elements(layer.values.len() as u64));
        group.bench_with_input(BenchmarkId::new("commit", label), layer, |b, input| {
            b.iter(|| {
                let committed = FriLayer::new(input.index, input.coset_shift, input.values.clone())
                    .expect("layer commitment");
                black_box(committed.root());
            });
        });
    }

    group.finish();
}

fn bench_folding_throughput(c: &mut Criterion) {
    let params = sample_params(FriSecurityLevel::Standard);
    let schedule = build_layer_schedule(&params);
    let mut group = c.benchmark_group("fri_binary_fold");

    for layer in &schedule.layers {
        let eta = FieldElement::from((layer.index as u64) + 7);
        let label = format!("layer{}_n{}", layer.index, layer.values.len());
        group.throughput(Throughput::Elements(layer.values.len() as u64));
        group.bench_with_input(
            BenchmarkId::new("fold", label),
            &layer.values,
            |b, values| {
                b.iter(|| {
                    black_box(binary_fold(values, eta, layer.coset_shift));
                });
            },
        );
    }

    group.finish();
}

fn level_label(level: FriSecurityLevel) -> &'static str {
    match level {
        FriSecurityLevel::Standard => "standard",
        FriSecurityLevel::HiSec => "hisec",
        FriSecurityLevel::Throughput => "throughput",
    }
}

fn bench_verifier_latency(c: &mut Criterion) {
    let mut group = c.benchmark_group("fri_verifier_latency");

    for level in [
        FriSecurityLevel::Throughput,
        FriSecurityLevel::Standard,
        FriSecurityLevel::HiSec,
    ] {
        let params = sample_params(level);
        let domain_size = 1usize << (params.fri().domain_log2 as usize);
        let evaluations = sample_evaluations(domain_size);
        let mut prover_transcript = stage_transcript_for_fri(&params);
        let proof = fri_prove(&evaluations, &params, &mut prover_transcript).expect("fri proof");

        group.bench_function(BenchmarkId::new("verify", level_label(level)), |b| {
            b.iter(|| {
                let mut transcript = stage_transcript_for_fri(&params);
                fri_verify(black_box(&proof), &params, &mut transcript).expect("verification");
            });
        });
    }

    group.finish();
}

criterion_group!(
    fri_benches,
    bench_layer_commitment,
    bench_folding_throughput,
    bench_verifier_latency
);
criterion_main!(fri_benches);
