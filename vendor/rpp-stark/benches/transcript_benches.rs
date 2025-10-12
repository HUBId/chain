use criterion::{black_box, criterion_group, criterion_main, Criterion};
use rpp_stark::params::{BuiltinProfile, StarkParamsBuilder};
use rpp_stark::transcript::{Transcript, TranscriptContext, TranscriptLabel};
use rpp_stark::utils::serialization::DigestBytes;

fn sample_params() -> rpp_stark::params::StarkParams {
    StarkParamsBuilder::from_profile(BuiltinProfile::PROFILE_X8)
        .build()
        .expect("valid profile")
}

fn prepare_for_trace(params: &rpp_stark::params::StarkParams) -> Transcript {
    let mut transcript = Transcript::new(params, TranscriptContext::StarkMain);
    let public = DigestBytes { bytes: [1u8; 32] };
    transcript
        .absorb_digest(TranscriptLabel::PublicInputsDigest, &public)
        .expect("phase");
    let trace = DigestBytes { bytes: [2u8; 32] };
    transcript
        .absorb_digest(TranscriptLabel::TraceRoot, &trace)
        .expect("phase");
    transcript
}

fn prepare_for_comp(params: &rpp_stark::params::StarkParams) -> Transcript {
    let mut transcript = prepare_for_trace(params);
    let _ = transcript
        .challenge_field(TranscriptLabel::TraceChallengeA)
        .expect("challenge");
    let comp_root = DigestBytes { bytes: [3u8; 32] };
    transcript
        .absorb_digest(TranscriptLabel::CompRoot, &comp_root)
        .expect("phase");
    transcript
}

fn prepare_for_queries(params: &rpp_stark::params::StarkParams) -> Transcript {
    let mut transcript = prepare_for_comp(params);
    let _ = transcript
        .challenge_field(TranscriptLabel::CompChallengeA)
        .expect("challenge");
    for layer in 0..params.fri().num_layers {
        let fri_root = DigestBytes {
            bytes: [10 + layer; 32],
        };
        transcript
            .absorb_digest(TranscriptLabel::FriRoot(layer), &fri_root)
            .expect("fri root");
        let _ = transcript
            .challenge_field(TranscriptLabel::FriFoldChallenge(layer))
            .expect("fri fold");
    }
    transcript
        .absorb_bytes(
            TranscriptLabel::QueryCount,
            &params.fri().queries.to_le_bytes(),
        )
        .expect("query count");
    transcript
}

fn bench_transcript(c: &mut Criterion) {
    let params = sample_params();
    let mut group = c.benchmark_group("transcript");

    group.bench_function("absorb_bytes_small", |b| {
        let payload = [0u8; 32];
        b.iter(|| {
            let mut transcript = Transcript::new(&params, TranscriptContext::StarkMain);
            transcript
                .absorb_bytes(TranscriptLabel::PublicInputsDigest, &payload)
                .expect("absorb");
            black_box(transcript.state_digest())
        });
    });

    group.bench_function("absorb_bytes_large", |b| {
        let payload = vec![42u8; 64 * 1024];
        b.iter(|| {
            let mut transcript = Transcript::new(&params, TranscriptContext::StarkMain);
            transcript
                .absorb_bytes(TranscriptLabel::PublicInputsDigest, &payload)
                .expect("absorb");
            black_box(transcript.state_digest())
        });
    });

    group.bench_function("challenge_field", |b| {
        b.iter(|| {
            let mut transcript = prepare_for_trace(&params);
            black_box(
                transcript
                    .challenge_field(TranscriptLabel::TraceChallengeA)
                    .expect("challenge"),
            )
        });
    });

    group.bench_function("challenge_usize", |b| {
        b.iter(|| {
            let mut transcript = prepare_for_queries(&params);
            black_box(
                transcript
                    .challenge_usize(TranscriptLabel::QueryIndexStream, 1 << 16)
                    .expect("usize"),
            )
        });
    });

    group.finish();
}

criterion_group!(benches, bench_transcript);
criterion_main!(benches);
