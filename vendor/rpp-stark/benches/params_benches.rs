use criterion::{black_box, criterion_group, criterion_main, Criterion};
use rpp_stark::params::{params_hash, serialize_params, BuiltinProfile, StarkParamsBuilder};

fn bench_params(c: &mut Criterion) {
    let mut group = c.benchmark_group("stark_params");
    group.bench_function("build_profile_x8", |b| {
        b.iter(|| {
            let builder = StarkParamsBuilder::new();
            black_box(builder.build().expect("builder must succeed"));
        });
    });

    let params = StarkParamsBuilder::new().build().expect("valid profile");
    group.bench_function("hash_profile_x8", |b| {
        b.iter(|| black_box(params_hash(black_box(&params))));
    });
    group.bench_function("serialize_profile_x8", |b| {
        b.iter(|| black_box(serialize_params(black_box(&params))));
    });

    let hisec = StarkParamsBuilder::from_profile(BuiltinProfile::PROFILE_HISEC_X16)
        .build()
        .expect("valid profile");
    group.bench_function("hash_profile_hisec", |b| {
        b.iter(|| black_box(params_hash(black_box(&hisec))));
    });
    group.finish();
}

criterion_group!(benches, bench_params);
criterion_main!(benches);
