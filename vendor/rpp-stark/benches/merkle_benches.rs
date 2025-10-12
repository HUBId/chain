use criterion::{criterion_group, criterion_main, BatchSize, BenchmarkId, Criterion, Throughput};
use rpp_stark::merkle::{DeterministicMerkleHasher, Leaf, MerkleCommit, MerkleTree};
use rpp_stark::params::{Endianness, HashKind, MerkleArity, StarkParams, StarkParamsBuilder};

fn build_params(arity: MerkleArity, leaf_width: u8) -> StarkParams {
    let mut builder = StarkParamsBuilder::new();
    builder.hash = HashKind::Blake2s { digest_size: 32 };
    builder.merkle.arity = arity;
    builder.merkle.leaf_width = leaf_width;
    builder.merkle.leaf_encoding = Endianness::Little;
    builder.build().expect("valid params")
}

fn make_leaves(count: usize, width: u8) -> Vec<Leaf> {
    let mut leaves = Vec::with_capacity(count);
    for i in 0..count {
        let mut bytes = Vec::new();
        for j in 0..width as usize {
            let value = (i * width as usize + j) as u64;
            bytes.extend_from_slice(&value.to_le_bytes());
        }
        leaves.push(Leaf::new(bytes));
    }
    leaves
}

fn bench_commit(c: &mut Criterion) {
    let params_bin = build_params(MerkleArity::Binary, 4);
    let params_quad = build_params(MerkleArity::Quaternary, 4);
    let sizes = [1024usize, 16_384, 65_536];
    for &size in &sizes {
        let leaves = make_leaves(size, params_bin.merkle().leaf_width);
        let bytes = (size * params_bin.merkle().leaf_width as usize * 8) as u64;
        let mut group = c.benchmark_group("commit_binary");
        group.throughput(Throughput::Bytes(bytes));
        group.bench_with_input(BenchmarkId::from_parameter(size), &leaves, |b, leaves| {
            b.iter_batched(
                || {
                    (
                        MerkleTree::<DeterministicMerkleHasher>::new(&params_bin).unwrap(),
                        leaves.clone(),
                    )
                },
                |(mut tree, leaves)| {
                    let _ = tree.commit(leaves.into_iter()).unwrap();
                },
                BatchSize::SmallInput,
            );
        });
        group.finish();

        let leaves = make_leaves(size, params_quad.merkle().leaf_width);
        let bytes = (size * params_quad.merkle().leaf_width as usize * 8) as u64;
        let mut group = c.benchmark_group("commit_quaternary");
        group.throughput(Throughput::Bytes(bytes));
        group.bench_with_input(BenchmarkId::from_parameter(size), &leaves, |b, leaves| {
            b.iter_batched(
                || {
                    (
                        MerkleTree::<DeterministicMerkleHasher>::new(&params_quad).unwrap(),
                        leaves.clone(),
                    )
                },
                |(mut tree, leaves)| {
                    let _ = tree.commit(leaves.into_iter()).unwrap();
                },
                BatchSize::SmallInput,
            );
        });
        group.finish();
    }
}

fn bench_verify(c: &mut Criterion) {
    let params = build_params(MerkleArity::Binary, 4);
    let sizes = [16usize, 64, 256];
    let leaves = make_leaves(1 << 12, params.merkle().leaf_width);
    let mut tree = MerkleTree::<DeterministicMerkleHasher>::new(&params).unwrap();
    let root = tree.commit(leaves.clone().into_iter()).unwrap();
    let aux = tree.into_aux();
    for &queries in &sizes {
        let indices: Vec<u32> = (0..queries as u32).collect();
        let proof = MerkleTree::<DeterministicMerkleHasher>::open(&params, &aux, &indices).unwrap();
        let selected: Vec<Leaf> = indices
            .iter()
            .map(|i| leaves[*i as usize].clone())
            .collect();
        c.bench_with_input(
            BenchmarkId::new("verify_batch", queries),
            &queries,
            |b, _| {
                b.iter(|| {
                    MerkleTree::<DeterministicMerkleHasher>::verify(
                        &params, &root, &proof, &selected,
                    )
                    .unwrap();
                });
            },
        );
    }
}

fn merkle_benches(c: &mut Criterion) {
    bench_commit(c);
    bench_verify(c);
}

criterion_group!(benches, merkle_benches);
criterion_main!(benches);
