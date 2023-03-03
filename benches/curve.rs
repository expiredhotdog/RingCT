// SPDX short identifier: Unlicense

use criterion::{
    black_box,
    criterion_group,
    criterion_main,
    Criterion,
    BenchmarkId
};
use std::time::Duration;
use ringct::{
    common::*,
    hashes::*
};

fn ristretto_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("Ristretto");
    group.sample_size(40);
    group.measurement_time(Duration::from_secs(3));


    let params = (*random_scalar().as_bytes(), *random_scalar().as_bytes());
    group.bench_with_input(BenchmarkId::new("Scalar", "deterministic"), &params,
    |b, (p1, p2) | b.iter(|| {
        black_box(h_scalar(&[p1.as_slice(), p2.as_slice()].concat()));
    }));
    group.bench_with_input(BenchmarkId::new("Scalar", "random"), &(),
    |b, () | b.iter(|| {
        black_box(random_scalar());
    }));


    let params = random_point();
    group.bench_with_input(BenchmarkId::new("Encode", "Regular/1"), &params,
    |b, p | b.iter(|| {
        black_box(p.compress().to_bytes());
    }));
    let params = [random_point(); 2].to_vec();
    group.bench_with_input(BenchmarkId::new("Encode", "Batched/2"), &params,
    |b, p | b.iter(|| {
        black_box(batch_encode_points(p));
    }));
    let params = [random_point(); 4].to_vec();
    group.bench_with_input(BenchmarkId::new("Encode", "Batched/4"), &params,
    |b, p | b.iter(|| {
        black_box(batch_encode_points(p));
    }));
    let params = [random_point(); 8].to_vec();
    group.bench_with_input(BenchmarkId::new("Encode", "Batched/8"), &params,
    |b, p | b.iter(|| {
        black_box(batch_encode_points(p));
    }));
    let params = [random_point(); 16].to_vec();
    group.bench_with_input(BenchmarkId::new("Encode", "Batched/16"), &params,
    |b, p | b.iter(|| {
        black_box(batch_encode_points(p));
    }));


    let params = random_point();
    group.bench_with_input(BenchmarkId::new("Generate", "RistrettoBasepointTable"), &params,
    |b, p | b.iter(|| {
        black_box(RistrettoBasepointTable::create(p));
    }));
    let params = random_point();
    group.bench_with_input(BenchmarkId::new("Generate", "MultiscalarMultiplyPrecomputed"), &params,
    |b, p | b.iter(|| {
        black_box( VartimeRistrettoPrecomputation::new(vec!(p)));
    }));


    let params = (random_scalar(), random_point());
    group.bench_with_input(BenchmarkId::new("Multiply", "RistrettoPoint"), &params,
    |b, (s, p) | b.iter(|| {
        black_box(s * p);
    }));
    let params = (random_scalar(), RistrettoBasepointTable::create(&random_point()));
    group.bench_with_input(BenchmarkId::new("Multiply", "RistrettoBasepointTable"), &params,
    |b, (s, p) | b.iter(|| {
        black_box(s * p);
    }));


    let params = (random_scalar(), random_scalar(), random_point(), random_point());
    group.bench_with_input(BenchmarkId::new("MultiscalarMultiply", "2"), &params,
    |b, (s1, s2, p1, p2) | b.iter(|| {
        black_box(RistrettoPoint::multiscalar_mul(vec!(s1, s2), vec!(p1, p2)));
    }));
    let params = (random_scalar(), random_scalar(), random_point(), random_point());
    group.bench_with_input(BenchmarkId::new("MultiscalarMultiply", "2-Vartime"), &params,
    |b, (s1, s2, p1, p2) | b.iter(|| {
        black_box(RistrettoPoint::vartime_multiscalar_mul(vec!(s1, s2), vec!(p1, p2)));
    }));
    let params = (random_scalar(), random_scalar(), random_point(), VartimeRistrettoPrecomputation::new(vec!(random_point())));
    group.bench_with_input(BenchmarkId::new("MultiscalarMultiplyPrecomputed", "1/1-Vartime"), &params,
    |b, (s1, s2, p1, p2) | b.iter(|| {
        black_box(p2.vartime_mixed_multiscalar_mul(vec!(s1), vec!(s2), vec!(p1)));
    }));
}

criterion_group!(rangeproofs, ristretto_benchmark);
criterion_main!(rangeproofs);