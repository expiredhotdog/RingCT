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
    curve::{
        Scalar,
        Random
    },
    address::ECDHPrivateKey,
};

fn ecdh_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("ECDH");
    group.sample_size(100);
    group.measurement_time(Duration::from_secs(3));

    let sk1 = Scalar::generate();
    let sk2 = Scalar::generate();
    let pk2 = sk2.to_public();

    let ss1 = sk1.shared_secret(&pk2);

    let params = sk1.clone();
    group.bench_with_input(BenchmarkId::new("Generate", "Shared secret"), &params,
    |b, sk1| b.iter(|| {
        black_box(sk1.shared_secret(&pk2));
    }));

    group.bench_with_input(BenchmarkId::new("Generate", "View tag"), &(),
    |b, () | b.iter(|| {
        black_box(ss1.get_view_tag());
    }));

    group.bench_with_input(BenchmarkId::new("Generate", "Derived key"), &(ss1),
    |b, ss1| b.iter(|| {
        black_box(sk1.derive_key(ss1.clone()));
    }));
}

criterion_group!(rangeproofs, ecdh_benchmark);
criterion_main!(rangeproofs);