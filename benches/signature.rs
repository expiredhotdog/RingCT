// SPDX short identifier: Unlicense

use criterion::{
    criterion_group,
    criterion_main,
    Criterion,
    BenchmarkId
};
use rand::{thread_rng, Rng};

const RING_SIZES: [usize; 10] = [2, 4, 8, 16, 32, 64, 128, 256, 512, 1024];

use ringct::{
    common::*,
    signature::{
        MLSAGSignature,
        CLSAGSignature
    }
};

fn random_enote_keys() -> EnoteKeys {
    return EnoteKeys {
        owner: random_scalar(),
        value: thread_rng().gen::<u64>(),
        blinding: random_scalar()
    }
}

fn clsag_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("CLSAG");
    group.sample_size(20);

    //prove
    for x in RING_SIZES {
        let mut enote_keys: Vec<EnoteKeys> = Vec::new();
        let mut enotes: Ring = Ring::new();
        for _ in 0..x {
            let _enote_keys = random_enote_keys();
            enote_keys.push(_enote_keys.clone());
            enotes.push(_enote_keys.to_enote());
        }
        let my_key = &enote_keys[thread_rng().gen::<usize>() % x];
        let out_blinding = random_scalar();

        let params = (enotes, my_key.to_owned(), out_blinding);
        group.bench_with_input(BenchmarkId::new("sign", format!("Ring size: {x}")), &params,
            |b, (enotes, my_key, out_blinding)| b.iter(|| {
                CLSAGSignature::sign_unsorted(enotes, my_key.to_owned(), out_blinding.to_owned(), b"abcdef").unwrap()
            }));
    }

    //verify
    for x in RING_SIZES {
        let mut enote_keys: Vec<EnoteKeys> = Vec::new();
        let mut enotes: Ring = Ring::new();
        for _ in 0..x {
            let _enote_keys = random_enote_keys();
            enote_keys.push(_enote_keys.clone());
            enotes.push(_enote_keys.to_enote());
        }
        let my_key = &enote_keys[thread_rng().gen::<usize>() % x];
        let out_blinding = random_scalar();
        let sig = CLSAGSignature::sign_unsorted(&enotes, my_key.to_owned(), out_blinding, b"abcdef").unwrap();

        let params = (sig.1, enotes, sig.0);
        group.bench_with_input(BenchmarkId::new("verify", format!("Ring size: {x}")), &params,
            |b, (sig, enotes, pseudo_out)| b.iter(|| {
                CLSAGSignature::verify_unsorted(sig.to_owned(), enotes, pseudo_out.to_owned(), b"abcdef").unwrap()
            }));
    }
}

fn mlsag_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("MLSAG");
    group.sample_size(20);

    //prove
    for x in RING_SIZES {
        let mut enote_keys: Vec<EnoteKeys> = Vec::new();
        let mut enotes: Ring = Ring::new();
        for _ in 0..x {
            let _enote_keys = random_enote_keys();
            enote_keys.push(_enote_keys.clone());
            enotes.push(_enote_keys.to_enote());
        }
        let my_key = &enote_keys[thread_rng().gen::<usize>() % x];
        let out_blinding = random_scalar();

        let params = (enotes, my_key.to_owned(), out_blinding);
        group.bench_with_input(BenchmarkId::new("sign", format!("Ring size: {x}")), &params,
            |b, (enotes, my_key, out_blinding)| b.iter(|| {
                MLSAGSignature::sign_unsorted(enotes, my_key.to_owned(), out_blinding.to_owned(), b"abcdef").unwrap()
            }));
    }

    //verify
    for x in RING_SIZES {
        let mut enote_keys: Vec<EnoteKeys> = Vec::new();
        let mut enotes: Ring = Ring::new();
        for _ in 0..x {
            let _enote_keys = random_enote_keys();
            enote_keys.push(_enote_keys.clone());
            enotes.push(_enote_keys.to_enote());
        }
        let my_key = &enote_keys[thread_rng().gen::<usize>() % x];
        let out_blinding = random_scalar();
        let sig = MLSAGSignature::sign_unsorted(&enotes, my_key.to_owned(), out_blinding, b"abcdef").unwrap();

        let params = (sig.1, enotes, sig.0);
        group.bench_with_input(BenchmarkId::new("verify", format!("Ring size: {x}")), &params,
            |b, (sig, enotes, pseudo_out)| b.iter(|| {
                MLSAGSignature::verify_unsorted(sig.to_owned(), enotes, pseudo_out.to_owned(), b"abcdef").unwrap()
            }));
    }
}


criterion_group!(signature_ringct, clsag_benchmark, mlsag_benchmark);
criterion_main!(signature_ringct);