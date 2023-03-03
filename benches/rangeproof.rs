// SPDX short identifier: Unlicense

use criterion::{
    black_box,
    criterion_group,
    criterion_main,
    Criterion,
    BenchmarkId
};
use std::time::Duration;
use std::iter::zip;

const AGGREGATION_SIZES: [usize; 6] = [1, 2, 4, 8, 16, 128];
const BATCH_SIZES: [usize; 3] = [1, 25, 256];

use ringct::{
    common::*,
    rangeproof::{
        BulletPlusRangeProof,
        BorromeanRangeProof
    }
};

fn bulletproofsplus_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("Bulletproofs+");
    group.sample_size(10);
    group.measurement_time(Duration::from_secs(10));

    //prove
    for x in AGGREGATION_SIZES {
        let mut values: Vec<u64> = Vec::new();
        let mut blindings: Vec<Scalar> = Vec::new();
        for n in 0..x {
            values.push(1234567890 + n as u64);
            blindings.push(random_scalar());
        }
        let params = (values, blindings);
        group.bench_with_input(BenchmarkId::new("prove", format!("Aggregation size: {x}")), &params,
            |b, (values, blindings)| b.iter(|| {
                BulletPlusRangeProof::prove(values.to_owned(), blindings.to_owned())
            }));
    }

    //verify
    for x in AGGREGATION_SIZES {
        let mut values: Vec<u64> = Vec::new();
        let mut blindings: Vec<Scalar> = Vec::new();
        for n in 0..x {
            values.push(1234567890 + n as u64);
            blindings.push(random_scalar());
        }

        let (commitment, proof) = BulletPlusRangeProof::prove(values, blindings).unwrap();
        for i in BATCH_SIZES {
            let mut commitments: Vec<Vec<Commitment>> = Vec::new();
            let mut proofs: Vec<BulletPlusRangeProof> = Vec::new();
            for _ in 0..i {
                commitments.push(commitment.clone());
                proofs.push(proof.clone());
            }

            let proofs = (commitments, proofs);

            if i == 1 {
                //linear
                group.bench_with_input(BenchmarkId::new(format!("verify {i}"), format!("linear/Aggregation size: {x}")), &proofs,
                |b, (commitments, proofs)| b.iter(|| {
                    for (commitment, proof) in zip(commitments, proofs) {
                        black_box(BulletPlusRangeProof::verify(commitment.to_owned(), proof.to_owned()).unwrap());
                    }
                }));

            } else {
                //batched
                group.bench_with_input(BenchmarkId::new(format!("verify {i}"), format!("batched/Aggregation size: {x}")), &proofs,
                |b, (commitments, proofs)| b.iter(|| {
                    black_box(BulletPlusRangeProof::batch_verify(commitments.to_owned(), proofs.to_owned()).unwrap())
                }));
            }
        }
    }
}


fn borromean_benchmark(c: &mut Criterion) {
    //prove
    let params = (1234567890u64, random_scalar());
    c.bench_with_input(BenchmarkId::new("Borromean", "prove"), &params,
        |b, (value, blinding)| b.iter(|| {
            BorromeanRangeProof::prove(value.to_owned(), blinding.to_owned())
        }));


    //verify
    let params = BorromeanRangeProof::prove(1234567890u64, random_scalar()).unwrap();
    c.bench_with_input(BenchmarkId::new("Borromean", "verify"), &params,
        |b, (commitment, proof)| b.iter(|| {
            black_box(BorromeanRangeProof::verify(commitment.to_owned(), proof.to_owned()).unwrap());
        }));
}


criterion_group!(rangeproofs, bulletproofsplus_benchmark, borromean_benchmark);
criterion_main!(rangeproofs);