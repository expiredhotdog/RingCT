// SPDX short identifier: Unlicense

#![allow(unused, unused_mut)]

use ringct::{
    common::*,
    rangeproof::{
        BulletPlusRangeProof,
        BorromeanRangeProof,
        BIT_RANGE
    }
};

const AGGREGATION_SIZES: [usize; 6] = [1, 2, 3, 8, 55, 256];

#[test]
fn bulletproofsplus_test() {
    for x in AGGREGATION_SIZES {
        let mut batched_commitments: Vec<Vec<Commitment>> = Vec::new();
        let mut batched_proofs: Vec<BulletPlusRangeProof> = Vec::new();

        let mut values: Vec<u64> = Vec::new();
        let mut blindings: Vec<Scalar> = Vec::new();
        for n in 0..x {
            values.push(1234567890 + n as u64);
            blindings.push(random_scalar());
        }
        //prove
        let (commitments, proof) = BulletPlusRangeProof::prove(
            values, blindings).unwrap();

        batched_commitments.push(commitments);

        let mut deserialized = proof.clone();
        #[cfg(feature = "to_bytes")]
        {
            //serialize
            let serialized = proof.to_bytes().unwrap();
            deserialized = BulletPlusRangeProof::from_bytes(&serialized).unwrap();
        }
        batched_proofs.push(deserialized);

        //verify
        BulletPlusRangeProof::batch_verify(
            batched_commitments, batched_proofs).unwrap();
    }

    //test max/min values
    let (commitments, proof) = BulletPlusRangeProof::prove(
        vec!(0u64), vec!(random_scalar())).unwrap();
    BulletPlusRangeProof::verify(commitments, proof).unwrap();

    let (commitments, proof) = BulletPlusRangeProof::prove(
        vec!(((1u128 << BIT_RANGE) - 1) as u64), vec!(random_scalar())).unwrap();
    BulletPlusRangeProof::verify(commitments, proof).unwrap();
}

#[test]
fn borromean_test() {
    //prove
    let (commitment, proof) = BorromeanRangeProof::prove(
        1234567890u64, random_scalar()).unwrap();

    let mut deserialized = proof.clone();
    #[cfg(feature = "to_bytes")]
    {
        //serialize
        let serialized = proof.to_bytes().unwrap();
        deserialized = BorromeanRangeProof::from_bytes(&serialized).unwrap();
    }
    //verify
    BorromeanRangeProof::verify(
        commitment, deserialized).unwrap();

    //test max/min values
    let (commitment, proof) = BorromeanRangeProof::prove(
        0u64, random_scalar()).unwrap();
    BorromeanRangeProof::verify(commitment, proof).unwrap();

    let (commitment, proof) = BorromeanRangeProof::prove(
        ((1u128 << BIT_RANGE) - 1) as u64, random_scalar()).unwrap();
    BorromeanRangeProof::verify(commitment, proof).unwrap();
}