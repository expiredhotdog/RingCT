// SPDX short identifier: Unlicense

use ringct::{
    curve::random_scalar,
    rangeproof::BulletPlusRangeProof
};

fn main() {
    //See the pedersen commitment example before this

    //values of the Pedersen commitments (in atomic units, for example piconeros:
        //https://web.getmonero.org/resources/moneropedia/atomic-units.html)
    let values = vec!(123456789, 2222222, 8, 69420);
    //blinding factors of the Pedersen commitments
    let blindings = vec!(random_scalar(), random_scalar(), random_scalar(), random_scalar());

    //Create an aggregated rangeproof,
    //proving that all of the given values are valid 64-bit integers (between 0 and 2^64 - 1).
    //This example proves 4 values, but any number between 1 and 256 can be done.
    let (commitments, proof) = BulletPlusRangeProof::prove(
        values,
        blindings
    ).expect("Real software should have proper error handling.");

    //Verify the rangeproof
    BulletPlusRangeProof::verify(commitments.clone(), proof.clone())
        .expect("Real software should have proper error handling.");


    //Create another rangeproof
    let values = vec!(123, 0, 42069);
    let blindings = vec!(random_scalar(), random_scalar(), random_scalar());
    let (commitments2, proof2) = BulletPlusRangeProof::prove(
        values, blindings).unwrap();

    //Batch verify multiple rangeproofs at once.
    //This is a lot more efficient than verifying them individually!
    let batched_commitments = vec!(commitments, commitments2);
    let batched_proofs = vec!(proof, proof2);
    BulletPlusRangeProof::batch_verify(batched_commitments, batched_proofs)
        .expect("Real software should have proper error handling.");
}
