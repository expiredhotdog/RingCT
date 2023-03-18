// SPDX short identifier: Unlicense

use ringct::{
    curve::{
        Scalar,
        Random
    },
    rangeproof::BorromeanRangeProof
};

fn main() {
    //See the pedersen commitment example before this

    //Note that these proofs are essentially obsolete;
    //Bulletproofs+ are smaller, faster, and scale better than these proofs.

    //Create a rangeproof, proving that the given value is a valid 64-bit integer (between 0 and 2^64 - 1)
    let (commitment, proof) = BorromeanRangeProof::prove(
        123456789,      //value of the Pedersen commitment (in atomic units, for example piconeros:
                            //https://web.getmonero.org/resources/moneropedia/atomic-units.html)
        Scalar::generate() //blinding factor of the Pedersen commitment
    ).expect("Real software should have proper error handling.");

    //Verify the rangeproof
    BorromeanRangeProof::verify(commitment, proof)
        .expect("Real software should have proper error handling.");
}
