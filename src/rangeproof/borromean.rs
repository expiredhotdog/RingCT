/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

//! Borromean ring signature-based rangeproofs


use crate::internal_common::*;
use super::{BIT_RANGE, MAX_VALUE};

lazy_static! {
    static ref BORROMEAN_H_TABLE: BorromeanHTable = BorromeanHTable::new();
}

const NUMBER_OF_PROOF_DIGITS: usize = BIT_RANGE / 2;
const FILLER_SCALAR: Scalar = constants::BASEPOINT_ORDER;

//convert base 10 number to quaternary (base 4) digits
//base 4 is the most efficient for these rangeproofs
fn quaternary(n: u64) -> [usize; NUMBER_OF_PROOF_DIGITS] {
    let mut number = n;
    let mut remainder;

    let mut x = 0;
    let mut digits = [0; NUMBER_OF_PROOF_DIGITS];

    while number != 0 {
        remainder = number % 4;
        number = (number - remainder) / 4;

        digits[x] = remainder as usize;
        x += 1;
    }
    return digits;
}

//header for borromean range proofs
struct BorromeanHTable {
    positive: [[RistrettoPoint; 4]; NUMBER_OF_PROOF_DIGITS],
    negative: [[RistrettoPoint; 4]; NUMBER_OF_PROOF_DIGITS]

} impl BorromeanHTable {
    pub fn new() -> Self {
        let zero = &Scalar::from(0u8) * &*PEDERSEN_G;

        //positive H values
        let mut pos_h_table = [[*PEDERSEN_H_POINT; 4]; NUMBER_OF_PROOF_DIGITS];
        for i in 0..NUMBER_OF_PROOF_DIGITS {
            //4 ^ i
            let n = Scalar::from(4u128.pow(i as u32));

            pos_h_table[i] = [
                zero,
                &n * &*PEDERSEN_H,
                &(n + n) * &*PEDERSEN_H,
                &(n + n + n) * &*PEDERSEN_H,
            ];
        }

        //negative H values
        let mut neg_h_table = [[*PEDERSEN_H_POINT; 4]; NUMBER_OF_PROOF_DIGITS];
        for i in 0..NUMBER_OF_PROOF_DIGITS {
            for j in 0..4 {
                neg_h_table[i][j] = -pos_h_table[i][j]
            }
        }

        return Self{
            positive: pos_h_table,
            negative: neg_h_table
        }
    }
}

//borromean ring signature. (e_0, s)
type BorromeanSignature = (Scalar, [[Scalar; 4]; NUMBER_OF_PROOF_DIGITS]);

//hash that can be "tweaked" if we know the private key of p
fn chameleon_h(m: &[u8], e: Scalar, s: Scalar, p: RistrettoPoint) -> Scalar {
    let point = &encode_point( &((&s * G) + (e * p)) );
    let msg: &[u8] = &[m, point].concat();
    return h_scalar(msg);
}

//hash that can be "tweaked" if we know the private key of p
fn vartime_chameleon_h(m: &[u8], e: Scalar, s: Scalar, p: RistrettoPoint) -> Scalar {
    //(s * G) + (e * P)
    let point = &encode_point(
        &G_MULTISCALAR_MUL.vartime_mixed_multiscalar_mul(vec!(s), vec!(e), vec!(p)) );
    let msg: &[u8] = &[m, point].concat();
    return h_scalar(msg);
}

//combine multiple chameleon hashes
fn multi_chameleon_h(m: &[u8], groups: Vec<(Scalar, Scalar, RistrettoPoint)>) -> Scalar {
    let mut points: Vec<RistrettoPoint> = Vec::new();
    for group in groups {
        let (e, s, p) = group;
        points.push( (&s * G) + (e * p) );
    }
    let combined = batch_encode_points(&points).concat();
    return h_scalar(&[m, &combined].concat())
}

//combine multiple chameleon hashes
fn vartime_multi_chameleon_h(m: &[u8], groups: Vec<(Scalar, Scalar, RistrettoPoint)>) -> Scalar {
    let mut points: Vec<RistrettoPoint> = Vec::new();
    for group in groups {
        let (e, s, p) = group;
        //(s * G) + (e * P)
        points.push(
            G_MULTISCALAR_MUL.vartime_mixed_multiscalar_mul(vec!(s), vec!(e), vec!(p)));
    }
    let combined = batch_encode_points(&points).concat();
    return h_scalar(&[m, &combined].concat())
}

//signed message includes a hash of all keys
fn create_m(rings: &Vec<Vec<RistrettoPoint>>, msg: &[u8]) -> [u8; 32] {
    let mut m: Vec<Vec<u8>> = Vec::new();
    for ring in rings {
        m.push(batch_encode_points(ring).concat())
    }
    return h_bytes(&[&m.concat(), msg].concat());
}


//create borromean ring signature
fn borromean_sign(rings: &Vec<Vec<RistrettoPoint>>, sk: &Vec<Scalar>, indices: Vec<usize>, msg: &[u8]) -> BorromeanSignature {
    //the signed message includes a hash of all keys
    let m = create_m(rings, msg);

    let mut s: [[Scalar; 4]; NUMBER_OF_PROOF_DIGITS] = [[FILLER_SCALAR; 4]; NUMBER_OF_PROOF_DIGITS];
    for i in 0..NUMBER_OF_PROOF_DIGITS {
        let mut s_ring: [Scalar; 4] = [FILLER_SCALAR; 4];
        for j in 0..4 {
            s_ring[j] = random_scalar();
        }
        s[i] = s_ring;
    }

    //random starting values
    let mut e_start: Vec<Scalar> = Vec::new();
    for _ in rings {
        e_start.push(random_scalar());
    }

    let mut e_0: Vec<(Scalar, Scalar, RistrettoPoint)> = Vec::new();
    //go around each ring until reaching e_0
    for i in 0..rings.len() {
        let mut eij = e_start[i];
        let n = rings[i].len() - 1;
        for j in indices[i]..n {
            eij = chameleon_h(&m, eij, s[i][j], rings[i][j]);
        }
        e_0.push((eij, s[i][n], rings[i][n]));
    }

    //calculate e_0, the shared seed
    let e_0 = multi_chameleon_h(&m, e_0);

    //finish constructing each ring, starting at e_0
    for i in 0..rings.len() {
        let mut eij = e_0;
        for j in 0..indices[i] {
            eij = chameleon_h(&m, eij, s[i][j], rings[i][j]);
        }

        //"tie" the ring, proving we know one of the private keys
        s[i][indices[i]] += sk[i] * (e_start[i] - eij);
    }
    return (e_0, s);
}

//verify borromean ring signature
fn borromean_verify(rings: &Vec<Vec<RistrettoPoint>>, sig: &BorromeanSignature, msg: &[u8]) -> Result<(), RangeProofError> {
    //the signed message includes a hash of all keys
    let m = create_m(rings, msg);

    let (sig_e_0, s) = sig;

    let s = &s;
    let mut e_0: Vec<(Scalar, Scalar, RistrettoPoint)> = Vec::new();
    //travel around each ring
    for i in 0..rings.len() {
        let mut eij = *sig_e_0;
        let n = rings[i].len() - 1;
        for j in 0..n {
            eij = vartime_chameleon_h(&m, eij, s[i][j], rings[i][j]);
        }

        e_0.push((eij, s[i][n], rings[i][n]));
    }
    //recreate e_0, the shared seed
    let e_0 = vartime_multi_chameleon_h(&m, e_0);

    //check if we end up back where we started
    return match e_0 == *sig_e_0 {
        true => Ok(()),
        false => Err(RangeProofError::Invalid)
    };
}


///Rangeproof based on borromean ring signatures.
///
///These proofs are essentially obsolete;
///Bulletproofs+ are smaller, faster, and scale better than these proofs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BorromeanRangeProof {
    c_i: [Commitment; NUMBER_OF_PROOF_DIGITS], //c_i values
    sig: BorromeanSignature //signature

} impl BorromeanRangeProof {
    ///Create a Borromean rangeproof, given a value and blinding factor.
    ///
    ///Return a commitment and a Borromean rangeproof if proving was successful,
    ///or `RangeProofError` if an error occurred.
    pub fn prove(value: u64, blinding: Scalar
    ) -> Result<(Commitment, Self), RangeProofError> {
        if value > MAX_VALUE {
            return Err(RangeProofError::OutOfRange);
        }
        let digits = quaternary(value);

        let mut r: Vec<Scalar> = Vec::new();
        let mut c: [RistrettoPoint; NUMBER_OF_PROOF_DIGITS] = [G_POINT; NUMBER_OF_PROOF_DIGITS];
        let mut rings: Vec<Vec<RistrettoPoint>> = Vec::new();

        let mut r_i: Scalar; // "r" is a blinding factor
        let mut c_0: RistrettoPoint;
        let mut c_x: RistrettoPoint;
        let mut ring: Vec<RistrettoPoint>;

        for i in 0..NUMBER_OF_PROOF_DIGITS {
            //pick r value for current digit
            if i == digits.len() - 1 {
                let r_total: Scalar = r.iter().sum();
                r_i = blinding - r_total;
            } else {
                r_i = random_scalar();
            }
            r.push(r_i);

            //create the H = 0 and H = x commitments
            c_0 = &r_i * &*PEDERSEN_G;
            c_x = c_0 + BORROMEAN_H_TABLE.positive[i][digits[i]];
            c[i] = c_x;

            //create the rest of the ring members
            ring = vec!(c_x);
            for j in 1..4 {
                if j == digits[i] {
                    ring.push(c_0);
                } else {
                    ring.push(BORROMEAN_H_TABLE.negative[i][j] + c_x);
                }
            }
            rings.push(ring);
        }

        //final commitment
        let c_total: RistrettoPoint = c.iter().sum();
        let c_i = match Commitment::from_ristretto(c.to_vec()).try_into() {
            Ok(c_i) => c_i,
            Err(_) => return Err(
                RangeProofError::Unspecified("failed to convert commitment vector to array"
            .to_string()))
        };

        return Ok((Commitment(c_total), Self {
            c_i,
            sig: borromean_sign(&rings, &r, digits.to_vec(), &encode_point(&c_total))
        } ));
    }

    ///Verify a Borromean rangeproof given its associated commitments.
    ///
    ///Returns `Ok()` if the proof is valid,
    ///or `Err(RangeProofError)` if it's invalid.
    pub fn verify(commitment: Commitment, proof: BorromeanRangeProof
    ) -> Result<(), RangeProofError> {
        let BorromeanRangeProof {c_i, sig: proof} = proof;

        //check if the bit-commitments equal the total commitment
        let commitments = Commitment::to_ristretto(c_i.to_vec());
        if commitment.0 != commitments.iter().sum() {
            return Err(RangeProofError::Invalid)
        }

        let mut rings: Vec<Vec<RistrettoPoint>> = Vec::new();
        for i in 0..c_i.len() {
            rings.push(vec!(
                commitments[i],
                BORROMEAN_H_TABLE.negative[i][1] + commitments[i],
                BORROMEAN_H_TABLE.negative[i][2] + commitments[i],
                BORROMEAN_H_TABLE.negative[i][3] + commitments[i]
            ))
        }

        return borromean_verify(&rings, &proof, &encode_point(&commitment.0))
    }

} #[cfg(feature = "to_bytes")] impl ToBytes<'_> for BorromeanRangeProof {}
