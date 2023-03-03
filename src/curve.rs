/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

//! Elliptic curve functions and constants

#[cfg(feature = "to_bytes")]
use crate::errors::SerializationError;
#[cfg(feature = "to_bytes")]
use crate::tobytes::*;

pub use curve25519_dalek::{
    constants,
    scalar::Scalar,
    ristretto::{
        RistrettoPoint,
        CompressedRistretto,
        RistrettoBasepointTable,
        VartimeRistrettoPrecomputation
    },
    traits::{
        MultiscalarMul,
        VartimeMultiscalarMul,
        VartimePrecomputedMultiscalarMul
    }
};
use rand::{thread_rng, Rng};

///The basepoint of the elliptic curve.
///`G` is a precomputed table of values, not an EC point, in order to speed up operations.
///To access the EC point itself, use `G_POINT`.
pub const G: &RistrettoBasepointTable = &constants::RISTRETTO_BASEPOINT_TABLE;
///The basepoint of the elliptic curve.
///`G_POINT` is the actual EC point, whereas `G` is a precomputed table of values for faster operations.
pub const G_POINT: RistrettoPoint = constants::RISTRETTO_BASEPOINT_POINT;

lazy_static! {
    pub(crate) static ref G_MULTISCALAR_MUL: VartimeRistrettoPrecomputation = VartimeRistrettoPrecomputation::new(vec!(G_POINT));
}

///Encode a point to byte array for hashing purposes.
///
///Though possible, this is not intended to be reversible:
///if you wish to "decode" back to a point,
///then use the methods provided by `ToBytes` instead.
///
///You should use `batch_encode_points` when encoding multiple points,
///as that is much more efficient.
///Note that `batch_encode_points` may return different bytes than `encode_point` for the same point due to how batching is done.
pub fn encode_point(point: &RistrettoPoint) -> [u8; 32] {
    return point.compress().to_bytes()
}

///Efficient batch encoding for multiple points to byte arrays for hashing purposes.
///
///Though possible, this is not intended to be reversible:
///if you wish to "decode" back to a point,
///then use the methods provided by `ToBytes` instead.
pub fn batch_encode_points(points: &Vec<RistrettoPoint>) -> Vec<[u8; 32]> {
    let mut encoded: Vec<[u8; 32]> = Vec::new();
    for point in RistrettoPoint::double_and_compress_batch(points) {
        encoded.push(point.to_bytes());
    }
    return encoded
}

///return a random scalar
pub fn random_scalar() -> Scalar {
    let mut scalar_bytes = [0u8; 64];
    thread_rng().fill(&mut scalar_bytes[..]);
    return Scalar::from_bytes_mod_order_wide(&scalar_bytes);
}

///return a random point on the curve
pub fn random_point() -> RistrettoPoint {
    return &random_scalar() * G;
}

#[cfg(feature = "to_bytes")]
impl ToBytes<'_> for Scalar {
    fn to_bytes(&self) -> Result<Vec<u8>, SerializationError> {
        return Ok(self.reduce().to_bytes().to_vec())
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self, SerializationError> {
        return match bytes.try_into() {
            Ok(bytes) => {
                match Scalar::from_canonical_bytes(bytes) {
                    Some(scalar) => Ok(scalar),
                    None => Err(SerializationError::DecodingError)
                }
            },
            Err(_) => Err(SerializationError::DecodingError)
        }
    }
}

#[cfg(feature = "to_bytes")]
impl ToBytes<'_> for RistrettoPoint {
    fn to_bytes(&self) -> Result<Vec<u8>, SerializationError> {
        return Ok(self.compress().to_bytes().to_vec());
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self, SerializationError> {
        if bytes.len() != 32 {
            return Err(SerializationError::DecodingError)
        }

        return match CompressedRistretto::from_slice(bytes).decompress() {
            Some(point) => Ok(point),
            None => Err(SerializationError::DecodingError)
        };
    }
}