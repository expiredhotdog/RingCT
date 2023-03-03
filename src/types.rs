/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

use std::iter::Sum;

use crate::tobytes::*;
use crate::curve::*;
use crate::pedersen::*;
use crate::signature::{
    encode_rings,
    separate_ring,
    ring_as_sorted,
    ring_is_sorted,
    get_key_image
};

use zeroize::Zeroize;

///A pedersen commitment
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct Commitment(
    pub RistrettoPoint

); impl Commitment {
    ///create a commitment to `value` with blinding factor `blinding`
    pub fn commit(value: u64, blinding: Scalar) -> Self {
        //(r * G) + (v * H)
        return Self(
            (&blinding * &*PEDERSEN_G) + (&Scalar::from(value) * &*PEDERSEN_H)
        )
    }

    ///Return the elliptic curve point which represents this commitment.
    ///To convert an elliptic curve point back into a commitment, use `Commitment(point)`.
    pub fn to_point(&self) -> RistrettoPoint {
        return self.0;
    }

    ///Given input commitments, output commitments, and "extra" output (ie fees),
    ///check if the equation is balanced.
    ///
    ///`in == (out + extra)`
    pub fn is_balanced(in_commitments: Vec<Commitment>, out_commitments: Vec<Commitment>, extra: u64) -> bool {
        let out = [ out_commitments, vec!(Commitment(&Scalar::from(extra) * &*PEDERSEN_H)) ].concat();
        return Commitment::sum(in_commitments.into_iter()) == Commitment::sum(out.into_iter())
    }

    ///given a `Vec` of commitments, convert them into `RistrettoPoint`'s
    pub(crate) fn to_ristretto(commitments: Vec<Commitment>) -> Vec<RistrettoPoint> {
        return commitments.into_iter().map(|com| com.0).collect();
    }

    ///given a `Vec` of `RistrettoPoint`'s, convert them into commitments
    pub(crate) fn from_ristretto(commitments: Vec<RistrettoPoint>) -> Vec<Commitment> {
        return commitments.into_iter().map(|com| Commitment(com)).collect();
    }

} impl Sum for Commitment {
    fn sum<I: Iterator<Item = Self>>(iter: I) -> Self {
        return Commitment(RistrettoPoint::sum(
            iter.map(|com| com.to_point()).collect::<Vec<RistrettoPoint>>().iter()))
    }
}

#[cfg(feature = "to_bytes")] impl ToBytes<'_> for Commitment {
    fn to_bytes(&self) -> Result<Vec<u8>, SerializationError> {
        return Ok(self.0.compress().to_bytes().to_vec())
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self, SerializationError> {
        return match CompressedRistretto::from_slice(bytes).decompress() {
            Some(point) => Ok(Self(point)),
            None => Err(SerializationError::DecodingError)
        };
    }
}

///The "private keys" of an Enote.
/// * `owner`: The private key of the public key which owns the Enote
/// * `value`: The value of the Enote's commitment
/// * `blinding`: The blinding factor of the Enote's commitment
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Zeroize)]
pub struct EnoteKeys {
    pub owner: Scalar,
    pub value: u64,
    pub blinding: Scalar

} impl EnoteKeys {
    ///Create an EnoteKeys instance given an owning private key, a value, and a blinding factor
    pub fn new(key: Scalar, value: u64, blinding: Scalar) -> Self {
        return Self{
            owner: key, value, blinding
        };
    }

    ///Turn these (private) EnoteKeys into a (public) Enote
    pub fn to_enote(&self) -> Enote {
        return Enote::new(
            &self.owner * G,
            Commitment::commit(self.value, self.blinding),
        )
    }

    ///Return the key image of this enote
    pub fn get_key_image(&self) -> RistrettoPoint {
        return get_key_image(self.owner)
    }

} impl Drop for EnoteKeys{
    fn drop(&mut self) {
        //clear the keys from memory to improve security
        self.zeroize()
    }

} #[cfg(feature = "to_bytes")] impl ToBytes<'_> for EnoteKeys {}

///An enote represents a public key and the RingCT commitment that it is associated with.
///
///These are sometimes referred to as "outputs", but are always called "enotes" in this library.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct Enote {
    pub owner: RistrettoPoint,
    pub commitment: Commitment

} impl Enote {
    ///Given an owner and a commitment, return an Enote
    pub fn new(owner: RistrettoPoint, commitment: Commitment) -> Self {
        return Self{owner, commitment}
    }

} #[cfg(feature = "to_bytes")] impl ToBytes<'_> for Enote {}

///A Ring represents a vector of Enotes in a ring signature.
///
///This is a wrapper type for `Vec<Enote>`.
///The internal `Vec` can be accessed with `ring.0`.
///Some methods have been implemented for this type.
pub struct Ring(pub Vec<Enote>);
impl Ring {
    ///Creates a new, empty ring.
    pub fn new() -> Self {
        return Self(Vec::new());
    }

    ///Appends an enote to the ring.
    pub fn push(&mut self, value: Enote) {
        self.0.push(value);
    }

    ///Inserts an enote at position `index` within the ring, shifting all enotes after it to the right.
    pub fn insert(&mut self, index: usize, element: Enote) {
        self.0.insert(index, element);
    }

    //Sorts the ring and removes duplicates
    pub fn sort(&mut self) {
        let [ring_l, ring_c] = separate_ring(&self);
        let (ring_l, ring_c) = encode_rings(ring_l, ring_c);
        self.0 = ring_as_sorted(&self, &ring_l, &ring_c).0;
    }

    //Checks if the ring is sorted
    pub fn is_sorted(self) -> bool {
        let [ring_l, ring_c] = separate_ring(&self);
        let (ring_l, ring_c) = encode_rings(ring_l, ring_c);
        return ring_is_sorted(&self, &ring_l, &ring_c)
    }
}

///A 1-byte public tag used to quickly eliminate an ECDH `SharedSecret` if the keys do not match.
///
///This can be used to improve scanning speeds:
///Items whose view tags which do not match the one expected
///are discarded so we don't have to waste any more time on them.
///
///Note that this does not guarantee that the keys match.
///There is a 1/256 chance of a false positive, but zero chance of a false negative.
pub type ViewTag = u8;
