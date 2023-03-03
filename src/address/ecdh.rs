/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

//! [Elliptic Curve Diffie Hellman (ECDH)](https://en.wikipedia.org/wiki/Elliptic-curve_Diffie%E2%80%93Hellman) related functions.

use std::ops::Add;

use crate::internal_common::*;
use zeroize::Zeroize;


///Shared secret between two keys, `A` and `B`.
///This can be calculated by having the private key of `A` and the public key of `B`,
///or the private key of `B` and the public key of `A`.
///Without the private key to at least one of these keys,
///it is impossible to determine the shared secret between `A` and `B`.
///
///To calculate a shared secret, use `ECDHPrivateKey` and `ECDHPublicKey`.
///
///**This should not be publically shared.**
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Zeroize)]
pub struct SharedSecret(
    [u8; 32]

); impl SharedSecret {
    ///Import point
    pub(crate) fn from_point(point: &RistrettoPoint) -> Self {
        return Self(point.compress().to_bytes())
    }

    ///Given a user's one-time private key (`my_private`),
    ///and another user's public key (`other_public`),
    ///create a unique one-time shared secret that only those 2 users know.
    pub(crate) fn get(my_private: Scalar, other_public: &RistrettoPoint) -> Self {
        return Self::from_point(&(my_private * other_public))
    }

    ///Calculate the view tag associated with this shared secret.
    pub fn get_view_tag(&self) -> ViewTag {
        return domain_h_bytes(&self.0, domains::ECDH_VIEW_TAG)[0]
    }

    ///Convert this shared secret to a scalar.
    pub fn as_scalar(&self) -> Scalar {
        return Scalar::from_bytes_mod_order(self.0)
    }

    ///Encrypt an amount (`u64`) with this shared secret.
    pub fn encrypt_amount(&self, amount: u64) -> u64 {
        //amount is XOR'ed
        return amount ^ u64::from_be_bytes(
            domain_h_bytes(&self.0, domains::ECDH_ENCRYPTION_KEY)[0..8]
            .try_into().expect("Failed to convert shared secret to u64 encryption key"))
    }

    ///Decrypt an amount (`u64`) with this shared secret.
    pub fn decrypt_amount(&self, encrypted_amount: u64) -> u64 {
        self.encrypt_amount(encrypted_amount)
    }

} impl Drop for SharedSecret {
    fn drop(&mut self) {
        self.zeroize()
    }

} #[cfg(feature = "to_bytes")] impl ToBytes<'_> for SharedSecret {
    fn to_bytes(&self) -> Result<Vec<u8>, SerializationError> {
        return Ok(self.0.to_vec())
    }

    fn from_bytes<'a>(bytes: &'a [u8]) -> Result<Self, SerializationError> {
        return match bytes.try_into() {
            Ok(secret) => Ok(Self(secret)),
            Err(_) => Err(SerializationError::DecodingError)
        }
    }
}


///Private key used in ECDH exchanges.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Zeroize)]
pub struct ECDHPrivateKey (
    Scalar

); impl ECDHPrivateKey {
    ///Convert this private key into a public key, with a custom basepoint.
    ///**These keys should never be reused.**
    pub fn to_public_with_base(&self, base: RistrettoPoint) -> ECDHPublicKey {
        return ECDHPublicKey(self.as_scalar() * base)
    }

    ///Convert this private key into a public key.
    ///**These keys should never be reused.**
    pub fn to_public(&self) -> ECDHPublicKey {
        return ECDHPublicKey(&self.as_scalar() * G)
    }

    ///Given a public key, calculate the "shared secret" of these keys.
    pub fn shared_secret(&self, other_public: &ECDHPublicKey) -> SharedSecret {
        return SharedSecret::get(self.as_scalar(), &other_public.as_point())
    }

    ///Deterministically derive a unique ephemeral private key given a shared secret.
    ///**These keys should never be reused.**
    ///
    ///Note that the `base` parameter is not used in this function,
    ///and only included for consistency purposes.
    #[allow(unused_variables)]
    pub fn derive_key_with_base(&self, shared_secret: SharedSecret, base: RistrettoPoint) -> ECDHPrivateKey {
        return self.derive_key(shared_secret)
    }

    ///Deterministically derive a unique ephemeral private key given a shared secret.
    ///**These keys should never be reused.**
    pub fn derive_key(&self, shared_secret: SharedSecret) -> ECDHPrivateKey {
        return Self(self.as_scalar() + shared_secret.as_scalar())
    }

    ///Generate a random new private key.
    pub fn generate() -> Self {
        return Self(random_scalar())
    }

    ///Deterministically convert a seed into a private key.
    pub fn from_seed(bytes: [u8; 32]) -> Self {
        return Self(domain_h_scalar(&bytes, domains::ECDH_PRIVATE_KEY))
    }

    ///Deterministically convert a scalar into a private key.
    pub fn from_scalar(scalar: Scalar) -> Self {
        return Self(scalar)
    }

    ///Convert this private key to a scalar.
    pub fn as_scalar(&self) -> Scalar {
        return self.0
    }

} impl Add for ECDHPrivateKey {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        return Self::from_scalar(self.as_scalar() + rhs.as_scalar())
    }

} impl Drop for ECDHPrivateKey {
    fn drop(&mut self) {
        self.zeroize()
    }

} #[cfg(feature = "to_bytes")] impl ToBytes<'_> for ECDHPrivateKey {
    fn to_bytes(&self) -> Result<Vec<u8>, SerializationError> {
        return Ok(self.0.to_bytes().to_vec())
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self, SerializationError> {
        return Ok(Self(Scalar::from_bytes(bytes)?))
    }
}


///Public key used in ECDH exchanges.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct ECDHPublicKey (
    RistrettoPoint

); impl ECDHPublicKey {
    ///Given a private key, calculate the "shared secret" of these keys.
    pub fn shared_secret(&self, other_private: ECDHPrivateKey) -> SharedSecret {
        return SharedSecret::get(other_private.as_scalar(), &self.as_point())
    }

    ///Deterministically derive a unique ephemeral public key given a shared secret and a custom basepoint.
    ///**These keys should never be reused.**
    pub fn derive_key_with_base(&self, shared_secret: SharedSecret, base: RistrettoPoint) -> ECDHPublicKey {
        return Self(self.as_point() + (shared_secret.as_scalar() * base))
    }

    ///Derive the unique ephemeral public key given a shared secret.
    ///**These keys should never be reused.**
    pub fn derive_key(&self, shared_secret: SharedSecret) -> ECDHPublicKey {
        return Self(self.as_point() + (&shared_secret.as_scalar() * G))
    }

    ///Deterministically convert a point into a private key.
    pub fn from_point(point: RistrettoPoint) -> Self {
        return Self(point)
    }

    ///Convert this public key to an elliptic curve point.
    pub fn as_point(&self) -> RistrettoPoint {
        return self.0
    }

} impl Add for ECDHPublicKey {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        return Self::from_point(self.as_point() + rhs.as_point())
    }

} #[cfg(feature = "to_bytes")] impl ToBytes<'_> for ECDHPublicKey {
    fn to_bytes(&self) -> Result<Vec<u8>, SerializationError> {
        return self.as_point().to_bytes();
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self, SerializationError> {
        return Ok(Self(RistrettoPoint::from_bytes(bytes)?));
    }
}
