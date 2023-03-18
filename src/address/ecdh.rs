/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

//! [Elliptic Curve Diffie Hellman (ECDH)](https://en.wikipedia.org/wiki/Elliptic-curve_Diffie%E2%80%93Hellman) related functions.

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

} impl ToBytes<'_> for SharedSecret {
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


///Implements ECDH private key methods for `Scalar`
pub trait ECDHPrivateKey {
    fn to_public_with_base(&self, base: RistrettoPoint) -> RistrettoPoint;
    fn to_public(&self) -> RistrettoPoint;
    fn shared_secret(&self, other_public: &RistrettoPoint) -> SharedSecret;
    fn derive_key_with_base(&self, shared_secret: SharedSecret, base: RistrettoPoint) -> Self;
    fn derive_key(&self, shared_secret: SharedSecret) -> Self;
    fn from_seed(bytes: [u8; 32]) -> Self;

} impl ECDHPrivateKey for Scalar {
    ///Convert this private key into a public key, with a custom basepoint.
    ///**These keys should never be reused.**
    fn to_public_with_base(&self, base: RistrettoPoint) -> RistrettoPoint {
        return self * base
    }

    ///Convert this private key into a public key.
    ///**These keys should never be reused.**
    fn to_public(&self) -> RistrettoPoint {
        return self * G
    }

    ///Given a public key, calculate the "shared secret" of these keys.
    fn shared_secret(&self, other_public: &RistrettoPoint) -> SharedSecret {
        return SharedSecret::get(*self, &other_public)
    }

    ///Deterministically derive a unique ephemeral private key given a shared secret.
    ///**These keys should never be reused.**
    ///
    ///Note that the `base` parameter is not used in this function,
    ///and only included for consistency purposes.
    #[allow(unused_variables)]
    fn derive_key_with_base(&self, shared_secret: SharedSecret, base: RistrettoPoint) -> Self {
        return self.derive_key(shared_secret)
    }

    ///Deterministically derive a unique ephemeral private key given a shared secret.
    ///**These keys should never be reused.**
    fn derive_key(&self, shared_secret: SharedSecret) -> Self {
        return self + shared_secret.as_scalar()
    }

    ///Deterministically convert a seed into a private key.
    fn from_seed(bytes: [u8; 32]) -> Self {
        return domain_h_scalar(&bytes, domains::ECDH_PRIVATE_KEY)
    }
}


///Implements ECDH public key methods for `RistrettoPoint`
pub trait ECDHPublicKey {
    fn shared_secret(&self, other_private: Scalar) -> SharedSecret;
    fn derive_key_with_base(&self, shared_secret: SharedSecret, base: RistrettoPoint) -> Self;
    fn derive_key(&self, shared_secret: SharedSecret) -> Self;

} impl ECDHPublicKey for RistrettoPoint {
    ///Given a private key, calculate the "shared secret" of these keys.
    fn shared_secret(&self, other_private: Scalar) -> SharedSecret {
        return SharedSecret::get(other_private, &self)
    }

    ///Deterministically derive a unique ephemeral public key given a shared secret and a custom basepoint.
    ///**These keys should never be reused.**
    fn derive_key_with_base(&self, shared_secret: SharedSecret, base: RistrettoPoint) -> Self {
        return self + (shared_secret.as_scalar() * base)
    }

    ///Derive the unique ephemeral public key given a shared secret.
    ///**These keys should never be reused.**
    fn derive_key(&self, shared_secret: SharedSecret) -> Self {
        return self + (&shared_secret.as_scalar() * G)
    }
}