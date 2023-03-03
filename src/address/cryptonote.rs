/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

//! Cryptonote-style stealth addresses

use zeroize::Zeroize;

use crate::internal_common::*;
use super::ecdh::*;

///Private keys of CryptoNote address.
///
///These keys can view *and* spend funds sent to this "wallet"
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Zeroize)]
pub struct CryptoNotePrivate {
    pub view: ECDHPrivateKey,
    pub spend: ECDHPrivateKey

} impl CryptoNotePrivate {
    ///Convert this private key into a public key.
    pub fn to_public(&self) -> CryptoNotePublic {
        return CryptoNotePublic {
            view: self.view.to_public(),
            spend: self.spend.to_public()
        }
    }

    ///Convert this private key into a view-only private key.
    pub fn to_view_only(&self) -> CryptoNotePrivateView {
        return CryptoNotePrivateView {
            view: self.view.to_owned(),
            spend: self.spend.to_public()
        }
    }

    ///Given a public key, calculate the "shared secret" of these keys.
    ///
    ///**The public key should not be reused.**
    pub fn shared_secret(&self, other_public: &ECDHPublicKey) -> SharedSecret {
        return SharedSecret::get(self.view.as_scalar(), &other_public.as_point())
    }

    ///Deterministically derive a unique ephemeral private key given a shared secret.
    ///**These keys should never be reused.**
    pub fn derive_key(&self, shared_secret: SharedSecret) -> ECDHPrivateKey {
        return ECDHPrivateKey::from_scalar(self.spend.as_scalar() + shared_secret.as_scalar())
    }

    ///Generate a random new private key.
    pub fn generate() -> Self {
        return Self {
            view: ECDHPrivateKey::from_scalar(random_scalar()),
            spend: ECDHPrivateKey::from_scalar(random_scalar())
        }
    }

    ///Deterministically convert a seed into a CryptoNote private key.
    pub fn from_seed(bytes: [u8; 32]) -> Self {
        return Self {
            view: ECDHPrivateKey::from_scalar(
                domain_h_scalar(&bytes, domains::CRYPTONOTE_PRIVATE_VIEW)),
            spend: ECDHPrivateKey::from_scalar(
                domain_h_scalar(&bytes, domains::CRYPTONOTE_PRIVATE_SPEND))
        }
    }

} impl Drop for CryptoNotePrivate {
    fn drop(&mut self) {
        self.zeroize()
    }

} #[cfg(feature = "to_bytes")] impl ToBytes<'_> for CryptoNotePrivate {
    fn to_bytes(&self) -> Result<Vec<u8>, SerializationError> {
        return Ok([self.view.to_bytes()?, self.spend.to_bytes()?].concat())
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self, SerializationError> {
        if bytes.len() != 64 {
            return Err(SerializationError::DecodingError)
        }

        return Ok(Self{
            view: ECDHPrivateKey::from_bytes(&bytes[0..32])?,
            spend: ECDHPrivateKey::from_bytes(&bytes[32..64])?
        })
    }
}


///Private view-only key of CryptoNote address.
///
///This key can only *view* funds sent to this "wallet"
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CryptoNotePrivateView {
    pub view: ECDHPrivateKey,
    pub spend: ECDHPublicKey

} impl CryptoNotePrivateView {
    ///Convert this private key into a public key.
    pub fn to_public(&self) -> CryptoNotePublic {
        return CryptoNotePublic {
            view: self.view.to_public(),
            spend: self.spend
        }
    }

    ///Given a public key, calculate the "shared secret" of these keys.
    ///
    ///**The public key should not be reused.**
    pub fn shared_secret(&self, other_public: &ECDHPublicKey) -> SharedSecret {
        return SharedSecret::get(self.view.as_scalar(), &other_public.as_point())
    }

    ///Deterministically derive a unique ephemeral private key given a shared secret.
    ///**These keys should never be reused.**
    pub fn derive_key(&self, shared_secret: SharedSecret) -> ECDHPublicKey {
        return ECDHPublicKey::from_point(self.spend.as_point() + (&shared_secret.as_scalar() * G))
    }

    ///Create a new viewing keypair from the private view key and public spend key
    pub fn from_keys(private_view: ECDHPrivateKey, public_spend: ECDHPublicKey) -> Self {
        return Self {
            view: private_view,
            spend: public_spend
        }
    }

} impl Zeroize for CryptoNotePrivateView {
    fn zeroize(&mut self) {
        self.view.zeroize();
    }

} impl Drop for CryptoNotePrivateView {
    fn drop(&mut self) {
        self.zeroize()
    }

} #[cfg(feature = "to_bytes")] impl ToBytes<'_> for CryptoNotePrivateView {
    fn to_bytes(&self) -> Result<Vec<u8>, SerializationError> {
        return Ok([self.view.to_bytes()?, self.spend.to_bytes()?].concat())
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self, SerializationError> {
        if bytes.len() != 64 {
            return Err(SerializationError::DecodingError)
        }

        return Ok(Self{
            view: ECDHPrivateKey::from_bytes(&bytes[0..32])?,
            spend: ECDHPublicKey::from_bytes(&bytes[32..64])?
        })
    }
}


///Public keys of CryptoNote address.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct CryptoNotePublic {
    pub view: ECDHPublicKey,
    pub spend: ECDHPublicKey

} impl CryptoNotePublic {
    ///Given a private key, calculate the "shared secret" of these keys.
    ///
    ///**The private key should not be reused.**
    ///
    ///The recipient will need the public key of `other_private` to recreate this secret.
    pub fn shared_secret(&self, other_private: ECDHPrivateKey) -> SharedSecret {
        return SharedSecret::get(other_private.as_scalar(), &self.view.as_point())
    }

    ///Derive the unique ephemeral public key given a shared secret.
    ///**These keys should never be reused.**
    pub fn derive_key(&self, shared_secret: SharedSecret) -> ECDHPublicKey {
        return ECDHPublicKey::from_point(
            self.spend.as_point() + (&shared_secret.as_scalar() * G))
    }

} #[cfg(feature = "to_bytes")] impl ToBytes<'_> for CryptoNotePublic {
    fn to_bytes(&self) -> Result<Vec<u8>, SerializationError> {
        return Ok([self.view.to_bytes()?, self.spend.to_bytes()?].concat())
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self, SerializationError> {
        if bytes.len() != 64 {
            return Err(SerializationError::DecodingError)
        }

        return Ok(Self{
            view: ECDHPublicKey::from_bytes(&bytes[0..32])?,
            spend: ECDHPublicKey::from_bytes(&bytes[32..64])?
        })
    }
}