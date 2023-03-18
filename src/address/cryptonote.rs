/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

//! Cryptonote-style stealth addresses

use zeroize::Zeroize;

use crate::internal_common::*;
use super::{
    ecdh::*,
    Recipient
};

///Private keys of CryptoNote address.
///
///These keys can view *and* spend funds sent to this "wallet"
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Zeroize)]
pub struct CryptoNotePrivate {
    pub view: Scalar,
    pub spend: Scalar

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
    pub fn shared_secret(&self, other_public: &RistrettoPoint) -> SharedSecret {
        return SharedSecret::get(self.view, &other_public)
    }

    ///Deterministically derive a unique ephemeral private key given a shared secret.
    ///**These keys should never be reused.**
    pub fn derive_key(&self, shared_secret: SharedSecret) -> Scalar {
        return self.spend + shared_secret.as_scalar()
    }

    ///Generate a random new private key.
    pub fn generate() -> Self {
        return Self {
            view: Scalar::generate(),
            spend: Scalar::generate()
        }
    }

    ///Deterministically convert a seed into a CryptoNote private key.
    pub fn from_seed(bytes: [u8; 32]) -> Self {
        return Self {
            view: domain_h_scalar(&bytes, domains::CRYPTONOTE_PRIVATE_VIEW),
            spend: domain_h_scalar(&bytes, domains::CRYPTONOTE_PRIVATE_SPEND)
        }
    }

    ///"Receive" a payment, decrypting its content, given the pedersen commitment.
    ///
    ///Returns `Some(EnoteKeys)` if the enote belongs to these keys, or `None` if not.
    pub fn receive(&self, recipient: &Recipient, commitment: &Commitment) -> Option<EnoteKeys> {
        if let Some(transaction_key) = recipient.transaction_key {
            return self.receive_internal(recipient, commitment, transaction_key)
        };
        return None
    }

    ///"Receive" a payment, decrypting its content, given the pedersen commitment and a transaction/ECDH key.
    ///
    ///Returns `Some(EnoteKeys)` if the enote belongs to these keys, or `None` if not.
    pub fn receive_with_key(
        &self, recipient: &Recipient, commitment: &Commitment, transaction_key: RistrettoPoint
    ) -> Option<EnoteKeys> {
        return self.receive_internal(recipient, commitment, transaction_key)
    }

    ///Internal receiving functionality
    fn receive_internal(
        &self, recipient: &Recipient, commitment: &Commitment, transaction_key: RistrettoPoint
    ) -> Option<EnoteKeys> {
        //check view tag
        let shared_secret = self.shared_secret(&transaction_key);
        if shared_secret.get_view_tag() != recipient.view_tag {
            return None
        }

        //check public key
        let owner = self.derive_key(shared_secret.clone());
        if &owner * G != recipient.public_key {
            return None
        }

        //check commitment
        let value = shared_secret.decrypt_amount(recipient.encrypted_amount);
        let blinding = shared_secret.as_scalar();
        if Commitment::commit(value, blinding) != *commitment {
            return None
        }

        return Some(EnoteKeys{
            owner,
            value,
            blinding
        })
    }

} impl Drop for CryptoNotePrivate {
    fn drop(&mut self) {
        self.zeroize()
    }

} impl ToBytes<'_> for CryptoNotePrivate {
    fn to_bytes(&self) -> Result<Vec<u8>, SerializationError> {
        return Ok([self.view.to_bytes(), self.spend.to_bytes()].concat())
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self, SerializationError> {
        if bytes.len() != 64 {
            return Err(SerializationError::DecodingError)
        }

        return Ok(Self{
            view: Scalar::from_bytes(&bytes[0..32])?,
            spend: Scalar::from_bytes(&bytes[32..64])?
        })
    }
}


///Private view-only key of CryptoNote address.
///
///This key can only *view* funds sent to this "wallet"
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CryptoNotePrivateView {
    pub view: Scalar,
    pub spend: RistrettoPoint

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
    pub fn shared_secret(&self, other_public: &RistrettoPoint) -> SharedSecret {
        return SharedSecret::get(self.view, &other_public)
    }

    ///Deterministically derive a unique ephemeral private key given a shared secret.
    ///**These keys should never be reused.**
    pub fn derive_key(&self, shared_secret: SharedSecret) -> RistrettoPoint {
        return self.spend + (&shared_secret.as_scalar() * G)
    }

    ///Create a new viewing keypair from the private view key and public spend key
    pub fn from_keys(private_view: Scalar, public_spend: RistrettoPoint) -> Self {
        return Self {
            view: private_view,
            spend: public_spend
        }
    }

    ///"Receive" a payment, decrypting its content, given the pedersen commitment.
    ///
    ///Returns the amount and blinding factor of the pedersen commitment if the enote belongs to these keys, or `None` if not.
    pub fn receive(&self, recipient: &Recipient, commitment: &Commitment) -> Option<(u64, Scalar)> {
        if let Some(transaction_key) = recipient.transaction_key {
            return self.receive_internal(recipient, commitment, transaction_key)
        };
        return None
    }

    ///"Receive" a payment, decrypting its content, given the pedersen commitment and a transaction/ECDH key.
    ///
    ///Returns the amount and blinding factor of the pedersen commitment if the enote belongs to these keys, or `None` if not.
    pub fn receive_with_key(
        &self, recipient: &Recipient, commitment: &Commitment, transaction_key: RistrettoPoint,
    ) -> Option<(u64, Scalar)> {
        return self.receive_internal(recipient, commitment, transaction_key)
    }

    ///Internal receiving functionality
    fn receive_internal(
        &self, recipient: &Recipient,commitment: &Commitment, transaction_key: RistrettoPoint,
    ) -> Option<(u64, Scalar)> {
        //check view tag
        let shared_secret = self.shared_secret(&transaction_key);
        if shared_secret.get_view_tag() != recipient.view_tag {
            return None
        }

        //check public key
        if self.derive_key(shared_secret.clone()) != recipient.public_key {
            return None
        }

        //check commitment
        let value = shared_secret.decrypt_amount(recipient.encrypted_amount);
        let blinding = shared_secret.as_scalar();
        if Commitment::commit(value, blinding) != *commitment {
            return None
        }

        return Some((value, blinding))
    }

} impl Zeroize for CryptoNotePrivateView {
    fn zeroize(&mut self) {
        self.view.zeroize();
    }

} impl Drop for CryptoNotePrivateView {
    fn drop(&mut self) {
        self.zeroize()
    }

} impl ToBytes<'_> for CryptoNotePrivateView {
    fn to_bytes(&self) -> Result<Vec<u8>, SerializationError> {
        return Ok([self.view.to_bytes(), self.spend.compress().to_bytes()].concat())
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self, SerializationError> {
        if bytes.len() != 64 {
            return Err(SerializationError::DecodingError)
        }

        return Ok(Self{
            view: Scalar::from_bytes(&bytes[0..32])?,
            spend: RistrettoPoint::from_bytes(&bytes[32..64])?
        })
    }
}


///Public keys of CryptoNote address.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct CryptoNotePublic {
    pub view: RistrettoPoint,
    pub spend: RistrettoPoint

} impl CryptoNotePublic {
    ///Given a private key, calculate the "shared secret" of these keys.
    ///
    ///**The private key should not be reused.**
    ///
    ///The recipient will need the public key of `other_private` to recreate this secret.
    pub fn shared_secret(&self, other_private: Scalar) -> SharedSecret {
        return SharedSecret::get(other_private, &self.view)
    }

    ///Derive the unique ephemeral public key given a shared secret.
    ///**These keys should never be reused.**
    pub fn derive_key(&self, shared_secret: SharedSecret) -> RistrettoPoint {
        return self.spend + (&shared_secret.as_scalar() * G)
    }

    ///"Send" to this address, where only the recipient can detect that the payment is for them.
    ///
    ///The transaction/ECDH key is generated automatically.
    ///Use `send_with_key` instead to manually input a transaction key.
    ///
    ///Returns the blinding factor of the pedersen commitment (for use in a rangeproof),
    ///and the public data for the receiver to detect the payment.
    pub fn send(&self, amount: u64) -> (Scalar, Recipient) {
        let seed = batch_encode_points(&vec!(self.view, self.spend)).concat();
        let seed = h_scalar(&[seed, amount.to_le_bytes().to_vec()].concat());
        let key = seed + Scalar::generate();
        self.send_internal(amount, key, true)
    }

    ///"Send" to this address, given a transaction/ECDH key,
    ///where only the recipient can detect that the payment is for them.
    ///
    ///Note that `receive_with_key` must be used to receive payments created by this method.
    ///For automatic transaction key generation, used `send` instead.
    ///
    ///Returns the blinding factor of the pedersen commitment (for use in a rangeproof),
    ///and the public data for the receiver to detect the payment.
    pub fn send_with_key(&self, amount: u64, transaction_key: Scalar) -> (Scalar, Recipient) {
        self.send_internal(amount, transaction_key, false)
    }

    ///Internal sending functionality
    fn send_internal(&self, amount: u64, transaction_sk: Scalar, include_txn_key: bool) -> (Scalar, Recipient) {
        let transaction_key = match include_txn_key {
            true => Some(&transaction_sk * G),
            false => None
        };

        let shared_secret = self.shared_secret(transaction_sk);
        let view_tag = shared_secret.get_view_tag();
        let encrypted_amount = shared_secret.encrypt_amount(amount);
        let blinding = shared_secret.as_scalar();

        let recipient = Recipient {
            public_key: self.derive_key(shared_secret),
            transaction_key,
            view_tag,
            encrypted_amount
        };
        return (blinding, recipient)
    }

} impl ToBytes<'_> for CryptoNotePublic {
    fn to_bytes(&self) -> Result<Vec<u8>, SerializationError> {
        return Ok([self.view.to_bytes()?, self.spend.to_bytes()?].concat())
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self, SerializationError> {
        if bytes.len() != 64 {
            return Err(SerializationError::DecodingError)
        }

        return Ok(Self{
            view: RistrettoPoint::from_bytes(&bytes[0..32])?,
            spend: RistrettoPoint::from_bytes(&bytes[32..64])?
        })
    }
}