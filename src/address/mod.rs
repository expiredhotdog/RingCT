/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

mod ecdh;
use crate::internal_common::*;

pub use ecdh::{
    ECDHPrivateKey,
    ECDHPublicKey,
    SharedSecret
};
pub mod cryptonote;
pub mod subaddress;

///A recipient in a transaction.
///Contains the public key, as well as the necessary information for the recipient to retrieve the private keys.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Recipient {
    ///Public key of the Enote
    pub public_key: RistrettoPoint,
    ///Transaction key used by the recipient to "detect" that they received a payment.
    ///
    ///Some protocols require that each recipient has their own transaction key,
    ///others can use one key for all recipients.
    pub transaction_key: Option<RistrettoPoint>,
    ///View tag
    pub view_tag: ViewTag,
    ///Encrypted amount which only the sender and receiver can decrypt
    pub encrypted_amount: u64

} impl Recipient {
    pub fn to_enote(&self, commitment: &Commitment) -> Enote {
        return Enote{
            owner: self.public_key,
            commitment: *commitment
        }
    }

} impl ToBytes<'_> for Recipient {}