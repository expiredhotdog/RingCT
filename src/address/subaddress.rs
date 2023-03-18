/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

//! An implementation of [Monero's stealth-subaddressing system](https://www.getmonero.org/resources/research-lab/pubs/MRL-0006.pdf).
//!
//! **By default, this protocol is vulnerable to the
//! [Janus attack](https://web.getmonero.org/2019/10/18/subaddress-janus.html).**

use std::collections::HashMap;
use zeroize::Zeroize;

use crate::internal_common::*;
use super::{
    ecdh::*,
    Recipient
};


///Lookup table for recovering private keys
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub(crate) struct GenericLookupTable<S: Zeroize> {
    pub(crate) coords: HashMap<CompressedRistretto, (u32, u32)>,
    pub(crate) secrets: HashMap<(u32, u32), S>

} impl<S: Zeroize> GenericLookupTable<S> {
    ///Reserves capacity for at least `additional` more elements to be inserted into each table.
    pub(crate) fn reserve(&mut self, additional: usize) {
        self.coords.reserve(additional);
        self.secrets.reserve(additional);
    }

    ///Inserts a group of values into the table.
    pub(crate) fn insert(&mut self, point: CompressedRistretto, coords: (u32, u32), key: S) {
        self.coords.insert(point, coords);
        self.secrets.insert(coords, key);
    }

} impl<S: Zeroize> Zeroize for GenericLookupTable<S> {
    fn zeroize(&mut self) {
        for (mut key, mut secret) in self.secrets.drain() {
            secret.zeroize();
            key.0.zeroize();
            key.1.zeroize();
        }
        for (mut key, mut coords) in self.coords.drain() {
            key.zeroize();
            coords.0.zeroize();
            coords.1.zeroize();
        }
    }

} impl<S: Zeroize> Drop for GenericLookupTable<S> {
    fn drop(&mut self) {
        self.zeroize()
    }
}

pub(crate) type LookupTable = GenericLookupTable<Scalar>;
pub(crate) type LookupTableView = GenericLookupTable<RistrettoPoint>;


trait LookupTableProtocol<S: Zeroize> {
    fn get_subkey_unchecked() -> Result<S, SubaddressError>;
}


///Master private keys of subaddress "wallet".
///
///These keys can view *and* spend funds sent to this "wallet"
///
///### Note on Serialization:
///There are two ways for this struct to be represented.
///The `to_bytes` and `from_bytes` methods provide a much more compact representation, but require more time to process.
///The `Serialize` and `Deserialize` traits are much less compact, but faster to process.
#[derive(Debug, Clone, Serialize, Deserialize, Zeroize)]
pub struct MasterPrivateKeys {
    pub view: Scalar,
    pub spend: Scalar,

    table: Option<LookupTable>

} impl MasterPrivateKeys {
    ///Get private spend key for subaddress without checking if the coordinates are initialized.
    pub(crate) fn get_subkey_unchecked(&self, coordinates: (u32, u32)) -> Scalar {
        //b + H(a,x,y)
        let msg = [
            self.view.as_bytes().as_slice(),
            &coordinates.0.to_le_bytes(),
            &coordinates.0.to_le_bytes()
        ].concat();
        return self.spend + domain_h_scalar(&msg, domains::SUBADDRESS_SUB_PRIVATE_SPEND)
    }

    ///Get the private spend key for the subaddress at the given coordinates.
    ///
    ///If those coordinates are uninitialized, return `Err(SubaddressError)`.
    pub(crate) fn get_subaddress_key(&self, coordinates: (u32, u32)) -> Result<Scalar, SubaddressError> {
        if self.get_table()?.secrets.get(&coordinates).is_none() {
            return Err(SubaddressError::UninitializedCoordinates)
        }
        return Ok(
            self.get_subkey_unchecked(coordinates)
        )
    }


    ///Export the lookup table for these keys.
    ///
    ///If uninitialized, return `Err(SubaddressError)`.
    pub(crate) fn get_table(&self) -> Result<&LookupTable, SubaddressError> {
        return match &self.table {
            Some(table) => Ok(table),
            None => Err(SubaddressError::UninitializedTable)
        }
    }

    ///Export the lookup table for these keys, as mutable.
    ///
    ///If uninitialized, return `Err(SubaddressError)`.
    pub(crate) fn get_mut_table(&mut self) -> Result<&mut LookupTable, SubaddressError> {
        return match self.table.as_mut() {
            Some(table) => Ok(table),
            None => Err(SubaddressError::UninitializedTable)
        }
    }

    ///Export the lookup table for these keys, as mutable.
    ///
    ///If uninitialized, create a new one.
    pub(crate) fn get_mut_table_else_new(&mut self) -> &mut LookupTable {
        if self.table.is_none() {
            self.table = Some(LookupTable::default())
        }
        return self.table.as_mut().unwrap()
    }

    ///Convert these master private keys into an (uninitialized) view-only master private key.
    pub fn to_view_only(&self) -> MasterPrivateView {
        return MasterPrivateView {
            view: self.view.to_owned(),
            spend: self.spend.to_public(),
            table: None
        }
    }

    ///Initialize all coordinates on the table up to these `x` and `y` values, exclusive.
    ///
    ///This may take a lot of time and memory when using large `x` and `y` values,
    ///as `x * y` individual coordinates need to be initialized.
    pub fn init(&mut self, x: u32, y: u32) -> () {
        let keypair = Self::from_keys(self.view.clone(), self.spend.clone());

        let table = self.get_mut_table_else_new();
        table.reserve((x * y) as usize);
        for x_coord in 0..x {
            for y_coord in 0..y {
                let key = keypair.get_subkey_unchecked((x_coord, y_coord));
                table.insert((&key * G).compress(), (x_coord, y_coord), key);
            }
        }
    }

    ///Initialize coordinates in the lookup table.
    pub fn init_coordinates(&mut self, coordinates: (u32, u32)) -> () {
        let keypair = Self::from_keys(self.view.clone(), self.spend.clone());

        let table = self.get_mut_table_else_new();
        let key = keypair.get_subkey_unchecked(coordinates);
        table.insert((&key * G).compress(), coordinates, key);
    }

    ///Get the subaddress controlled by this master keypair at the given coordinates.
    ///
    ///If the coordinates are not initialized, return `Err(SubaddressError)`.
    pub fn get_subaddress(&self, coordinates: (u32, u32)) -> Result<SubaddressPublic, SubaddressError> {
        //(b + H(a,x,y)) * G
        let spend = &self.get_subaddress_key(coordinates)? * G;

        return Ok(SubaddressPublic{
            spend,
            //C = a * D
            view: self.view * spend
        })
    }


    ///Given a public key, calculate the "shared secret" of these keys.
    ///
    ///**The transaction public key should not be reused.**
    pub fn shared_secret(&self, transaction_key: &RistrettoPoint) -> SharedSecret {
        return SharedSecret::get(self.view, &transaction_key)
    }

    ///Given a public key and shared secret, determine the coordinates of the subaddress that the key was derived from.
    ///
    ///Returns `Ok((x, y))` if successful.
    ///If the private key cannot be found, returns `Err(SubaddressError)`.
    pub fn recover_coordinates(&self, public_key: RistrettoPoint, shared_secret: SharedSecret) -> Result<(u32, u32), SubaddressError> {
        let table = self.get_table()?;
        //D' = P - H(aR)G
        return match table.coords.get(&(public_key - (&shared_secret.as_scalar() * G)).compress()) {
            Some(coords) => Ok(*coords),
            None => Err(SubaddressError::KeyNotFound)
        }
    }

    ///Given a shared secret, and subaddress coordinates, deterministically derive a unique ephemeral private key.
    ///**These keys should never be reused.**
    ///
    ///If the coordinates are not initialized, return `Err(SubaddressError)`.
    pub fn derive_key(&self, shared_secret: SharedSecret, coordinates: (u32, u32)) -> Result<Scalar, SubaddressError> {
        let table = self.get_table()?;
        //p = H(aR) + b + H(a,x,y)
        return match table.secrets.get(&coordinates) {
            Some(key) => Ok(key + shared_secret.as_scalar()),
            None => Err(SubaddressError::KeyNotFound)
        }
    }


    ///Generate a random new private key.
    pub fn generate() -> Self {
        let private_view = Scalar::generate();
        let private_spend = Scalar::generate();

        return Self::from_keys(private_view, private_spend)
    }

    ///Import from private keys.
    pub fn from_keys(private_view_key: Scalar, private_spend_key: Scalar) -> Self {
        return Self{view: private_view_key, spend: private_spend_key, table: None}
    }

    ///Deterministically convert a seed into a Subaddress private key.
    pub fn from_seed(bytes: [u8; 32]) -> Self {
        let private_view = domain_h_scalar(&bytes, domains::SUBADDRESS_MASTER_PRIVATE_VIEW);
        let private_spend = domain_h_scalar(&bytes, domains::SUBADDRESS_MASTER_PRIVATE_SPEND);

        return Self::from_keys(private_view, private_spend)
    }

    ///"Receive" a payment, decrypting its content, given the pedersen commitment.
    ///
    ///**Make sure that the appropiate coordinates are initialized first!**
    ///Otherwise the payment won't be recognized.
    ///
    ///Returns `Some(EnoteKeys)` if the enote belongs to these keys, or `None` if not.
    pub fn receive(&self, recipient: &Recipient, commitment: &Commitment) -> Option<EnoteKeys> {
        fn receive_inner(
            master_keys: &MasterPrivateKeys, recipient: &Recipient, commitment: &Commitment
        ) -> Result<EnoteKeys, SubaddressError> {
            //check view tag
            let transaction_key = match recipient.transaction_key {
                Some(key) => key,
                None => return Err(SubaddressError::Unspecified("".to_string()))
            };
            let shared_secret = master_keys.shared_secret(&transaction_key);
            if shared_secret.get_view_tag() != recipient.view_tag {
                return Err(SubaddressError::Unspecified("".to_string()))
            }

            //check public key
            let coordinates = master_keys.recover_coordinates(recipient.public_key, shared_secret.clone())?;
            let owner = master_keys.derive_key(shared_secret.clone(), coordinates)?;

            //check commitment
            let value = shared_secret.decrypt_amount(recipient.encrypted_amount);
            let blinding = shared_secret.as_scalar();
            if Commitment::commit(value, blinding) != *commitment {
                return Err(SubaddressError::Unspecified("".to_string()))
            }

            return Ok(EnoteKeys{
                owner,
                value,
                blinding
            })
        }
        if let Ok(keys) = receive_inner(self, recipient, commitment) {
            return Some(keys)
        }
        return None
    }


    ///Export the lookup table's initialized coordinates for these keys.
    ///
    ///If the lookup table is uninitialized, return `Err(SerializationError)`.
    pub fn export_coordinates(&self) -> Result<Vec<u8>, SerializationError> {
        let mut result: Vec<u8> = Vec::new();

        return match self.get_table() {
            Ok(table) => {
                for item in table.secrets.keys() {
                    result.extend(item.0.to_le_bytes());
                    result.extend(item.1.to_le_bytes());
                }
                Ok(result)
            },
            Err(_) => Err(SerializationError::EncodingError)
        }
    }

    ///Import and initialize a lookup table from encoded coordinates.
    pub fn import_coordinates(&mut self, bytes: &[u8]) -> Result<(), SerializationError> {
        fn decode_u32(bytes: &[u8]) -> Result<u32, SerializationError> {
            return match bytes[0..4].try_into() {
                Ok(item) => Ok(u32::from_le_bytes(item)),
                Err(_) => Err(SerializationError::DecodingError)
            }
        }

        if bytes.len() % 8 != 0 {
            return Err(SerializationError::DecodingError)
        }
        let mut coordinates: Vec<(u32, u32)> = Vec::new();
        for item in bytes.chunks(8) {
            coordinates.push((
                decode_u32(&item[0..4])?,
                decode_u32(&item[4..8])?
            ))
        }

        self.table = Some(LookupTable::default());
        self.get_mut_table().unwrap().reserve(coordinates.len());
        for item in coordinates {
            self.init_coordinates(item)
        }
        return Ok(())
    }

    ///Export these private keys.
    ///The lookup table, regardless of whether or not it is initialized, is **not** included.

    pub fn export_keys(&self) -> Result<Vec<u8>, SerializationError> {
        return Ok([self.view.to_bytes(), self.spend.to_bytes()].concat())
    }

    ///Import encoded private keys.

    pub fn import_keys(bytes: &[u8]) -> Result<Self, SerializationError> {
        if bytes.len() != 64 {
            return Err(SerializationError::DecodingError)
        }
        let private_view = Scalar::from_bytes(&bytes[0..32])?;
        let private_spend = Scalar::from_bytes(&bytes[32..64])?;

        return Ok(Self::from_keys(private_view, private_spend))
    }

} impl PartialEq for MasterPrivateKeys {
    fn eq(&self, other: &Self) -> bool {
        return self.view == other.view && self.spend == other.spend
    }

} impl Eq for MasterPrivateKeys {}
impl Drop for MasterPrivateKeys {
    fn drop(&mut self) {
        self.zeroize()
    }

} impl ToBytes<'_> for MasterPrivateKeys {
    fn to_bytes(&self) -> Result<Vec<u8>, SerializationError> {
        return Ok([self.export_keys()?, self.export_coordinates().or(Ok(vec!()))?].concat())
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self, SerializationError> {
        if bytes.len() < 64 || bytes.len() % 8 != 0 {
            return Err(SerializationError::DecodingError)
        }
        let mut keys = Self::import_keys(&bytes[0..64])?;
        keys.import_coordinates(&bytes[64..bytes.len()])?;

        return Ok(keys)
    }
}


///Master private view key of subaddress "view-only wallet".
///
///This key can only *view* funds sent to this "wallet"
///
///### Note on Serialization:
///There are two ways for this struct to be represented.
///The `to_bytes` and `from_bytes` methods provide a much more compact representation, but require more time to process.
///The `Serialize` and `Deserialize` traits are much less compact, but faster to process.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MasterPrivateView {
    pub view: Scalar,
    pub spend: RistrettoPoint,

    table: Option<LookupTableView>

} impl MasterPrivateView {
    ///Get public spend key for subaddress without checking if the coordinates are initialized.
    pub(crate) fn get_subkey_unchecked(&self, coordinates: (u32, u32)) -> RistrettoPoint {
        //b + H(a,x,y)
        let msg = [
            self.view.as_bytes().as_slice(),
            &coordinates.0.to_le_bytes(),
            &coordinates.0.to_le_bytes()
        ].concat();
        return self.spend + (&domain_h_scalar(&msg, domains::SUBADDRESS_SUB_PRIVATE_SPEND) * G)
    }

    ///Get the public spend key for the subaddress at the given coordinates.
    ///
    ///If those coordinates are uninitialized, return `Err(SubaddressError)`.
    pub(crate) fn get_subaddress_key(&self, coordinates: (u32, u32)) -> Result<RistrettoPoint, SubaddressError> {
        if self.get_table()?.secrets.get(&coordinates).is_none() {
            return Err(SubaddressError::UninitializedCoordinates)
        }
        return Ok(
            self.get_subkey_unchecked(coordinates)
        )
    }


    ///Export the lookup table for these keys.
    ///
    ///If uninitialized, return `Err(SubaddressError)`.
    pub(crate) fn get_table(&self) -> Result<&LookupTableView, SubaddressError> {
        return match &self.table {
            Some(table) => Ok(table),
            None => Err(SubaddressError::UninitializedTable)
        }
    }

    ///Export the lookup table for these keys, as mutable.
    ///
    ///If uninitialized, return `Err(SubaddressError)`.
    pub(crate) fn get_mut_table(&mut self) -> Result<&mut LookupTableView, SubaddressError> {
        return match self.table.as_mut() {
            Some(table) => Ok(table),
            None => Err(SubaddressError::UninitializedTable)
        }
    }

    ///Export the lookup table for these keys, as mutable.
    ///
    ///If uninitialized, create a new one.
    pub(crate) fn get_mut_table_else_new(&mut self) -> &mut LookupTableView {
        if self.table.is_none() {
            self.table = Some(LookupTableView::default())
        }
        return self.table.as_mut().unwrap()
    }

    ///Initialize all coordinates on the table up to these `x` and `y` values, exclusive.
    ///
    ///This may take a lot of time and memory when using large `x` and `y` values,
    ///as `x * y` individual coordinates need to be initialized.
    pub fn init(&mut self, x: u32, y: u32) -> () {
        let keypair = Self::from_keys(self.view.clone(), self.spend.clone());

        let table = self.get_mut_table_else_new();
        table.reserve((x * y) as usize);
        for x_coord in 0..x {
            for y_coord in 0..y {
                let key = keypair.get_subkey_unchecked((x_coord, y_coord));
                table.insert((&key).compress(), (x_coord, y_coord), key);
            }
        }
    }

    ///Initialize coordinates in the lookup table.
    pub fn init_coordinates(&mut self, coordinates: (u32, u32)) -> () {
        let keypair = Self::from_keys(self.view.clone(), self.spend.clone());

        let table = self.get_mut_table_else_new();
        let key = keypair.get_subkey_unchecked(coordinates);
        table.insert((&key).compress(), coordinates, key);
    }

    ///Get the subaddress controlled by this master view key at the given coordinates.
    ///
    ///If the coordinates are not initialized, return `Err(SubaddressError)`.
    pub fn get_subaddress(&self, coordinates: (u32, u32)) -> Result<SubaddressPublic, SubaddressError> {
        //(b + H(a,x,y)) * G
        let spend = &self.get_subaddress_key(coordinates)?;

        return Ok(SubaddressPublic{
            spend: *spend,
            //C = a * D
            view: self.view * spend
        })
    }


    ///Given a public key, calculate the "shared secret" of these keys.
    ///
    ///**The transaction public key should not be reused.**
    pub fn shared_secret(&self, transaction_key: &RistrettoPoint) -> SharedSecret {
        return SharedSecret::get(self.view, &transaction_key)
    }

    ///Given a public key and shared secret, determine the coordinates of the subaddress that the key was derived from.
    ///
    ///Returns `Ok((x, y))` if successful.
    ///If the private key cannot be found, returns `Err(SubaddressError)`.
    pub fn recover_coordinates(&self, public_key: RistrettoPoint, shared_secret: SharedSecret) -> Result<(u32, u32), SubaddressError> {
        let table = self.get_table()?;
        //D' = P - H(aR)G
        return match table.coords.get(&(public_key - (&shared_secret.as_scalar() * G)).compress()) {
            Some(coords) => Ok(*coords),
            None => Err(SubaddressError::KeyNotFound)
        }
    }

    ///Given a shared secret, and subaddress coordinates, deterministically derive a unique ephemeral private key.
    ///**These keys should never be reused.**
    ///
    ///If the coordinates are not initialized, return `Err(SubaddressError)`.
    pub fn derive_key(&self, shared_secret: SharedSecret, coordinates: (u32, u32)) -> Result<RistrettoPoint, SubaddressError> {
        let table = self.get_table()?;
        //p = H(aR) + b + H(a,x,y)
        return match table.secrets.get(&coordinates) {
            Some(key) => Ok(key + (&shared_secret.as_scalar() * G)),
            None => Err(SubaddressError::KeyNotFound)
        }
    }

    ///Import from a private view key and a public spend key.
    pub fn from_keys(private_view_key: Scalar, public_spend_key: RistrettoPoint) -> Self {
        return Self{view: private_view_key, spend: public_spend_key, table: None}
    }

    ///"Receive" a payment, decrypting its content, given the pedersen commitment.
    ///
    ///**Make sure that the appropiate coordinates are initialized first!**
    ///Otherwise the payment won't be recognized.
    ///
    ///Returns the amount and blinding factor of the pedersen commitment if the enote belongs to these keys, or `None` if not.
    pub fn receive(&self, recipient: &Recipient, commitment: &Commitment) -> Option<(u64, Scalar)> {
        fn receive_inner(
            master_keys: &MasterPrivateView, recipient: &Recipient, commitment: &Commitment
        ) -> Result<(u64, Scalar), SubaddressError> {
            //check view tag
            let transaction_key = match recipient.transaction_key {
                Some(key) => key,
                None => return Err(SubaddressError::Unspecified("".to_string()))
            };
            let shared_secret = master_keys.shared_secret(&transaction_key);
            if shared_secret.get_view_tag() != recipient.view_tag {
                return Err(SubaddressError::Unspecified("".to_string()))
            }

            //check public key
            master_keys.recover_coordinates(recipient.public_key, shared_secret.clone())?;

            //check commitment
            let value = shared_secret.decrypt_amount(recipient.encrypted_amount);
            let blinding = shared_secret.as_scalar();
            if Commitment::commit(value, blinding) != *commitment {
                return Err(SubaddressError::Unspecified("".to_string()))
            }

            return Ok((value, blinding))
        }
        if let Ok(keys) = receive_inner(self, recipient, commitment) {
            return Some(keys)
        }
        return None
    }

    ///Export the lookup table's initialized coordinates for these keys.
    ///
    ///If the lookup table is uninitialized, return `Err(SerializationError)`.
    pub fn export_coordinates(&self) -> Result<Vec<u8>, SerializationError> {
        let mut result: Vec<u8> = Vec::new();

        return match self.get_table() {
            Ok(table) => {
                for item in table.secrets.keys() {
                    result.extend(item.0.to_le_bytes());
                    result.extend(item.1.to_le_bytes());
                }
                Ok(result)
            },
            Err(_) => Err(SerializationError::EncodingError)
        }
    }

    ///Import and initialize a lookup table from encoded coordinates.
    pub fn import_coordinates(&mut self, bytes: &[u8]) -> Result<(), SerializationError> {
        fn decode_u32(bytes: &[u8]) -> Result<u32, SerializationError> {
            return match bytes[0..4].try_into() {
                Ok(item) => Ok(u32::from_le_bytes(item)),
                Err(_) => Err(SerializationError::DecodingError)
            }
        }

        if bytes.len() % 8 != 0 {
            return Err(SerializationError::DecodingError)
        }
        let mut coordinates: Vec<(u32, u32)> = Vec::new();
        for item in bytes.chunks(8) {
            coordinates.push((
                decode_u32(&item[0..4])?,
                decode_u32(&item[4..8])?
            ))
        }

        self.table = Some(LookupTableView::default());
        self.get_mut_table().unwrap().reserve(coordinates.len());
        for item in coordinates {
            self.init_coordinates(item)
        }
        return Ok(())
    }

    ///Export these keys.
    ///The lookup table, regardless of whether or not it is initialized, is **not** included.

    pub fn export_keys(&self) -> Result<Vec<u8>, SerializationError> {
        return Ok([self.view.to_bytes(), self.spend.compress().to_bytes()].concat())
    }

    ///Import encoded private keys.

    pub fn import_keys(bytes: &[u8]) -> Result<Self, SerializationError> {
        if bytes.len() != 64 {
            return Err(SerializationError::DecodingError)
        }
        let private_view = Scalar::from_bytes(&bytes[0..32])?;
        let public_spend = RistrettoPoint::from_bytes(&bytes[32..64])?;

        return Ok(Self::from_keys(private_view, public_spend))
    }

} impl PartialEq for MasterPrivateView {
    fn eq(&self, other: &Self) -> bool {
        return self.view == other.view && self.spend == other.spend
    }

} impl Eq for MasterPrivateView {}
impl Zeroize for MasterPrivateView {
    fn zeroize(&mut self) {
        self.view.zeroize();
        self.table.zeroize();
    }

} impl Drop for MasterPrivateView {
    fn drop(&mut self) {
        self.zeroize()
    }

} impl ToBytes<'_> for MasterPrivateView {
    fn to_bytes(&self) -> Result<Vec<u8>, SerializationError> {
        return Ok([self.export_keys()?, self.export_coordinates().or(Ok(vec!()))?].concat())
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self, SerializationError> {
        if bytes.len() < 64 || bytes.len() % 8 != 0 {
            return Err(SerializationError::DecodingError)
        }
        let mut keys = Self::import_keys(&bytes[0..64])?;
        keys.import_coordinates(&bytes[64..bytes.len()])?;

        return Ok(keys)
    }
}


///Public keys of a subaddress.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct SubaddressPublic {
    pub view: RistrettoPoint,
    pub spend: RistrettoPoint

} impl SubaddressPublic {
    ///Given a private key, calculate the "shared secret" of these keys,
    ///and the public transaction key needed for the recipient to recreate the shared secret.
    ///
    ///**The private key and transaction key should not be reused.**
    pub fn shared_secret(&self, other_private: Scalar) -> (SharedSecret, RistrettoPoint) {
        return (
            SharedSecret::get(other_private, &self.view),
            other_private.to_public_with_base(self.spend)
        )
    }

    ///Derive the unique ephemeral public key given a shared secret.
    ///**These keys should never be reused.**
    pub fn derive_key(&self, shared_secret: SharedSecret) -> RistrettoPoint {
        return self.spend + (&shared_secret.as_scalar() * G)
    }

    ///"Send" to this address, where only the recipient can detect that the payment is for them.
    ///
    ///The transaction/ECDH key is generated automatically.
    ///
    ///Returns the blinding factor of the pedersen commitment (for use in a rangeproof),
    ///and the public data for the receiver to detect the payment.
    pub fn send(&self, amount: u64) -> (Scalar, Recipient) {
        let seed = batch_encode_points(&vec!(self.view, self.spend)).concat();
        let seed = h_scalar(&[seed, amount.to_le_bytes().to_vec()].concat());
        let transaction_sk = seed + Scalar::generate();

        let (shared_secret, transaction_key) = self.shared_secret(transaction_sk);
        let view_tag = shared_secret.get_view_tag();
        let encrypted_amount = shared_secret.encrypt_amount(amount);
        let blinding = shared_secret.as_scalar();

        let recipient = Recipient {
            public_key: self.derive_key(shared_secret),
            transaction_key: Some(transaction_key),
            view_tag,
            encrypted_amount
        };
        return (blinding, recipient)
    }

} impl ToBytes<'_> for SubaddressPublic {
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