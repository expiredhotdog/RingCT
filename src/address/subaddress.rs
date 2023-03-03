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
use super::ecdh::*;


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
    pub view: ECDHPrivateKey,
    pub spend: ECDHPrivateKey,

    table: Option<LookupTable>

} impl MasterPrivateKeys {
    ///Get private spend key for subaddress without checking if the coordinates are initialized.
    pub(crate) fn get_subkey_unchecked(&self, coordinates: (u32, u32)) -> Scalar {
        //b + H(a,x,y)
        let msg = [
            self.view.as_scalar().as_bytes().as_slice(),
            &coordinates.0.to_le_bytes(),
            &coordinates.0.to_le_bytes()
        ].concat();
        return self.spend.as_scalar() + domain_h_scalar(&msg, domains::SUBADDRESS_SUB_PRIVATE_SPEND)
    }

    ///Get the private spend key for the subaddress at the given coordinates.
    ///
    ///If those coordinates are uninitialized, return `Err(SubaddressError)`.
    pub(crate) fn get_subaddress_key(&self, coordinates: (u32, u32)) -> Result<ECDHPrivateKey, SubaddressError> {
        if self.get_table()?.secrets.get(&coordinates).is_none() {
            return Err(SubaddressError::UninitializedCoordinates)
        }
        return Ok(
            ECDHPrivateKey::from_scalar(self.get_subkey_unchecked(coordinates)
        ))
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
        let spend = &self.get_subaddress_key(coordinates)?.as_scalar() * G;

        return Ok(SubaddressPublic{
            spend: ECDHPublicKey::from_point(spend),
            //C = a * D
            view: ECDHPublicKey::from_point(self.view.as_scalar() * spend)
        })
    }


    ///Given a public key, calculate the "shared secret" of these keys.
    ///
    ///**The transaction public key should not be reused.**
    pub fn shared_secret(&self, transaction_key: &ECDHPublicKey) -> SharedSecret {
        return SharedSecret::get(self.view.as_scalar(), &transaction_key.as_point())
    }

    ///Given a public key and shared secret, determine the coordinates of the subaddress that the key was derived from.
    ///
    ///Returns `Ok((x, y))` if successful.
    ///If the private key cannot be found, returns `Err(SubaddressError)`.
    pub fn recover_coordinates(&self, public_key: ECDHPublicKey, shared_secret: SharedSecret) -> Result<(u32, u32), SubaddressError> {
        let table = self.get_table()?;
        //D' = P - H(aR)G
        return match table.coords.get(&(public_key.as_point() - (&shared_secret.as_scalar() * G)).compress()) {
            Some(coords) => Ok(*coords),
            None => Err(SubaddressError::KeyNotFound)
        }
    }

    ///Given a shared secret, and subaddress coordinates, deterministically derive a unique ephemeral private key.
    ///**These keys should never be reused.**
    ///
    ///If the coordinates are not initialized, return `Err(SubaddressError)`.
    pub fn derive_key(&self, shared_secret: SharedSecret, coordinates: (u32, u32)) -> Result<ECDHPrivateKey, SubaddressError> {
        let table = self.get_table()?;
        //p = H(aR) + b + H(a,x,y)
        return match table.secrets.get(&coordinates) {
            Some(key) => Ok(ECDHPrivateKey::from_scalar(key + shared_secret.as_scalar())),
            None => Err(SubaddressError::KeyNotFound)
        }
    }


    ///Generate a random new private key.
    pub fn generate() -> Self {
        let private_view = ECDHPrivateKey::from_scalar(random_scalar());
        let private_spend = ECDHPrivateKey::from_scalar(random_scalar());

        return Self::from_keys(private_view, private_spend)
    }

    ///Import from private keys.
    pub fn from_keys(private_view_key: ECDHPrivateKey, private_spend_key: ECDHPrivateKey) -> Self {
        return Self{view: private_view_key, spend: private_spend_key, table: None}
    }

    ///Deterministically convert a seed into a Subaddress private key.
    pub fn from_seed(bytes: [u8; 32]) -> Self {
        let private_view = ECDHPrivateKey::from_scalar(
            domain_h_scalar(&bytes, domains::SUBADDRESS_MASTER_PRIVATE_VIEW));
        let private_spend = ECDHPrivateKey::from_scalar(
            domain_h_scalar(&bytes, domains::SUBADDRESS_MASTER_PRIVATE_SPEND));

        return Self::from_keys(private_view, private_spend)
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
    #[cfg(feature = "to_bytes")]
    pub fn export_keys(&self) -> Result<Vec<u8>, SerializationError> {
        return Ok([self.view.to_bytes()?, self.spend.to_bytes()?].concat())
    }

    ///Import encoded private keys.
    #[cfg(feature = "to_bytes")]
    pub fn import_keys(bytes: &[u8]) -> Result<Self, SerializationError> {
        if bytes.len() != 64 {
            return Err(SerializationError::DecodingError)
        }
        let private_view = ECDHPrivateKey::from_bytes(&bytes[0..32])?;
        let private_spend = ECDHPrivateKey::from_bytes(&bytes[32..64])?;

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

} #[cfg(feature = "to_bytes")] impl ToBytes<'_> for MasterPrivateKeys {
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
    pub view: ECDHPrivateKey,
    pub spend: ECDHPublicKey,

    table: Option<LookupTableView>

} impl MasterPrivateView {
    ///Get public spend key for subaddress without checking if the coordinates are initialized.
    pub(crate) fn get_subkey_unchecked(&self, coordinates: (u32, u32)) -> RistrettoPoint {
        //b + H(a,x,y)
        let msg = [
            self.view.as_scalar().as_bytes().as_slice(),
            &coordinates.0.to_le_bytes(),
            &coordinates.0.to_le_bytes()
        ].concat();
        return self.spend.as_point() + (&domain_h_scalar(&msg, domains::SUBADDRESS_SUB_PRIVATE_SPEND) * G)
    }

    ///Get the public spend key for the subaddress at the given coordinates.
    ///
    ///If those coordinates are uninitialized, return `Err(SubaddressError)`.
    pub(crate) fn get_subaddress_key(&self, coordinates: (u32, u32)) -> Result<ECDHPublicKey, SubaddressError> {
        if self.get_table()?.secrets.get(&coordinates).is_none() {
            return Err(SubaddressError::UninitializedCoordinates)
        }
        return Ok(
            ECDHPublicKey::from_point(self.get_subkey_unchecked(coordinates)
        ))
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
        let spend = &self.get_subaddress_key(coordinates)?.as_point();

        return Ok(SubaddressPublic{
            spend: ECDHPublicKey::from_point(*spend),
            //C = a * D
            view: ECDHPublicKey::from_point(self.view.as_scalar() * spend)
        })
    }


    ///Given a public key, calculate the "shared secret" of these keys.
    ///
    ///**The transaction public key should not be reused.**
    pub fn shared_secret(&self, transaction_key: &ECDHPublicKey) -> SharedSecret {
        return SharedSecret::get(self.view.as_scalar(), &transaction_key.as_point())
    }

    ///Given a public key and shared secret, determine the coordinates of the subaddress that the key was derived from.
    ///
    ///Returns `Ok((x, y))` if successful.
    ///If the private key cannot be found, returns `Err(SubaddressError)`.
    pub fn recover_coordinates(&self, public_key: ECDHPublicKey, shared_secret: SharedSecret) -> Result<(u32, u32), SubaddressError> {
        let table = self.get_table()?;
        //D' = P - H(aR)G
        return match table.coords.get(&(public_key.as_point() - (&shared_secret.as_scalar() * G)).compress()) {
            Some(coords) => Ok(*coords),
            None => Err(SubaddressError::KeyNotFound)
        }
    }

    ///Given a shared secret, and subaddress coordinates, deterministically derive a unique ephemeral private key.
    ///**These keys should never be reused.**
    ///
    ///If the coordinates are not initialized, return `Err(SubaddressError)`.
    pub fn derive_key(&self, shared_secret: SharedSecret, coordinates: (u32, u32)) -> Result<ECDHPublicKey, SubaddressError> {
        let table = self.get_table()?;
        //p = H(aR) + b + H(a,x,y)
        return match table.secrets.get(&coordinates) {
            Some(key) => Ok(ECDHPublicKey::from_point(key + (&shared_secret.as_scalar() * G))),
            None => Err(SubaddressError::KeyNotFound)
        }
    }

    ///Import from a private view key and a public spend key.
    pub fn from_keys(private_view_key: ECDHPrivateKey, public_spend_key: ECDHPublicKey) -> Self {
        return Self{view: private_view_key, spend: public_spend_key, table: None}
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
    #[cfg(feature = "to_bytes")]
    pub fn export_keys(&self) -> Result<Vec<u8>, SerializationError> {
        return Ok([self.view.to_bytes()?, self.spend.to_bytes()?].concat())
    }

    ///Import encoded private keys.
    #[cfg(feature = "to_bytes")]
    pub fn import_keys(bytes: &[u8]) -> Result<Self, SerializationError> {
        if bytes.len() != 64 {
            return Err(SerializationError::DecodingError)
        }
        let private_view = ECDHPrivateKey::from_bytes(&bytes[0..32])?;
        let public_spend = ECDHPublicKey::from_bytes(&bytes[32..64])?;

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

} #[cfg(feature = "to_bytes")] impl ToBytes<'_> for MasterPrivateView {
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
    pub view: ECDHPublicKey,
    pub spend: ECDHPublicKey

} impl SubaddressPublic {
    ///Given a private key, calculate the "shared secret" of these keys,
    ///and the public transaction key needed for the recipient to recreate the shared secret.
    ///
    ///**The private key and transaction key should not be reused.**
    pub fn shared_secret(&self, other_private: ECDHPrivateKey) -> (SharedSecret, ECDHPublicKey) {
        return (
            SharedSecret::get(other_private.as_scalar(), &self.view.as_point()),
            other_private.to_public_with_base(self.spend.as_point())
        )
    }

    ///Derive the unique ephemeral public key given a shared secret.
    ///**These keys should never be reused.**
    pub fn derive_key(&self, shared_secret: SharedSecret) -> ECDHPublicKey {
        return ECDHPublicKey::from_point(
            self.spend.as_point() + (&shared_secret.as_scalar() * G))
    }

} #[cfg(feature = "to_bytes")] impl ToBytes<'_> for SubaddressPublic {
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