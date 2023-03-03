/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

pub use serde::{
    Serialize,
    Deserialize,
};
pub use crate::errors::SerializationError;

///Implements functions to convert to (`to_bytes`) and from (`from_bytes`) bytes
///for most data types in this crate.
#[cfg(feature = "to_bytes")]
pub trait ToBytes<'a>: Sized + Serialize + Deserialize<'a> {
    fn to_bytes(&self) -> Result<Vec<u8>, SerializationError> {
        return match bincode::serialize(self) {
            Ok(bytes) => Ok(bytes),
            Err(_) => Err(SerializationError::EncodingError)
        }
    }

    fn from_bytes(bytes: &'a [u8]) -> Result<Self, SerializationError> {
        return match bincode::deserialize(bytes) {
            Ok(signature) => Ok(signature),
            Err(_) => Err(SerializationError::DecodingError)
        }
    }
}