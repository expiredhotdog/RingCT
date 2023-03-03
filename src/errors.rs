/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

use std::{
    error::Error,
    fmt::Display
};

///Encoding/serialization errors
#[derive(Debug, Clone)]
pub enum SerializationError {
    ///Failure to serialize.
    EncodingError,
    ///Failure to deserialize.
    DecodingError,

} impl Display for SerializationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", match self{
            Self::EncodingError => "Encoding error.",
            Self::DecodingError => "Decoding error."
        })
    }

} impl Error for SerializationError {}

///Rangeproof errors
#[derive(Debug, Clone)]
pub enum RangeProofError {
    ///The rangeproof is invalid.
    Invalid,
    ///The given rangeproof is malformed in some way,
    ///or the parameters are incorrect/inconsistent.
    Malformed,
    ///Aggregation size was too large, see `MAX_AGGREGATION_SIZE`.
    ///This is only relevant for Bulletproofs+.
    TooLargeAggregationSize,
    ///A given value is not in the valid range (0 <= `x` < 2<sup>`BIT_RANGE`</sup>) .
    OutOfRange,
    ///Miscellaneous/unspecified error.
    Unspecified(String)

} impl Display for RangeProofError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", match self{
            Self::Invalid => "This rangeproof is invalid.",
            Self::Malformed => "Malformed proof or parameters.",
            Self::TooLargeAggregationSize => "Too many aggregated values.",
            Self::OutOfRange => "Value is out of range.",
            Self::Unspecified(msg) => msg,
        })
    }

} impl Error for RangeProofError {}

///Ring signature errors
#[derive(Debug, Clone)]
pub enum SignatureError {
    ///The signature is invalid.
    Invalid,
    ///The given signature is malformed in some way,
    ///or the parameters are incorrect/inconsistent.
    Malformed,
    ///The enote which is being signed for is not in the ring.
    EnoteNotInRing,
    ///The ring is required to be sorted, but it is not
    UnsortedRing,
    ///Miscellaneous/unspecified error.
    Unspecified(String)

} impl Display for SignatureError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", match self{
            Self::Invalid => "This signature is invalid.",
            Self::Malformed => "Malformed signature or parameters.",
            Self::EnoteNotInRing => "Enote is not in ring.",
            Self::UnsortedRing => "The ring is not sorted.",
            Self::Unspecified(msg) => msg,
        })
    }

} impl Error for SignatureError {}

///Subaddress errors
#[derive(Debug, Clone)]
pub enum SubaddressError {
    ///The lookup table is not initalized.
    UninitializedTable,
    ///The coordinates are not initalized within the lookup table.
    UninitializedCoordinates,
    ///The extracted public spend key was not found in the lookup table.
    KeyNotFound,
    ///Miscellaneous/unspecified error.
    Unspecified(String)

} impl Display for SubaddressError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", match self{
            Self::UninitializedTable => "Uninitialized lookup table.",
            Self::UninitializedCoordinates => "Uninitialized coordinates",
            Self::KeyNotFound => "The lookup table did not have any key which matches the parameters.",
            Self::Unspecified(msg) => msg,
        })
    }

} impl Error for SubaddressError {}