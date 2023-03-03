/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

//! Cryptographic proofs which demonstrate that the amount committed to in a pedersen commitment is non-negative

mod borromean;
mod bulletplus;

pub use borromean::BorromeanRangeProof;
pub use bulletplus::BulletPlusRangeProof;

///Provides direct low-level access to the core Bulletproofs+ implementation.
///
///Don't use this unless you have a good reason to, and know what you're doing.
pub mod bulletplus_internal {
    pub use bulletproofs_plus::*;
}

///Commitment values (in atomic units) are allowed to be between 0 and 2<sup>`BIT_RANGE`</sup> - 1.
//This should not exceed 64, and must be a power of 2 when using Bulletproofs+.
//Increasing this number will increase the size and verification time of rangeproofs.
pub const BIT_RANGE: usize = 64;

///Maximum commitment value (in atomic units) allowed for a rangeproof: 2<sup>`BIT_RANGE`</sup>
pub const MAX_VALUE: u64 = ((1u128 << BIT_RANGE) - 1) as u64;

///Maximum number of values allowed in an aggregated Bulletproofs+ proof.
pub const MAX_AGGREGATION_SIZE: usize = 256;