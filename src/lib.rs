/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

#[macro_use]
extern crate lazy_static;


//internal modules
mod types;
pub use types::*;
mod tobytes;
#[cfg(feature = "to_bytes")]
pub use tobytes::ToBytes;


//uncommon public modules
pub mod pedersen;
pub mod hashes;


//"normal" public modules
pub mod errors;
pub mod curve;

pub mod rangeproof;
pub mod signature;
pub mod address;


pub mod common {
    //! A collection of commonly-used things in this crate.
    //! Errors, types, to/from bytes, and elliptic curve primitives/functions are all included.
    //!
    //! This is intended for situations where you don't want to bother with
    //! manually specifying everything you need.
    //! Relying on something like this is generally considered bad practice,
    //! and is intended for use in tests, examples, mockups, etc.
    //!
    //! Use `common::*` if you wish to automatically import everything.

    pub use crate::{
        types::*, errors::*, tobytes::*, curve::*
    };
}


mod internal_common {
    //! Similar to `common`, but for internal purposes only.
    //! This includes everything in `common`, as well as internal/less-common modules.
    //!
    //! Use `internal_common::*` if you wish to automatically import everything.

    pub use crate::{
        common::*, hashes::*, pedersen::*
    };
}