/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

//!RingCT-related ring signatures

/*
    Unused documentation:

    //!Given an enote, its private keys, and a ring containing that enote (along with decoys),
    //!create a ring signature which proves that:
    //! 1. the enote's "owner" key authorizes the signature, without revealing which enote is being spent
    //! 2. the key image (accessible with `signature.key_image`) is correct
    //! 3. the pseudo-output is a commitment to 0 (meaning that no conterfeit money is being created in the input)
*/

mod mlsag;
mod clsag;
mod signature_utils;

pub use mlsag::MLSAGSignature;
pub use clsag::CLSAGSignature;

pub(crate) use signature_utils::{
    separate_ring,
    encode_rings,
    ring_as_sorted,
    ring_is_sorted,
    get_key_image
};