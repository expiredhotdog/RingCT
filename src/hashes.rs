/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

use blake2::{
    Blake2b,
    Digest,
    digest::consts::{U32, U64}
};
use crate::curve::*;

type Blake2b256 = Blake2b<U32>;
type Blake2b512 = Blake2b<U64>;

///Hash bytes to bytes, domain separated.
///You most likely won't need this, see `h_bytes` instead.
pub fn domain_h_bytes(msg: &[u8], domain: &[u8]) -> [u8; 32] {
    let mut hasher = Blake2b256::default();
    hasher.update([msg, domain].concat());
    return hasher.finalize().as_slice().try_into()
        .expect("Wrong digest length");
}

///Hash bytes to elliptic curve point, domain separated.
///You most likely won't need this, see `h_point` instead.
pub fn domain_h_point(msg: &[u8], domain: &[u8]) -> RistrettoPoint {
    let mut hasher = Blake2b512::default();
    hasher.update([msg, domain].concat());
    return RistrettoPoint::from_uniform_bytes(
        hasher.finalize().as_slice().try_into()
        .expect("Wrong digest length")
    );
}

///Hash bytes to scalar, domain separated.
///You most likely won't need this, see `h_scalar` instead.
pub fn domain_h_scalar(msg: &[u8], domain: &[u8]) -> Scalar {
    return Scalar::from_bytes_mod_order(
        domain_h_bytes(msg, domain));
}

///Hash bytes to bytes.
pub fn h_bytes(msg: &[u8]) -> [u8; 32] {
    let mut hasher = Blake2b256::default();
    hasher.update(msg);
    return hasher.finalize().as_slice().try_into()
        .expect("Wrong digest length");
}

///Hash bytes to elliptic curve point.
pub fn h_point(msg: &[u8]) -> RistrettoPoint {
    let mut hasher = Blake2b512::default();
    hasher.update(msg);
    return RistrettoPoint::from_uniform_bytes(
        hasher.finalize().as_slice().try_into()
        .expect("Wrong digest length")
    );
}

///Hash bytes to scalar.
pub fn h_scalar(msg: &[u8]) -> Scalar {
    return Scalar::from_bytes_mod_order(h_bytes(msg));
}

pub mod domains {
    //! Pre-defined hash domains

    pub const SIGNATURE_KEY_IMAGE: &[u8] =              "key_img".as_bytes();

    pub const CLSAG_LINKING: &[u8] =                    "clsag_link".as_bytes();
    pub const CLSAG_AUXILIARY: &[u8] =                  "clsag_aux".as_bytes();
    pub const CLSAG_COMMITMENT: &[u8] =                 "clsag_com".as_bytes();

    pub const ECDH_VIEW_TAG: &[u8] =                    "ecdh_tag".as_bytes();
    pub const ECDH_ENCRYPTION_KEY: &[u8] =              "ecdh_enc".as_bytes();
    pub const ECDH_PRIVATE_KEY: &[u8] =                 "ecdh_priv".as_bytes();

    pub const CRYPTONOTE_PRIVATE_VIEW: &[u8] =          "cn_view".as_bytes();
    pub const CRYPTONOTE_PRIVATE_SPEND: &[u8] =         "cn_spend".as_bytes();

    pub const SUBADDRESS_MASTER_PRIVATE_VIEW: &[u8] =   "subaddr_mv".as_bytes();
    pub const SUBADDRESS_MASTER_PRIVATE_SPEND: &[u8] =  "subaddr_ms".as_bytes();
    pub const SUBADDRESS_SUB_PRIVATE_SPEND: &[u8] =     "subaddr_ss".as_bytes();
}
