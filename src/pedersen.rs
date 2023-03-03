/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

//!Pedersen commitments

use crate::curve::*;
use crate::hashes::*;

lazy_static! {
    pub static ref PEDERSEN_G_POINT: RistrettoPoint = pedersen_g_point();
    pub static ref PEDERSEN_H_POINT: RistrettoPoint = pedersen_h_point();
    pub static ref PEDERSEN_G: RistrettoBasepointTable = pedersen_g_table();
    pub static ref PEDERSEN_H: RistrettoBasepointTable = pedersen_h_table();

    pub(crate) static ref PEDERSEN_G_MULTISCALAR_MUL: VartimeRistrettoPrecomputation = VartimeRistrettoPrecomputation::new(vec!(*PEDERSEN_G_POINT));
}

///get `H`
fn pedersen_h_point() -> RistrettoPoint {
    return h_point(&[encode_point(&G_POINT)].concat());
}

///get table of precomputed `H` values
fn pedersen_h_table() -> RistrettoBasepointTable {
    return RistrettoBasepointTable::create(&PEDERSEN_H_POINT);
}

///get `G`
fn pedersen_g_point() -> RistrettoPoint {
    return G_POINT;
}

///get table of precomputed `G` values
fn pedersen_g_table() -> RistrettoBasepointTable {
    return G.to_owned();
}

