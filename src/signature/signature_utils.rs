/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

use std::collections::HashMap;
use crate::internal_common::*;



lazy_static! {
    pub(crate) static ref ZERO_POINT: RistrettoPoint = &Scalar::zero() * G;
}

///hash to point, specific for key image
pub(crate) fn h_key_image_point(msg: &[u8]) -> RistrettoPoint {
    return domain_h_point(msg, domains::SIGNATURE_KEY_IMAGE);
}

///return the key image points for a vector of encoded public keys
pub(crate) fn get_key_image_points(encoded_pubs: &Vec<[u8; 32]>) -> Vec<RistrettoPoint> {
    return encoded_pubs.into_iter()
        .map(|key| h_key_image_point(key)).collect();
}

///batch encode rings
pub(crate) fn encode_rings(ring_l: Vec<RistrettoPoint>, ring_c: Vec<RistrettoPoint>) -> (Vec<[u8; 32]>, Vec<[u8; 32]>) {
    let n = ring_l.len();
    let encoded_points = batch_encode_points(&[ring_l, ring_c].concat());
    return (
        encoded_points[0..n].to_vec(), //linking
        encoded_points[n..2 * n].to_vec() //commitment
    )
}

///separate a ring of enotes into separate vectors of owners and commitments
pub(crate) fn separate_ring(ring: &Ring) -> [Vec<RistrettoPoint>; 2] {
    let mut ring_l: Vec<RistrettoPoint> = Vec::new();
    let mut ring_c: Vec<RistrettoPoint> = Vec::new();
    for enote in &ring.0 {
        ring_l.push(enote.owner);
        ring_c.push(enote.commitment.0);
    }
    return [ring_l, ring_c]
}

///subtract the pseudo-out from each commitment (aka, "shift")
pub(crate) fn shift_commitments(unshifted_ring_c: &Vec<RistrettoPoint>, pseudo_out: Commitment) -> Vec<RistrettoPoint> {
    //neg_pseudo_out is the pseudo_out multiplied by -1: pseudo_out + neg_pseudo_out = 0
    let neg_pseudo_out = *ZERO_POINT - pseudo_out.0;
    return unshifted_ring_c.iter()
        .map(|com| com + neg_pseudo_out).collect();
}

///Given a private key, return its key image
pub(crate) fn get_key_image(private_key: Scalar) -> RistrettoPoint {
    let public_key = &private_key * G;
    return private_key * h_key_image_point(&batch_encode_points(&vec!(public_key))[0])
}

///Return a new Ring which is sorted and has no duplicates
pub(crate) fn ring_as_sorted(ring: &Ring, encoded_ring_l: &Vec<[u8; 32]>, encoded_ring_c: &Vec<[u8; 32]>) -> Ring {
    //create a hashmap so that we can recall which encoded data belongs to which enote
    let mut original_map: HashMap<[u8; 64], Enote> = HashMap::default();
    original_map.reserve(ring.0.len());

    let mut encoded_enotes: Vec<[u8; 64]> = Vec::new();
    for i in 0..ring.0.len() {
        let encoded = [encoded_ring_l[i], encoded_ring_c[i]].concat().try_into().unwrap();
        original_map.insert(encoded, ring.0[i]);
        encoded_enotes.push(encoded);
    }
    encoded_enotes.sort_unstable();
    encoded_enotes.dedup();
    return Ring(encoded_enotes.into_iter().map(
        |enote| *original_map.get(&enote).unwrap()).collect())
}

///Check if a Ring is sorted and has no duplicates
pub(crate) fn ring_is_sorted(ring: &Ring, encoded_ring_l: &Vec<[u8; 32]>, encoded_ring_c: &Vec<[u8; 32]>) -> bool {
    let mut encoded_enotes: Vec<[u8; 64]> = Vec::new();
    for i in 0..ring.0.len() {
        let encoded = [encoded_ring_l[i], encoded_ring_c[i]].concat().try_into().unwrap();
        encoded_enotes.push(encoded);
    }
    //ensure that no values are duplicated or out of order
    return encoded_enotes.windows(2)
        .all(|enotes| enotes[0] < enotes[1])
}