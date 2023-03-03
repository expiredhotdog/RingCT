/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

use zeroize::Zeroize;

use crate::internal_common::*;
use super::signature_utils::*;

const FILLER_SCALAR: Scalar = constants::BASEPOINT_ORDER;

///Create the signed message, including a hash of all keys.
fn create_message(
    encoded_ring_l: Vec<[u8; 32]>, encoded_ring_c: Vec<[u8; 32]>, pseudo_out: Commitment, key_image: RistrettoPoint, msg: &[u8]
) -> [u8; 32] {
    let encoded_points = batch_encode_points(&vec!(pseudo_out.0, key_image));
    return h_bytes(&[msg, &encoded_ring_l.concat(), &encoded_ring_c.concat(), &encoded_points.concat()].concat());
}

///A RingCT ring signature.
///
///MLSAG stands for "Multilayered Linkable Spontaneous Anonymous Group (signature)"
///
///These signatures are essentially obsolete;
///CLSAGs are smaller and about as fast as these signatures.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MLSAGSignature {
    pub key_image: RistrettoPoint,
    e_0: Scalar,
    s: [Vec<Scalar>; 2],

} impl MLSAGSignature {
    ///Create a signature given a **sorted** ring, the private keys of one of the private keys, a new blinding factor, and a message.
    ///
    ///Return an input commitment (aka "pseudo-out") and a CLSAG signature if signing was successful,
    ///or `SignatureError` if an error occurred.
    pub fn sign(
        ring: &Ring, enote_keys: EnoteKeys, pseudo_out_blinding: Scalar, msg: &[u8]
    ) -> Result<(Commitment, Self), SignatureError> {
        let [ring_l, unshifted_ring_c] = separate_ring(ring);
        let (encoded_ring_l, encoded_ring_c) = encode_rings(ring_l.clone(), unshifted_ring_c.clone());

        if !ring_is_sorted(ring, &encoded_ring_l, &encoded_ring_c) {
            return Err(SignatureError::UnsortedRing);
        }

        return Self::sign_internal(
            ring,
            ring_l,
            unshifted_ring_c,
            encoded_ring_l,
            encoded_ring_c,
            enote_keys,
            pseudo_out_blinding,
            msg
        )
    }

    ///Same as `sign`, except it doesn't check if the ring is sorted.
    ///
    ///Note that `verify_unsorted` will have to be used to verify signatures created by this function.
    pub fn sign_unsorted(
        ring: &Ring, enote_keys: EnoteKeys, pseudo_out_blinding: Scalar, msg: &[u8]
    ) -> Result<(Commitment, Self), SignatureError> {
        let [ring_l, unshifted_ring_c] = separate_ring(ring);
        let (encoded_ring_l, encoded_ring_c) = encode_rings(ring_l.clone(), unshifted_ring_c.clone());

        return Self::sign_internal(
            ring,
            ring_l,
            unshifted_ring_c,
            encoded_ring_l,
            encoded_ring_c,
            enote_keys,
            pseudo_out_blinding,
            msg
        )
    }

    ///Same as `sign`, except the ring is automatically sorted. `ring` must be mutable.
    ///
    ///This is slightly more efficient than sorting separately.
    pub fn sign_and_sort(
        ring: &mut Ring, enote_keys: EnoteKeys, pseudo_out_blinding: Scalar, msg: &[u8]
    ) -> Result<(Commitment, Self), SignatureError> {
        let [ring_l, unshifted_ring_c] = separate_ring(ring);
        let (encoded_ring_l, encoded_ring_c) = encode_rings(ring_l.clone(), unshifted_ring_c.clone());

        ring.0 = ring_as_sorted(ring, &encoded_ring_l, &encoded_ring_c).0;

        return Self::sign_internal(
            ring,
            ring_l,
            unshifted_ring_c,
            encoded_ring_l,
            encoded_ring_c,
            enote_keys,
            pseudo_out_blinding,
            msg
        )
    }

    ///Internal signing function.
    fn sign_internal(
        //So many parameters :(
        //The price of efficiency
        ring: &Ring,
        ring_l: Vec<RistrettoPoint>,
        unshifted_ring_c: Vec<RistrettoPoint>,
        encoded_ring_l: Vec<[u8; 32]>,
        encoded_ring_c: Vec<[u8; 32]>,
        enote_keys: EnoteKeys,
        pseudo_out_blinding: Scalar,
        msg: &[u8]
    ) -> Result<(Commitment, Self), SignatureError> {
        let n = ring.0.len();
        let mut commitment_key = enote_keys.blinding - pseudo_out_blinding;
        let pseudo_out = Commitment::commit(enote_keys.value, pseudo_out_blinding);
        let ring_c = shift_commitments(&unshifted_ring_c, pseudo_out);

        //find the user's enote in the ring
        let j = match ring.0.iter().position(|enote| enote == &enote_keys.to_enote()) {
            Some(key_index) => key_index,
            None => return Err(SignatureError::EnoteNotInRing)
        };
        let mut i = j;

        let key_image_points = get_key_image_points(&encoded_ring_l);
        //calculate the key image
        let key_image = enote_keys.owner * key_image_points[j];

        let m = create_message(encoded_ring_l, encoded_ring_c, pseudo_out, key_image, msg);
        let m = m.as_slice();

        //Scalars are generated deterministically.
        //This is the seed.
        let mut seed = [enote_keys.owner.as_bytes(), pseudo_out_blinding.as_bytes(), m].concat();
        let mut last_scalar: Scalar = FILLER_SCALAR;

        let mut s_l: Vec<Scalar> = Vec::new();
        for _ in 0..n {
            last_scalar = h_scalar(&[ &last_scalar.to_bytes(), seed.as_slice() ].concat());
            s_l.push(last_scalar);
        }

        let mut s_c: Vec<Scalar> = Vec::new();
        for _ in 0..n {
            last_scalar = h_scalar(&[ &last_scalar.to_bytes(), seed.as_slice() ].concat());
            s_c.push(last_scalar);
        }


        //compute starting values
        let mut left = &s_l[j] * G;
        let mut right = s_l[j] * key_image_points[j];
        let c_start = h_scalar(&[ &last_scalar.to_bytes(), seed.as_slice() ].concat());
        let mut c_i = (&s_c[i] * &*PEDERSEN_G) + (-c_start * ring_c[i]);

        let mut e: Vec<Scalar> = vec!(FILLER_SCALAR; n);
        for _ in 0..n {
            i = (i + 1) % n;

            //encode left, right, and commitment
            let next_e = batch_encode_points(&vec!(left, right, c_i));
            e[i] = h_scalar(&[
                m, &next_e[0], &next_e[1], &next_e[2]
            ].concat());

            if i == j { break }

            //linking key operations
            left = (&s_l[i] * G) + (e[i] * ring_l[i]);
            //(s_l[i] * key_image_points[i]) + (e_i * key_image);
            right = RistrettoPoint::multiscalar_mul(
                vec!(s_l[i], e[i]), vec!(key_image_points[i], key_image)
            );

            //commitment operations
            c_i = (&s_c[i] * &*PEDERSEN_G) - (e[i] * ring_c[i]);

        }
        s_l[j] -= enote_keys.owner * e[j];
        s_c[j] -= commitment_key * (c_start - e[j]);

        seed.zeroize();
        commitment_key.zeroize();

        return Ok((
            pseudo_out,
            Self{
                key_image,
                e_0: e[0],
                s: [s_l, s_c]
            }
        ))
    }


    ///Given an MLSAG signature, a **sorted** ring, and an input commitment (aka "pseudo-out"), check if it's valid.
    ///
    ///Returns `Ok()` if the signature is valid,
    ///or `Err(SignatureError)` if it's invalid or an error occurred.
    pub fn verify(
        signature: MLSAGSignature, ring: &Ring, pseudo_out: Commitment, msg: &[u8]
    ) -> Result<(), SignatureError> {
        let [ring_l, unshifted_ring_c] = separate_ring(ring);
        let (encoded_ring_l, encoded_ring_c) = encode_rings(ring_l.clone(), unshifted_ring_c.clone());

        if !ring_is_sorted(ring, &encoded_ring_l, &encoded_ring_c) {
            return Err(SignatureError::UnsortedRing);
        }

        return Self::verify_internal(
            signature,
            ring,
            ring_l,
            unshifted_ring_c,
            encoded_ring_l,
            encoded_ring_c,
            pseudo_out,
            msg
        )
    }

    ///Same as `verify`, except it doesn't check if the ring is sorted.
    ///
    ///Note that this will fail unless the ring is in the **exact** same order as when it was signed.
    pub fn verify_unsorted(
        signature: MLSAGSignature, ring: &Ring, pseudo_out: Commitment, msg: &[u8]
    ) -> Result<(), SignatureError> {
        let [ring_l, unshifted_ring_c] = separate_ring(ring);
        let (encoded_ring_l, encoded_ring_c) = encode_rings(ring_l.clone(), unshifted_ring_c.clone());

        return Self::verify_internal(
            signature,
            ring,
            ring_l,
            unshifted_ring_c,
            encoded_ring_l,
            encoded_ring_c,
            pseudo_out,
            msg
        )
    }

    ///Internal verification function.
    fn verify_internal(
        signature: MLSAGSignature,
        ring: &Ring,
        ring_l: Vec<RistrettoPoint>,
        unshifted_ring_c: Vec<RistrettoPoint>,
        encoded_ring_l: Vec<[u8; 32]>,
        encoded_ring_c: Vec<[u8; 32]>,
        pseudo_out: Commitment,
        msg: &[u8]
    ) -> Result<(), SignatureError> {
        /*
        Note: Ristretto is not vulnerable to this vulnerability:
        https://www.getmonero.org/2017/05/17/disclosure-of-a-major-bug-in-cryptonote-based-currencies.html
        */

        let MLSAGSignature{
            key_image,
            e_0: mut e_i,
            s: [s_l, s_c]
        } = &signature;

        let ring_c = shift_commitments(&unshifted_ring_c, pseudo_out);

        if s_l.len() != s_c.len() || s_l.len() != ring.0.len() {
            return Err(SignatureError::Malformed)
        }

        let key_image = key_image.to_owned();
        let key_image_points = get_key_image_points(&encoded_ring_l);

        let m = create_message(encoded_ring_l, encoded_ring_c, pseudo_out, key_image, msg);

        //travel around the ring
        for i in 0..ring.0.len() {
            //linking key operations
            //(s_l[i] * G) + (e_i * ring_l[i]);
            let left = G_MULTISCALAR_MUL.vartime_mixed_multiscalar_mul(
                vec!(s_l[i]), vec!(e_i), vec!(ring_l[i])
            );
            //(s_l[i] * key_image_points[i]) + (e_i * key_image);
            let right = RistrettoPoint::vartime_multiscalar_mul(
                vec!(s_l[i], e_i), vec!(key_image_points[i], key_image)
            );

            //commitment operations
            //(s_c[i] * G) - (e_i * ring_c[i]);
            let c_i = PEDERSEN_G_MULTISCALAR_MUL.vartime_mixed_multiscalar_mul(
                vec!(s_c[i]), vec!(-e_i), vec!(ring_c[i])
            );

            //encode left, right, and commitment
            let next_e = batch_encode_points(&vec!(left, right, c_i));
            e_i = h_scalar(&[
                m, next_e[0], next_e[1], next_e[2]
            ].concat());
        }
        //check if we end up back where we started
        return match e_i == signature.e_0 {
            true => Ok(()),
            false => Err(SignatureError::Invalid)
        };
    }

} #[cfg(feature = "to_bytes")] impl ToBytes<'_> for MLSAGSignature {}
