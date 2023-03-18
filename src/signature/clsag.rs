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
    encoded_ring_l: Vec<[u8; 32]>, encoded_ring_c: Vec<[u8; 32]>, pseudo_out: Commitment, key_image: RistrettoPoint, auxiliary_point: RistrettoPoint , msg: &[u8]
) -> [u8; 32] {
    let encoded_points = batch_encode_points(&vec!(pseudo_out.0, key_image, auxiliary_point));
    return h_bytes(&[msg, &encoded_ring_l.concat(), &encoded_ring_c.concat(), &encoded_points.concat()].concat());
}

///A RingCT ring signature.
///
///CLSAG stands for "Concise Linkable Spontaneous Anonymous Group (signature)"
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CLSAGSignature {
    pub key_image: RistrettoPoint,
    c_0: Scalar,
    s: Vec<Scalar>,
    auxiliary: RistrettoPoint

} impl CLSAGSignature {
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

        let key_image_points = get_key_image_points(&encoded_ring_l);
        //calculate the key image and auxiliary point
        let key_image = enote_keys.owner * key_image_points[j];
        let auxiliary_point = commitment_key * key_image_points[j];

        let m = create_message(encoded_ring_l, encoded_ring_c, pseudo_out, key_image, auxiliary_point, msg);
        let m = m.as_slice();

        //Scalars are generated deterministically.
        //This is the seed.
        let mut seed = [enote_keys.owner.as_bytes(), pseudo_out_blinding.as_bytes(), m].concat();
        let mut last_scalar: Scalar = FILLER_SCALAR;

        let mut s: Vec<Scalar> = Vec::new();
        for _ in 0..n {
            last_scalar = h_scalar(&[ &last_scalar.to_bytes(), seed.as_slice() ].concat());
            s.push(last_scalar);
        }

        //create aggregation coefficients
        let linking_ac = domain_h_scalar(&m, domains::CLSAG_LINKING);
        let auxiliary_ac = domain_h_scalar(&m, domains::CLSAG_AUXILIARY);
        //create aggregated public keys
        let mut w_left: Vec<RistrettoPoint> = Vec::new();
        for x in 0..n { w_left.push(
            //(linking_ac * ring_l[x]) + (auxiliary_ac * ring_c[x])
            RistrettoPoint::multiscalar_mul(
                vec!(linking_ac, auxiliary_ac), vec!(ring_l[x], ring_c[x]))
        ); }
        //(linking_ac * key_image) + (auxiliary_ac * auxiliary_point)
        let w_right = RistrettoPoint::multiscalar_mul(
            vec!(linking_ac, auxiliary_ac), vec!(key_image, auxiliary_point)
        );

        //create aggregated secret key
        let w_secret = (linking_ac * enote_keys.owner) + (auxiliary_ac * commitment_key);

        //compute starting values
        let mut left = &s[j] * G;
        let mut right = s[j] * key_image_points[j];

        let mut c_i = Scalar::one();
        let mut c_0 = c_i;
        let mut i = j;
        for _ in 0..n {
            i = (i + 1) % n;

            c_i = domain_h_scalar(&[
                m, &batch_encode_points(&vec!(left, right)).concat()
            ].concat(), domains::CLSAG_COMMITMENT);

            if i == 0 { c_0 = c_i }
            if i == j { break }

            left = (&s[i] * G) + (c_i * w_left[i]);

            //(s[i] * key_image_points[i]) + (c[i] * w_right)
            right = RistrettoPoint::multiscalar_mul(
                vec!(s[i], c_i), vec!(key_image_points[i], w_right)
            );

        }
        s[j] -= c_i * w_secret;

        seed.zeroize();
        commitment_key.zeroize();

        return Ok((
            pseudo_out,
            Self{key_image, c_0, s, auxiliary: auxiliary_point}
        ))
    }


    ///Given a CLSAG signature, a **sorted** ring, and an input commitment (aka "pseudo-out"), check if it's valid.
    ///
    ///Returns `Ok()` if the signature is valid,
    ///or `Err(SignatureError)` if it's invalid or an error occurred.
    pub fn verify(
        signature: CLSAGSignature, ring: &Ring, pseudo_out: Commitment, msg: &[u8]
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
        signature: CLSAGSignature, ring: &Ring, pseudo_out: Commitment, msg: &[u8]
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
        signature: CLSAGSignature,
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

        let CLSAGSignature{
            key_image,
            c_0: mut c_i,
            s,
            auxiliary: auxiliary_point
        } = &signature;

        let ring_c = shift_commitments(&unshifted_ring_c, pseudo_out);

        if s.len() != ring.0.len() {
            return Err(SignatureError::Malformed)
        }

        let key_image_points = get_key_image_points(&encoded_ring_l);

        let m = create_message(encoded_ring_l, encoded_ring_c, pseudo_out, *key_image, *auxiliary_point, msg);
        let m = m.as_slice();
        let n = ring.0.len();

        //create aggregation coefficients
        let linking_ac = domain_h_scalar(&m, domains::CLSAG_LINKING);
        let auxiliary_ac = domain_h_scalar(&m, domains::CLSAG_AUXILIARY);
        //create aggregated public keys
        let mut w_left: Vec<RistrettoPoint> = Vec::new();
        for x in 0..n { w_left.push(
            //(linking_ac * ring_l[x]) + (auxiliary_ac * ring_c[x])
            RistrettoPoint::vartime_multiscalar_mul(
                vec!(linking_ac, auxiliary_ac), vec!(ring_l[x], ring_c[x])
            )
        ); }
        //(linking_ac * key_image) + (auxiliary_ac * auxiliary_point);
        let w_right = RistrettoPoint::vartime_multiscalar_mul(
            vec!(linking_ac, auxiliary_ac), vec!(key_image, auxiliary_point)
        );

        //travel around the ring
        for i in 0..n {
            //(s[i] * G) + (c[i] * w_left[i]);
            let left = G_MULTISCALAR_MUL.vartime_mixed_multiscalar_mul(
                vec!(s[i]), vec!(c_i), vec!(w_left[i])
            );

            //(s[i] * key_image_points[i]) + (c[i] * w_right);
            let right = RistrettoPoint::vartime_multiscalar_mul(
                vec!(s[i], c_i), vec!(key_image_points[i], w_right)
            );

            c_i = domain_h_scalar(&[
                m, &batch_encode_points(&vec!(left, right)).concat()
            ].concat(), domains::CLSAG_COMMITMENT);
        }
        //check if we end up back where we started
        return match c_i == signature.c_0 {
            true => Ok(()),
            false => Err(SignatureError::Invalid)
        };
    }

} impl ToBytes<'_> for CLSAGSignature {}
