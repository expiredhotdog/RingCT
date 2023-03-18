// SPDX short identifier: Unlicense

use rand::{thread_rng, Rng};

use ringct::{
    common::*,
    signature::{
        MLSAGSignature,
        CLSAGSignature
    }
};

const RING_SIZES: [usize; 14] = [1, 2, 3, 4, 8, 11, 16, 25, 32, 64, 100, 128, 256, 512];

#[test]
fn mlsag_test() {
    for x in RING_SIZES {
        let mut enote_keys: Vec<EnoteKeys> = Vec::new();
        let mut ring: Ring = Ring::new();
        for _ in 0..x {
            let _enote_keys = EnoteKeys {
                owner: Scalar::generate(),
                value: thread_rng().gen::<u64>(),
                blinding: Scalar::generate()
            };
            enote_keys.push(_enote_keys.clone());
            ring.push(_enote_keys.to_enote());
        }
        let my_key = &enote_keys[thread_rng().gen::<usize>() % x];
        let out_blinding = Scalar::generate();

        ring.sort();

        ring.0.reverse();
        if x != 1 {
            //should fail, because the ring is unsorted
            assert!(MLSAGSignature::sign(
                &ring, my_key.to_owned(), out_blinding, b"abcdef").is_err());
        }
        MLSAGSignature::sign_unsorted(
            &ring, my_key.to_owned(), out_blinding, b"abcdef").unwrap();

        ring.0.reverse();
        //sign
        let (pseudo_out, sig) = MLSAGSignature::sign(
            &ring, my_key.to_owned(), out_blinding, b"abcdef").unwrap();

        //serialize
        let serialized = sig.to_bytes().unwrap();
        let deserialized = MLSAGSignature::from_bytes(&serialized).unwrap();


        //sanity check the key image
        assert!(deserialized.key_image == my_key.get_key_image());

        if x != 1 {
            ring.0.reverse();
            //should fail, because the ring is unsorted
            assert!(MLSAGSignature::verify(
                deserialized.clone(), &ring, pseudo_out, b"abcdef").is_err());
            ring.0.reverse();
        }

        //verify
        MLSAGSignature::verify(
            deserialized.clone(), &ring, pseudo_out, b"abcdef").unwrap();

        //wrong message
        assert!(MLSAGSignature::verify(
            deserialized, &ring, pseudo_out, b"123456").is_err());
    }
}

#[test]
fn clsag_test() {
    for x in RING_SIZES {
        let mut enote_keys: Vec<EnoteKeys> = Vec::new();
        let mut ring: Ring = Ring::new();
        for _ in 0..x {
            let _enote_keys = EnoteKeys {
                owner: Scalar::generate(),
                value: thread_rng().gen::<u64>(),
                blinding: Scalar::generate()
            };
            enote_keys.push(_enote_keys.clone());
            ring.push(_enote_keys.to_enote());
        }
        let my_key = &enote_keys[thread_rng().gen::<usize>() % x];
        let out_blinding = Scalar::generate();

        ring.sort();

        ring.0.reverse();
        if x != 1 {
            //should fail, because the ring is unsorted
            assert!(CLSAGSignature::sign(
                &ring, my_key.to_owned(), out_blinding, b"abcdef").is_err());
        }
        CLSAGSignature::sign_unsorted(
            &ring, my_key.to_owned(), out_blinding, b"abcdef").unwrap();

        ring.0.reverse();
        //sign
        let (pseudo_out, sig) = CLSAGSignature::sign(
            &ring, my_key.to_owned(), out_blinding, b"abcdef").unwrap();

        //serialize
        let serialized = sig.to_bytes().unwrap();
        let deserialized = CLSAGSignature::from_bytes(&serialized).unwrap();

        //sanity check the key image
        assert!(deserialized.key_image == my_key.get_key_image());

        ring.0.reverse();
        if x != 1 {
            //should fail, because the ring is unsorted
            assert!(CLSAGSignature::verify(
                deserialized.clone(), &ring, pseudo_out, b"abcdef").is_err());
        }

        ring.0.reverse();
        //verify
        CLSAGSignature::verify(
            deserialized.clone(), &ring, pseudo_out, b"abcdef").unwrap();

        //wrong message
        assert!(CLSAGSignature::verify(
            deserialized, &ring, pseudo_out, b"123456").is_err());
    }
}