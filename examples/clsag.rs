// SPDX short identifier: Unlicense

use ringct::{
    curve::{
        Scalar,
        RistrettoPoint,
        Random
    },
    Commitment,
    EnoteKeys,
    Enote,
    Ring,
    signature::CLSAGSignature,
};

const RINGSIZE: usize = 16;

fn main() {
    //See the pedersen commitment example before this

    //Create the signer's private keys.
    //In practice this would probably be created as an output of a previous transaction,
    //but for demonstration it will just be randomly generated.
    let signer_keys = EnoteKeys::new(
        Scalar::generate(),    //owning private key
        123456,             //value of the enote (in atomic units, for example piconeros:
                                //https://web.getmonero.org/resources/moneropedia/atomic-units.html)
        Scalar::generate(),    //blinding factor of the Pedersen commitment
    );
    let signer_enote = signer_keys.to_enote();

    let mut ring: Ring = Ring::new();
    ring.push(signer_enote);
    for _ in 0..(RINGSIZE - 1) {
        //Create random fake enotes to act as decoys for the signer.
        //Again, in practice, these would probably be created in a previous transaction
        ring.push(Enote::new(
            RistrettoPoint::generate(),             //the enote's owning public key
            Commitment(RistrettoPoint::generate())  //the pedersen commitment
        ))
    }

    //By defualt, the ring must be sorted.
    //If the signer's enote was simply always placed at the beginning or end,
    //then everyone would know who signed it, which defeats the purpose.
    ring.sort();

    //blinding factor of the input commitment (aka "pseudo-output")
    let input_commitment_blinding = Scalar::generate();

    //The message to be signed and verified
    let message = b"this is a test";

    //Create a CLSAG signature
    let (commitment, signature) = CLSAGSignature::sign(
        &ring,
        signer_keys.clone(),
        input_commitment_blinding,
        message
    ).expect("Real software should have proper error handling.");

    //Verify the signature
    CLSAGSignature::verify(
        signature.clone(),
        &ring,
        commitment,         //the pseudo-output
        message
    ).expect("Real software should have proper error handling.");


    //Create another CLSAG signature
    let mut ring: Ring = Ring::new();
    ring.push(signer_enote);
    for _ in 0..(RINGSIZE - 1) {
        ring.push(Enote::new(RistrettoPoint::generate(), Commitment(RistrettoPoint::generate())))
    }
    ring.sort();
    let (_, signature_2) = CLSAGSignature::sign(
        &ring, signer_keys, Scalar::generate(), b"another test"
    ).unwrap();

    //Key images will always be the same when signing with the same key,
    //regardless of other ring members, the message, or the pseudo-out.
    assert!(signature.key_image == signature_2.key_image);
}