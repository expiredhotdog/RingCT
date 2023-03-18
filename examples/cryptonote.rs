// SPDX short identifier: Unlicense

use ringct::{
    curve::{
        Scalar,
        Random
    },
    address::{
        ECDHPrivateKey,
        cryptonote::CryptoNotePrivate
    }
};

fn main() {
    //See the ECDH example before this

    //Create user A's keys
    let private_key_1 = CryptoNotePrivate::generate();
    let public_key_1 = private_key_1.to_public();

    //Create user B's keys
    let private_key_2 = Scalar::generate();
    let public_key_2 = private_key_2.to_public();

    //Calculate the shared secret between A and B
    let shared_secret_1 = private_key_1.shared_secret(&public_key_2);
    let shared_secret_2 = public_key_1.shared_secret(private_key_2);
    assert!(shared_secret_1 == shared_secret_2);

    //CryptoNote stealth address protocol
    let stealth_public_key = public_key_1.derive_key(shared_secret_2);
    let stealth_private_key = private_key_1.derive_key(shared_secret_1.clone());
    assert!(stealth_public_key == stealth_private_key.to_public());


    //View-only wallet: can view all incoming payments, but does not control the private spending keys.
    let view_only_1 = private_key_1.to_view_only();
    assert!(public_key_1 == view_only_1.to_public());

    assert!(shared_secret_1 == view_only_1.shared_secret(&public_key_2));
    assert!(stealth_public_key == view_only_1.derive_key(shared_secret_1));
}