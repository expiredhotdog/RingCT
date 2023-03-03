// SPDX short identifier: Unlicense

use ringct::address::{
    ECDHPrivateKey,
    subaddress::MasterPrivateKeys
};

fn main() {
    //See the ECDH example before this

    //Create user A's keys
    let mut master_keys = MasterPrivateKeys::generate();
    //Initialize the wallet with 16 accounts (0-15), each with 256 addresses (0-255).
    //This is necessary to derive private keys made with these subaddresses.
    master_keys.init(16, 256);
    //We can also initialize specific "coordinates".
    //Account x, with address index y.
    master_keys.init_coordinates((20, 500));

    //Create generate the subaddress at the given coordinates
    let public_key_1 = master_keys.get_subaddress((0, 5))
        .expect("Real software should have proper error handling.");

    //Create user B's keys
    let private_key_2 = ECDHPrivateKey::generate();

    //Deriving a public key from a subaddress produces a "transaction public key",
    //which must be known by the receiver to derive the private key.
    let (shared_secret_2, transaction_public_key) = public_key_1.shared_secret(private_key_2);
    let shared_secret_1 = master_keys.shared_secret(&transaction_public_key);
    assert!(shared_secret_1 == shared_secret_2);

    //Stealth-subaddress protocol
    let stealth_public_key = public_key_1.derive_key(shared_secret_2);
    let recovered_coordinates = master_keys.recover_coordinates(stealth_public_key, shared_secret_1.clone())
        .expect("Real software should have proper error handling.");
    let stealth_private_key = master_keys.derive_key(shared_secret_1.clone(), recovered_coordinates)
        .expect("Real software should have proper error handling.");
    assert!(stealth_public_key == stealth_private_key.to_public());


    //View-only wallet: can view all incoming payments, but does not control the private spending keys.
    let mut view_only = master_keys.to_view_only();
    view_only.init_coordinates((0, 5));
    assert!(public_key_1 == view_only.get_subaddress((0, 5)).unwrap());

    assert!(shared_secret_1 == view_only.shared_secret(&transaction_public_key));
    let coordinates = view_only.recover_coordinates(stealth_public_key, shared_secret_1.clone()).unwrap();
    let stealth_private_key = view_only.derive_key(shared_secret_1, coordinates).unwrap();
    assert!(stealth_public_key == stealth_private_key);
}