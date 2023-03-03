// SPDX short identifier: Unlicense

use ringct::address::ECDHPrivateKey;

fn main() {
    //Create user A's keys
    let private_key_1 = ECDHPrivateKey::generate();
    let public_key_1 = private_key_1.to_public();

    //Create user B's keys
    let private_key_2 = ECDHPrivateKey::generate();
    let public_key_2 = private_key_2.to_public();

    //Calculate the shared secret between A and B --
    //both A and B are able to calculate it, but noone else.
    let shared_secret_1 = private_key_1.shared_secret(&public_key_2);
    let shared_secret_2 = private_key_2.shared_secret(&public_key_1);

    //This shared secret can be used as an encryption key,
    //or anything else which needs to be kept private between A and B.
    //Some basic protocols are implemented in this library.
    assert!(shared_secret_1 == shared_secret_2);

    //One-time-use amount encryption
    let encrypted = shared_secret_1.encrypt_amount(1234);
    let decrypted = shared_secret_2.decrypt_amount(encrypted);
    assert!(1234 == decrypted);

    //View tag (see:
        //https://github.com/monero-project/research-lab/issues/73)
    assert!(shared_secret_1.get_view_tag() == shared_secret_2.get_view_tag());

    //Simple stealth address protocol
    let stealth_public_key_1 = public_key_1.derive_key(shared_secret_2);
    let stealth_private_key_1 = private_key_1.derive_key(shared_secret_1);
    assert!(stealth_public_key_1 == stealth_private_key_1.to_public());
}