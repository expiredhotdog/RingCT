// SPDX short identifier: Unlicense

#![allow(unused)]

#[cfg(feature = "to_bytes")]
use ringct::{
    ToBytes,
    address::{
        ECDHPublicKey,
        SharedSecret,
        cryptonote::{
            CryptoNotePublic,
            CryptoNotePrivateView
        },
        subaddress::{
            SubaddressPublic,
            MasterPrivateView
        }
    }
};

use ringct::{
    address::{
        ECDHPrivateKey,
        cryptonote::{
            CryptoNotePrivate,
        },
        subaddress::{
            MasterPrivateKeys,
        }
    }
};

#[test]
fn ecdh_test() {
    let sk1 = ECDHPrivateKey::generate();
    let pk1 = sk1.to_public();
    let sk2 = ECDHPrivateKey::generate();
    let pk2 = sk2.to_public();

    let ss1 = sk1.shared_secret(&pk2);
    let ss2 = sk2.shared_secret(&pk1);

    #[cfg(feature = "to_bytes")]
    {
        //Serialization
        let sk1 = sk1.to_bytes().unwrap();
        let sk1 = ECDHPrivateKey::from_bytes(&sk1).unwrap();
        let pk1 = pk1.to_bytes().unwrap();
        let pk1 = ECDHPublicKey::from_bytes(&pk1).unwrap();
        let ss1 = ss1.to_bytes().unwrap();
        let ss1 = SharedSecret::from_bytes(&ss1).unwrap();
}

    //Shared secrets should be equal
    assert!(ss1 == ss2);

    //View tags should be equal
    assert!(ss1.get_view_tag() == ss2.get_view_tag());

    //Amount encryption
    let encrypted = ss1.encrypt_amount(123456);
    assert!(123456u64 != encrypted);
    assert!(123456u64 == ss2.decrypt_amount(encrypted));

    //Derived (public) keys should be equal
    assert!(sk1.derive_key(ss1.clone()).to_public() == pk1.derive_key(ss2));
}

#[test]
fn cryptonote_test() {
    let sk1 = CryptoNotePrivate::generate();
    let pk1 = sk1.to_public();

    let sk2 = ECDHPrivateKey::generate();
    let pk2 = sk2.to_public();

    #[cfg(feature = "to_bytes")]
    {
        //Serialization
        let sk1 = sk1.to_bytes().unwrap();
        let sk1 = CryptoNotePrivate::from_bytes(&sk1).unwrap();
        let pk1 = pk1.to_bytes().unwrap();
        let pk1 = CryptoNotePublic::from_bytes(&pk1).unwrap();
    }

    //Shared secrets should be equal
    let ss1 = sk1.shared_secret(&pk2);
    let ss2 = pk1.shared_secret(sk2);
    assert!(ss1 == ss2);

    //Derived (public) keys should be equal
    assert!(sk1.derive_key(ss1.clone()).to_public() == pk1.derive_key(ss2.clone()));

    //View-only
    let view_1 = sk1.to_view_only();
    let ss1 = view_1.shared_secret(&pk2);
    assert!(ss1 == ss2);
    assert!(view_1.derive_key(ss1) == pk1.derive_key(ss2));
    #[cfg(feature = "to_bytes")]
    {
        let view_1 = view_1.to_bytes().unwrap();
        let view_1 = CryptoNotePrivateView::from_bytes(&view_1).unwrap();
    }
}

#[test]
fn subaddress_test() {
    let mut master_keys = MasterPrivateKeys::generate();
    let sk2 = ECDHPrivateKey::generate();

    #[cfg(feature = "to_bytes")]
    {
        //Serialization
        let master_keys2 = master_keys.to_bytes().unwrap();
        let master_keys2 = MasterPrivateKeys::from_bytes(&master_keys2).unwrap();
        assert!(master_keys == master_keys2);
        let master_keys2 = master_keys2.export_keys().unwrap();
        let master_keys2 = MasterPrivateKeys::import_keys(&master_keys2).unwrap();
        assert!(master_keys == master_keys2);
    }

    //Initializing
    master_keys.init(16, 256);
    master_keys.init_coordinates((1024,1024));
    master_keys.init_coordinates((1,99999));

    //Get subaddress
    let pk1 = master_keys.get_subaddress((4,5)).unwrap();

    #[cfg(feature = "to_bytes")]
    {
        //Serialization part 2
        let master_keys2 = master_keys.to_bytes().unwrap();
        let master_keys2 = MasterPrivateKeys::from_bytes(&master_keys2).unwrap();
        assert!(master_keys == master_keys2);
        let pk1 = pk1.to_bytes().unwrap();
        let pk1 = SubaddressPublic::from_bytes(&pk1).unwrap();
    }

    //Shared secrets should be equal
    let (ss2, tx_pk) = pk1.shared_secret(sk2);
    let ss1 = master_keys.shared_secret(&tx_pk);
    assert!(ss1 == ss2);

    //Derived (public) keys should be equal
    let derived_pk = pk1.derive_key(ss2);
    let coords = master_keys.recover_coordinates(derived_pk, ss1.clone()).unwrap();
    assert!(derived_pk == master_keys.derive_key(ss1.clone(), coords).unwrap().to_public());

    //View-only
    let mut view_only = master_keys.to_view_only();
    view_only.init(16, 256);
    view_only.init_coordinates((1024,1024));
    view_only.init_coordinates((1,99999));
    assert!(master_keys.export_coordinates().unwrap().len() == view_only.export_coordinates().unwrap().len());
    assert!(pk1 == view_only.get_subaddress((4,5)).unwrap());
    let coords = view_only.recover_coordinates(derived_pk, ss1.clone()).unwrap();
    assert!(derived_pk == view_only.derive_key(ss1, coords).unwrap());
    #[cfg(feature = "to_bytes")]
    {
        let view_only2 = view_only.to_bytes().unwrap();
        let view_only2 = MasterPrivateView::from_bytes(&view_only2).unwrap();
        assert!(view_only == view_only2);
    }
}