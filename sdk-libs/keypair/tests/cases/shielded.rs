use zolana_keypair::{
    hash::owner_hash, random_salt, CompressedShieldedAddress, KeypairError, ShieldedAddress,
    ShieldedKeypair, SigningKey, ViewingKey,
};

use crate::{
    cases::nullifier::{expand_nullifier_secret, expand_viewing_pubkey},
    KeypairWorld,
};

pub(crate) fn address_consistent(world: &mut KeypairWorld, name: String) {
    let kp = world.keypair(&name);
    let expected = ShieldedAddress {
        signing_pubkey: kp.signing_pubkey(),
        nullifier_pubkey: kp.nullifier_key.pubkey().unwrap(),
        viewing_pubkey: kp.viewing_pubkey(),
    };
    assert_eq!(kp.shielded_address().unwrap(), expected);

    let expected_owner_hash =
        owner_hash(&kp.signing_pubkey(), &kp.nullifier_key.pubkey().unwrap()).unwrap();
    assert_eq!(
        kp.compressed_address().unwrap(),
        CompressedShieldedAddress {
            owner_hash: expected_owner_hash,
            viewing_pubkey: kp.viewing_pubkey(),
        }
    );
}

pub(crate) fn p256_owner_has_no_solana_address(world: &mut KeypairWorld, name: String) {
    let kp = world.keypair(&name);
    assert_eq!(
        kp.shielded_address().unwrap().solana_address(),
        Err(KeypairError::NoSolanaAddress)
    );
}

pub(crate) fn from_parts_keeps_detached_viewing_key(
    world: &mut KeypairWorld,
    signing: String,
    viewing: String,
) {
    let signing_clone =
        SigningKey::from_p256_bytes(&world.sig_key(&signing).secret_bytes()).unwrap();
    let viewing_clone = ViewingKey::from_bytes(&world.vk(&viewing).secret_bytes()).unwrap();
    let derived = ShieldedKeypair::from_keypair(signing_clone.clone()).unwrap();
    let kp = ShieldedKeypair::with_viewing_key(signing_clone, viewing_clone).unwrap();
    assert_eq!(*kp.nullifier_key.secret(), *derived.nullifier_key.secret());
    assert_eq!(kp.viewing_key.pubkey(), world.vk(&viewing).pubkey());
    assert_ne!(kp.viewing_key.pubkey(), derived.viewing_key.pubkey());

    let ed_signing = SigningKey::from_ed25519_bytes(&[9u8; 32]);
    let ed_viewing = ViewingKey::from_bytes(&world.vk(&viewing).secret_bytes()).unwrap();
    let ed_derived = ShieldedKeypair::from_keypair(ed_signing.clone()).unwrap();
    let ed = ShieldedKeypair::with_viewing_key(ed_signing, ed_viewing).unwrap();
    assert_eq!(
        *ed.nullifier_key.secret(),
        *ed_derived.nullifier_key.secret()
    );
    assert_eq!(ed.viewing_key.pubkey(), world.vk(&viewing).pubkey());
    assert_ne!(ed.viewing_key.pubkey(), ed_derived.viewing_key.pubkey());
}

pub(crate) fn from_keypair_roots_both_keys_in_one_seed(world: &mut KeypairWorld, signing: String) {
    let sk = world.sig_key(&signing);
    let seed = sk.derivation_seed().unwrap();
    let kp = ShieldedKeypair::from_keypair(sk.clone()).unwrap();
    assert_eq!(
        *kp.nullifier_key.secret(),
        expand_nullifier_secret(&seed, b"TSPP/nf_key/ecdh/v1")
    );
    assert_eq!(
        kp.viewing_key.pubkey(),
        expand_viewing_pubkey(&seed, b"TSPP/view_key/ecdh/v1")
    );
}

pub(crate) fn new_derives_viewing_key_from_signing_key(world: &mut KeypairWorld, name: String) {
    let kp = world.keypair(&name);
    let rederived = ShieldedKeypair::from_keypair(kp.signing_key.clone()).unwrap();
    assert_eq!(kp.viewing_key.pubkey(), rederived.viewing_key.pubkey());
    assert_eq!(
        *kp.nullifier_key.secret(),
        *rederived.nullifier_key.secret()
    );
}

pub(crate) fn solana_signer_matches_solana_keypair() {
    use solana_signer::Signer;

    let secret = [7u8; 32];
    let shielded = ShieldedKeypair::from_keypair(SigningKey::from_ed25519_bytes(&secret)).unwrap();
    let solana = solana_keypair::Keypair::new_from_array(secret);
    assert_eq!(shielded.try_pubkey().unwrap(), solana.pubkey());
    let msg = b"tx message";
    assert_eq!(
        shielded.try_sign_message(msg).unwrap(),
        solana.sign_message(msg)
    );

    let p256 = ShieldedKeypair::new().unwrap();
    assert!(p256.try_pubkey().is_err());
    assert!(p256.try_sign_message(msg).is_err());

    assert!(shielded
        .try_sign_message(zolana_keypair::derivation::ED25519_DERIVATION_MSG)
        .is_err());
}

pub(crate) fn facade_sign_nullifier(world: &mut KeypairWorld, name: String) {
    let kp = world.keypair(&name);
    // The signing API signs a 32-byte prehash digest (the transaction message_hash).
    let msg = [7u8; 32];
    assert!(kp.signing_key.verify(&msg, &kp.sign(&msg).unwrap()));
    let utxo_hash = [5u8; 32];
    let blinding = [6u8; 32];
    assert_eq!(
        kp.nullifier(&utxo_hash, &blinding).unwrap(),
        kp.nullifier_key.nullifier(&utxo_hash, &blinding).unwrap()
    );
}

pub(crate) fn facade_shared_tags(world: &mut KeypairWorld, sender: String, recipient: String) {
    let send = world
        .keypair(&sender)
        .get_send_shared_view_tag(&world.keypair(&recipient).viewing_pubkey(), 0)
        .unwrap();
    let recv = world
        .keypair(&recipient)
        .get_recipient_shared_view_tag(&world.keypair(&sender).viewing_pubkey(), 0)
        .unwrap();
    assert_eq!(send, recv);
}

pub(crate) fn facade_transfer(world: &mut KeypairWorld, sender: String, recipient: String) {
    let first_nullifier = world
        .keypair(&sender)
        .nullifier(&[1u8; 32], &[2u8; 32])
        .unwrap();
    let recipient_pubkey = world.keypair(&recipient).viewing_pubkey();
    let payload = b"owner || asset || amount || blinding".to_vec();

    let tx = world
        .keypair(&sender)
        .viewing_key
        .get_transaction_viewing_key(&first_nullifier)
        .unwrap();
    let salt = random_salt();
    let ct = tx
        .encrypt_slot(&recipient_pubkey, &payload, salt, 1)
        .unwrap();

    let decrypted = world
        .keypair(&recipient)
        .decrypt_utxo(&ct, &tx.pubkey(), salt, 1)
        .unwrap();
    assert_eq!(decrypted, payload);
}
