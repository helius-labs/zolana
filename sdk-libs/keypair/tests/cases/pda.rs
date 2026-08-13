use solana_address::Address;
use zolana_keypair::{
    derivation::{DST_PDA_ROOT_P_PDA, P_CONST_SEC1, P_DERIVE_SEC1, P_PDA_SEC1},
    random_salt, Curve, KeypairError, NullifierKey, PublicKey, ShieldedKeypairTrait, ShieldedPda,
    ViewingKeyTrait,
};

use crate::KeypairWorld;

pub(crate) fn p_pda_matches() {
    use p256::{
        elliptic_curve::{
            hash2curve::{ExpandMsgXmd, GroupDigest},
            sec1::ToEncodedPoint,
        },
        NistP256,
    };
    use sha2::Sha256;

    let point =
        NistP256::hash_from_bytes::<ExpandMsgXmd<Sha256>>(&[b""], &[DST_PDA_ROOT_P_PDA]).unwrap();
    let sec1 = point.to_affine().to_encoded_point(true);
    assert_eq!(sec1.as_bytes(), P_PDA_SEC1);
    assert_ne!(P_PDA_SEC1, P_DERIVE_SEC1);
    assert_ne!(P_PDA_SEC1, P_CONST_SEC1);
}

fn pda(n: u8) -> Address {
    Address::new_from_array([n; 32])
}

pub(crate) fn both_parties_derive_the_same_identity(
    world: &mut KeypairWorld,
    a: String,
    b: String,
) {
    let alice = world.vk(&a);
    let bob = world.vk(&b);
    let from_a = ShieldedPda::from_key_exchange(pda(7), alice, &bob.pubkey()).unwrap();
    let from_b = ShieldedPda::from_key_exchange(pda(7), bob, &alice.pubkey()).unwrap();
    assert_eq!(
        from_a.shielded_address().unwrap(),
        from_b.shielded_address().unwrap()
    );
    assert_eq!(from_a.owner_hash().unwrap(), from_b.owner_hash().unwrap());
    assert_eq!(
        from_a.nullifier(&[1u8; 32], &[2u8; 32]).unwrap(),
        from_b.nullifier(&[1u8; 32], &[2u8; 32]).unwrap()
    );
}

pub(crate) fn pda_binding_separates_identities(world: &mut KeypairWorld, a: String, b: String) {
    let alice = world.vk(&a);
    let bob = world.vk(&b);
    let first = ShieldedPda::from_key_exchange(pda(7), alice, &bob.pubkey()).unwrap();
    let second = ShieldedPda::from_key_exchange(pda(8), alice, &bob.pubkey()).unwrap();
    assert_ne!(first.viewing_pubkey(), second.viewing_pubkey());
    assert_ne!(
        first.shielded_address().unwrap().nullifier_pubkey,
        second.shielded_address().unwrap().nullifier_pubkey
    );
}

pub(crate) fn from_viewing_key_is_deterministic_and_distinct(
    world: &mut KeypairWorld,
    a: String,
    b: String,
) {
    let alice = world.vk(&a);
    let bob = world.vk(&b);
    let first = ShieldedPda::from_viewing_key(pda(7), alice).unwrap();
    let second = ShieldedPda::from_viewing_key(pda(7), alice).unwrap();
    assert_eq!(
        first.shielded_address().unwrap(),
        second.shielded_address().unwrap()
    );
    assert_eq!(first.viewing_key().pubkey(), first.viewing_pubkey());

    let other_pda = ShieldedPda::from_viewing_key(pda(8), alice).unwrap();
    assert_ne!(first.viewing_pubkey(), other_pda.viewing_pubkey());
    assert_ne!(
        first.shielded_address().unwrap().nullifier_pubkey,
        other_pda.shielded_address().unwrap().nullifier_pubkey
    );

    let sole = ShieldedPda::from_key_exchange(pda(7), alice, &alice.pubkey()).unwrap();
    let paired = ShieldedPda::from_key_exchange(pda(7), alice, &bob.pubkey()).unwrap();
    for exchange in [&sole, &paired] {
        assert_ne!(first.viewing_pubkey(), exchange.viewing_pubkey());
        assert_ne!(
            first.shielded_address().unwrap().nullifier_pubkey,
            exchange.shielded_address().unwrap().nullifier_pubkey
        );
    }
}

pub(crate) fn sole_holder_identity(world: &mut KeypairWorld, a: String, b: String) {
    let alice = world.vk(&a);
    let bob = world.vk(&b);
    let sole = ShieldedPda::from_key_exchange(pda(7), alice, &alice.pubkey()).unwrap();
    let paired = ShieldedPda::from_key_exchange(pda(7), alice, &bob.pubkey()).unwrap();
    assert_ne!(sole.viewing_pubkey(), paired.viewing_pubkey());
    assert_ne!(
        sole.shielded_address().unwrap().nullifier_pubkey,
        paired.shielded_address().unwrap().nullifier_pubkey
    );
}

pub(crate) fn pda_cannot_sign(world: &mut KeypairWorld, a: String) {
    let alice = world.vk(&a);
    let identity = ShieldedPda::from_key_exchange(pda(7), alice, &alice.pubkey()).unwrap();
    assert_eq!(identity.curve().unwrap(), Curve::Pda);
    assert_eq!(
        ShieldedKeypairTrait::sign(&identity, b"private_tx_hash"),
        Err(KeypairError::PdaCannotSign)
    );
}

pub(crate) fn from_parts_holds_supplied_roles(world: &mut KeypairWorld, a: String) {
    let viewing = world.vk(&a).clone();
    let nullifier_key = NullifierKey::from_secret([3u8; 31]);
    let expected_nullifier_pubkey = nullifier_key.pubkey().unwrap();
    let identity = ShieldedPda::with_viewing_key(pda(7), nullifier_key, viewing.clone());
    assert_eq!(identity.viewing_pubkey(), viewing.pubkey());
    assert_eq!(
        identity.nullifier_pubkey().unwrap(),
        expected_nullifier_pubkey
    );
    assert_eq!(
        identity.shielded_address().unwrap().nullifier_pubkey,
        expected_nullifier_pubkey
    );
}

pub(crate) fn encrypted_slot_round_trips_to_the_pda(
    world: &mut KeypairWorld,
    a: String,
    b: String,
) {
    let alice = world.vk(&a);
    let bob = world.vk(&b);
    let identity = ShieldedPda::from_key_exchange(pda(7), alice, &bob.pubkey()).unwrap();
    let salt = random_salt();
    let plaintext = b"pda utxo".to_vec();
    let ciphertext = alice
        .encrypt_slot(&identity.viewing_pubkey(), &plaintext, salt, 0)
        .unwrap();
    assert_eq!(
        identity
            .decrypt_utxo(&ciphertext, &alice.pubkey(), salt, 0)
            .unwrap(),
        plaintext
    );
}

pub(crate) fn owner_tag_is_not_hashed() {
    let address = pda(7);
    let as_pda = PublicKey::from_pda(&address);
    let as_ed25519 = PublicKey::from_ed25519(address.as_array());
    assert_ne!(as_pda, as_ed25519);
    assert_eq!(
        as_pda.confidential_view_tag().unwrap(),
        as_ed25519.confidential_view_tag().unwrap()
    );
    assert_eq!(
        as_pda.owner_proof_input_hash().unwrap(),
        as_ed25519.owner_proof_input_hash().unwrap()
    );
}

pub(crate) fn pda_public_key_encoding_round_trips() {
    let address = pda(7);
    let tagged = PublicKey::from_pda(&address);
    assert_eq!(tagged.curve().unwrap(), Curve::Pda);
    assert_eq!(tagged.as_pda().unwrap(), address.to_bytes());
    assert_eq!(
        tagged.as_ed25519(),
        Err(KeypairError::InvalidSignatureType(u8::from(Curve::Pda)))
    );

    let parsed = PublicKey::from_bytes(*tagged.as_bytes()).unwrap();
    assert_eq!(parsed, tagged);

    let mut padded = *tagged.as_bytes();
    padded[33] = 1;
    assert_eq!(
        PublicKey::from_bytes(padded),
        Err(KeypairError::InvalidPublicKey)
    );
}

pub(crate) fn solana_address_returns_the_pda(world: &mut KeypairWorld, a: String) {
    let alice = world.vk(&a);
    let identity = ShieldedPda::from_key_exchange(pda(7), alice, &alice.pubkey()).unwrap();
    assert_eq!(
        identity
            .shielded_address()
            .unwrap()
            .solana_address()
            .unwrap(),
        pda(7)
    );
    assert_eq!(identity.pda(), &pda(7));
}
