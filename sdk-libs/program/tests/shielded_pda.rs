//! `ShieldedPda`: PDA-bound roles derived from a viewing key exchange or a
//! holder's viewing secret.

use solana_address::Address;
use spr_keypair::{
    derivation::PdaRoleExpansion, random_salt, Curve, KeypairError, NullifierKey,
    ShieldedKeypairTrait, ViewingKey, ViewingKeyTrait,
};
use spr_program::ShieldedPda;

fn pda(n: u8) -> Address {
    Address::new_from_array([n; 32])
}

fn alice() -> ViewingKey {
    ViewingKey::from_bytes(&[1; 32])
}

fn bob() -> ViewingKey {
    ViewingKey::from_bytes(&[2; 32])
}

/// spr-keypair's related-peer ECDH test asserts that no forged seed reaches the
/// roles `PdaRoleExpansion` derives from the canonical viewing secret. This pins
/// `from_viewing_key` to exactly those roles, so that test covers `ShieldedPda`.
#[test]
fn from_viewing_key_uses_the_canonical_viewing_secret() {
    let alice = alice();
    let identity = ShieldedPda::from_viewing_key(pda(7), &alice).unwrap();
    let expansion = PdaRoleExpansion::new(&alice.secret_bytes(), pda(7).to_bytes());
    assert_eq!(
        identity.nullifier_pubkey().unwrap(),
        expansion.nullifier_key().unwrap().pubkey().unwrap()
    );
    assert_eq!(
        identity.viewing_pubkey(),
        expansion.viewing_key().unwrap().pubkey()
    );
}

#[test]
fn both_parties_derive_the_same_identity() {
    let alice = &alice();
    let bob = &bob();
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

#[test]
fn pda_binding_separates_identities() {
    let alice = &alice();
    let bob = &bob();
    let first = ShieldedPda::from_key_exchange(pda(7), alice, &bob.pubkey()).unwrap();
    let second = ShieldedPda::from_key_exchange(pda(8), alice, &bob.pubkey()).unwrap();
    assert_ne!(first.viewing_pubkey(), second.viewing_pubkey());
    assert_ne!(
        first.shielded_address().unwrap().nullifier_pubkey,
        second.shielded_address().unwrap().nullifier_pubkey
    );
}

#[test]
fn from_viewing_key_is_deterministic_and_distinct() {
    let alice = &alice();
    let bob = &bob();
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

#[test]
fn sole_holder_identity() {
    let alice = &alice();
    let bob = &bob();
    let sole = ShieldedPda::from_key_exchange(pda(7), alice, &alice.pubkey()).unwrap();
    let paired = ShieldedPda::from_key_exchange(pda(7), alice, &bob.pubkey()).unwrap();
    assert_ne!(sole.viewing_pubkey(), paired.viewing_pubkey());
    assert_ne!(
        sole.shielded_address().unwrap().nullifier_pubkey,
        paired.shielded_address().unwrap().nullifier_pubkey
    );
}

#[test]
fn pda_cannot_sign() {
    let alice = &alice();
    let identity = ShieldedPda::from_key_exchange(pda(7), alice, &alice.pubkey()).unwrap();
    assert_eq!(identity.curve(), Curve::Pda);
    assert_eq!(
        identity.sign_message(b"private_tx_hash"),
        Err(KeypairError::PdaCannotSign)
    );
}

#[test]
fn from_parts_holds_supplied_roles() {
    let viewing = alice();
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

#[test]
fn encrypted_slot_round_trips_to_the_pda() {
    let alice = &alice();
    let bob = &bob();
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

#[test]
fn solana_address_returns_the_pda() {
    let alice = &alice();
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
