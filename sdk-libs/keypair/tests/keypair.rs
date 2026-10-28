mod cases;

use std::collections::HashMap;

use spr_keypair::{KeypairError, PublicKey, ShieldedKeypair, SigningKey, ViewingKey};

#[derive(Default)]
pub struct KeypairWorld {
    pub viewing: HashMap<String, ViewingKey>,
    pub shielded: HashMap<String, ShieldedKeypair>,
    pub signing: HashMap<String, SigningKey>,
    pub tagged: HashMap<String, PublicKey>,
    pub sigs: HashMap<String, [u8; 64]>,
    pub last_error: Option<KeypairError>,
}

impl KeypairWorld {
    pub fn vk(&self, name: &str) -> &ViewingKey {
        self.viewing.get(name).expect("viewing key not set")
    }

    pub fn keypair(&self, name: &str) -> &ShieldedKeypair {
        self.shielded.get(name).expect("shielded keypair not set")
    }

    pub fn sig_key(&self, name: &str) -> &SigningKey {
        self.signing.get(name).expect("signing key not set")
    }

    pub fn tag(&self, name: &str) -> PublicKey {
        *self.tagged.get(name).expect("tagged pubkey not set")
    }
}

pub fn scalar_bytes(n: u8) -> [u8; 32] {
    let mut scalar = [0u8; 32];
    scalar[31] = n;
    scalar
}

#[test]
fn hash_and_owner_vectors_are_stable() {
    let mut world = KeypairWorld::default();
    cases::hashing::sha256_be_matches("abc".into());
    cases::hashing::sha256_full_matches("abc".into());
    cases::common::signing_key_from_seed(&mut world, "g".into(), 1);
    cases::hashing::pubkey_field_golden(
        &mut world,
        "g".into(),
        serde_json::from_str::<serde_json::Value>(include_str!(
            "../../../test-vectors/key_derivation.json"
        ))
        .unwrap()["owner"]["owner_proof_input_hash"]
            .as_str()
            .unwrap()
            .into(),
    );
    cases::hashing::pubkey_field_stable(&mut world, "g".into());
    cases::common::random_shielded_keypair(&mut world, "alice".into());
    cases::hashing::owner_hash_stable(&mut world, "alice".into());
    cases::hashing::owner_hash_binds_nullifier(&mut world, "alice".into());
}

#[test]
fn nullifiers_bind_every_input_and_match_the_golden_vector() {
    let mut world = KeypairWorld::default();
    cases::common::random_signing_key(&mut world, "k".into());
    cases::nullifier::nullifier_deterministic(&mut world, "k".into());
    cases::common::random_signing_key(&mut world, "a".into());
    cases::common::random_signing_key(&mut world, "b".into());
    cases::nullifier::distinct_nullifier_secrets(&mut world, "a".into(), "b".into());
    cases::nullifier::nullifier_binds_inputs();
    cases::nullifier::nullifier_pubkey_golden(
        7,
        "2ece7cecb48850fb1762bea0a87c4f8290c40f90ac43b9dae85eed13b2e9af8c".into(),
    );
}

#[test]
fn nullifier_roles_are_hsm_derivable() {
    cases::nullifier::derivation_seed_matches_rail_primitives();
    cases::nullifier::eddsa_rail_matches_signature_entry_point();
    cases::nullifier::ed25519_keypair_derives_both_keys_from_one_signature();
    cases::nullifier::solana_keypair_matches_eddsa_rail();
    cases::nullifier::primitives_refuse_derivation_inputs();
}

#[test]
fn public_key_encodings_are_typed_and_canonical() {
    let mut world = KeypairWorld::default();
    cases::pubkey::tag_ed25519(&mut world, 7, "eddsa".into());
    cases::pubkey::scheme_is_ed25519(&mut world, "eddsa".into());
    cases::pubkey::last_byte_zero(&mut world, "eddsa".into());
    let key = world.tag("eddsa");
    assert_eq!(key.as_ed25519().unwrap(), [7u8; 32]);
    assert_eq!(PublicKey::from_bytes(*key.as_bytes()).unwrap(), key);
    cases::pubkey::parse_public_key_bad_prefix(&mut world, 0);
    cases::pubkey::public_key_parse_fails(&mut world, KeypairError::InvalidSignatureType(0));
    cases::pubkey::parse_public_key_bad_prefix(&mut world, 9);
    cases::pubkey::public_key_parse_fails(&mut world, KeypairError::InvalidSignatureType(9));
    cases::pubkey::parse_ed25519_nonzero_pad(&mut world);
    cases::pubkey::public_key_parse_fails(&mut world, KeypairError::InvalidPublicKey);
}

#[test]
fn shielded_keypair_facade_round_trips_full_transfers() {
    let mut world = KeypairWorld::default();
    cases::common::random_shielded_keypair(&mut world, "alice".into());
    cases::shielded::address_consistent(&mut world, "alice".into());
    cases::shielded::facade_sign_nullifier(&mut world, "alice".into());

    cases::common::random_signing_key(&mut world, "signing".into());
    cases::common::random_viewing_key(&mut world, "viewing".into());
    cases::shielded::from_parts_keeps_detached_viewing_key(
        &mut world,
        "signing".into(),
        "viewing".into(),
    );
    cases::shielded::from_keypair_roots_both_keys_in_one_seed(&mut world, "signing".into());
    cases::shielded::new_derives_viewing_key_from_signing_key(&mut world, "alice".into());
    cases::shielded::random_constructors_pick_their_rail();
    cases::shielded::solana_signer_matches_solana_keypair();

    cases::common::random_shielded_keypair(&mut world, "sender".into());
    cases::common::random_shielded_keypair(&mut world, "recipient".into());
    cases::shielded::facade_shared_tags(&mut world, "sender".into(), "recipient".into());
    cases::shielded::facade_transfer(&mut world, "sender".into(), "recipient".into());

    cases::shielded::text_address_round_trips(&mut world, "sender".into());
    cases::shielded::text_address_rejects_malformed();
}

#[test]
fn ed25519_signatures_are_deterministic_and_reject_tampering() {
    let mut world = KeypairWorld::default();
    cases::common::random_signing_key(&mut world, "k".into());
    cases::signing::sign_message(
        &mut world,
        "k".into(),
        "private_tx_hash".into(),
        "sig".into(),
    );
    cases::signing::verifies(
        &mut world,
        "k".into(),
        "sig".into(),
        "private_tx_hash".into(),
    );
    cases::signing::signing_scheme_ed25519(&mut world, "k".into());
    cases::signing::sign_message(&mut world, "k".into(), "a".into(), "a-sig".into());
    cases::signing::does_not_verify(&mut world, "k".into(), "a-sig".into(), "b".into());
    cases::signing::does_not_verify_tampered(&mut world, "k".into(), "a-sig".into(), "a".into());
    cases::signing::signs_identically(&mut world, "k".into(), "same".into());
    cases::signing::secret_roundtrip(&mut world, "k".into());
    cases::signing::new_ed25519_is_a_working_ed25519_key();
}

#[test]
fn encrypted_slots_are_unique_and_recipient_bound() {
    let mut world = KeypairWorld::default();
    for name in ["sender", "alice", "stranger"] {
        cases::common::random_viewing_key(&mut world, name.into());
    }
    cases::transaction::slot_round_trips(&mut world, "sender".into(), "alice".into());
    cases::transaction::distinct_slots(&mut world, "sender".into(), "alice".into());
    cases::transaction::stranger_cannot(
        &mut world,
        "stranger".into(),
        "sender".into(),
        "alice".into(),
    );
    cases::common::viewing_key_from_scalar(&mut world, "eph".into(), 1);
    cases::common::viewing_key_from_scalar(&mut world, "rcpt".into(), 2);
    cases::transaction::golden_decrypts(&mut world, "rcpt".into(), "eph".into());
}

#[test]
fn pda_identities_derive_from_the_viewing_key_exchange() {
    let mut world = KeypairWorld::default();
    cases::common::random_viewing_key(&mut world, "alice".into());
    cases::common::random_viewing_key(&mut world, "bob".into());
    cases::pda::both_parties_derive_the_same_identity(&mut world, "alice".into(), "bob".into());
    cases::pda::pda_binding_separates_identities(&mut world, "alice".into(), "bob".into());
    cases::pda::sole_holder_identity(&mut world, "alice".into(), "bob".into());
    cases::pda::from_viewing_key_is_deterministic_and_distinct(
        &mut world,
        "alice".into(),
        "bob".into(),
    );
    cases::pda::pda_cannot_sign(&mut world, "alice".into());
    cases::pda::from_parts_holds_supplied_roles(&mut world, "alice".into());
    cases::pda::encrypted_slot_round_trips_to_the_pda(&mut world, "alice".into(), "bob".into());
    cases::pda::solana_address_returns_the_pda(&mut world, "alice".into());
    cases::pda::owner_tag_is_not_hashed();
    cases::pda::pda_public_key_encoding_round_trips();
}

#[test]
fn domain_separation_tags_are_pairwise_distinct() {
    cases::derivation::hkdf_tags_pairwise_distinct();
    cases::derivation::poseidon_tags_pairwise_distinct();
}

#[test]
fn role_expansion_from_a_device_seed_matches_the_software_path() {
    cases::derivation::expand_roles_matches_the_software_constructor();
    cases::derivation::expand_roles_rejects_a_seed_of_the_wrong_width();
    cases::derivation::expand_roles_rejects_the_pda_curve();
}

#[test]
fn offchain_derivation_message_is_pinned_and_detected() {
    cases::derivation::application_domain_is_payload_hash();
    cases::derivation::offchain_derivation_message_golden();
    cases::derivation::derivation_inputs_are_detected();
}

#[test]
fn viewing_keys_and_tags_match_protocol_vectors() {
    let mut world = KeypairWorld::default();
    cases::common::random_viewing_key(&mut world, "alice".into());
    cases::common::random_viewing_key(&mut world, "bob".into());
    cases::viewing::ecdh_symmetric(&mut world, "alice".into(), "bob".into());
    cases::viewing::viewing_roundtrip(&mut world, "alice".into());
    cases::viewing::tags_advance(&mut world, "alice".into());
    cases::viewing::shared_tag_symmetric(&mut world, "alice".into(), "bob".into(), 0);
    cases::viewing::shared_tag_per_index(&mut world, "alice".into(), "bob".into(), 0, 1);
    cases::viewing::bootstrap_tag(&mut world, "alice".into());
    cases::viewing::tx_key_deterministic(&mut world, "alice".into());
    cases::common::viewing_key_from_scalar(&mut world, "k".into(), 1);
    cases::viewing::sender_view_tag_golden(
        &mut world,
        "k".into(),
        0,
        "00b903c62e50ee1466ff409fd4eede8da88006757c5865ef9e38975cd2a980ce".into(),
    );
}
