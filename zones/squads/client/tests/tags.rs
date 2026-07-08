use p256::{elliptic_curve::rand_core::OsRng, SecretKey};
use zolana_keypair::P256Pubkey;
use zolana_squads_client::{
    seed_viewing_key_account,
    tags::{account_query_tags, account_view_tag},
    ViewingKeyAccountSeed,
};
use zolana_squads_interface::types::Address;

#[test]
fn account_tag_is_shared_viewing_key_x_coordinate() {
    let shared = SecretKey::random(&mut OsRng);
    let ephemeral = SecretKey::random(&mut OsRng);
    let auditor = SecretKey::random(&mut OsRng);
    let auditor_pk = P256Pubkey::from_p256(&auditor.public_key());

    let account = seed_viewing_key_account(
        ViewingKeyAccountSeed {
            owner: Address::new_from_array([1u8; 32]),
            owner_kind: 1,
            state: 1,
            encryption_scheme: 0,
            key_nonce: 0,
        },
        &shared,
        &ephemeral,
        &[9u8; 32],
        &[],
        &[auditor_pk],
    )
    .expect("seed account");

    // The tag the caller feeds the prover as sender/recipient view tag: the
    // shared viewing key's X coordinate.
    let shared_pk = P256Pubkey::from_p256(&shared.public_key());
    let mut expected = [0u8; 32];
    expected.copy_from_slice(&shared_pk.as_bytes()[1..33]);

    assert_eq!(account_view_tag(&account), expected);
    assert_eq!(account_query_tags(&account), vec![expected]);
}
