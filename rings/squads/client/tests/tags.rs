use zolana_keypair::X25519Keypair;
use zolana_squads_client::{
    seed_viewing_key_account,
    tags::{account_query_tags, account_view_tag},
    ViewingKeyAccountSeed,
};
use zolana_squads_interface::types::Address;

#[test]
fn account_tag_is_shared_viewing_key_u_coordinate() {
    let shared = X25519Keypair::new();
    let ephemeral = X25519Keypair::new();
    let auditor = X25519Keypair::new();
    let auditor_pk = auditor.pubkey();

    let account = seed_viewing_key_account(
        ViewingKeyAccountSeed {
            owner: Address::new_from_array([1u8; 32]),
            owner_kind: 1,
            state: 1,
            encryption_scheme: zolana_squads_interface::constants::ENCRYPTION_SCHEME_X25519_AES,
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
    // shared viewing key's canonical u coordinate.
    let shared_pk = shared.pubkey();
    let mut expected = [0u8; 32];
    expected.copy_from_slice(shared_pk.as_bytes().get(1..).expect("u coordinate"));

    assert_eq!(account_view_tag(&account), expected);
    assert_eq!(account_query_tags(&account), vec![expected]);
}
