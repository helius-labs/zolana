use zolana_keypair::X25519Keypair;
use zolana_keypair::X25519Pubkey;
use zolana_squads_client::{seed_viewing_key_account, ViewingKeyAccountSeed};
use zolana_squads_interface::types::Address;
use zolana_squads_sdk::{
    crypto,
    viewing_key_account::{recover_nullifier_secret, recover_shared_secret},
};

#[test]
fn seeded_account_round_trips_via_auditor_key() {
    let shared = X25519Keypair::new();
    let ephemeral = X25519Keypair::new();
    let auditor = X25519Keypair::new();
    let auditor_pk = auditor.pubkey();
    let nullifier_secret = [7u8; 32];

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
        &nullifier_secret,
        &[],
        &[auditor_pk],
    )
    .expect("seed account");

    let ephemeral_pk =
        X25519Pubkey::from_bytes(account.key_ciphertext_ephemeral).expect("ephemeral pk");
    let ct = account.auditor_key_ciphertexts.first().expect("auditor ct");
    let recovered = recover_shared_secret(&auditor, &ephemeral_pk, ct).expect("recover shared");

    let shared_be = *shared.secret_bytes();
    assert_eq!(recovered, shared_be);
    assert_eq!(
        account.shared_viewing_key_commitment,
        crypto::hash_field(&shared_be).expect("commitment")
    );

    let shared_sk = X25519Keypair::from_bytes(&recovered);
    assert_eq!(shared_sk.pubkey().as_bytes(), &account.shared_viewing_key);

    let recovered_null = recover_nullifier_secret(
        &shared_sk,
        &ephemeral_pk,
        &account.encrypted_nullifier_secret,
    )
    .expect("recover nullifier");
    assert_eq!(
        recovered_null.as_slice(),
        nullifier_secret.get(1..).expect("low 31 bytes")
    );
}
