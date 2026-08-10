use p256::{elliptic_curve::rand_core::OsRng, SecretKey};
use zolana_keypair::P256Pubkey;
use zolana_squads_client::{seed_viewing_key_account, ViewingKeyAccountSeed};
use zolana_squads_interface::types::Address;
use zolana_squads_sdk::{
    crypto,
    viewing_key_account::{recover_nullifier_secret, recover_shared_secret},
};

#[test]
fn seeded_account_round_trips_via_auditor_key() {
    let shared = SecretKey::random(&mut OsRng);
    let ephemeral = SecretKey::random(&mut OsRng);
    let auditor = SecretKey::random(&mut OsRng);
    let auditor_pk = P256Pubkey::from_p256(&auditor.public_key());
    let nullifier_secret = [7u8; 32];

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
        &nullifier_secret,
        &[],
        &[auditor_pk],
    )
    .expect("seed account");

    let ephemeral_pk =
        P256Pubkey::from_bytes(account.key_ciphertext_ephemeral).expect("ephemeral pk");
    let ct = account.auditor_key_ciphertexts.first().expect("auditor ct");
    let recovered = recover_shared_secret(&auditor, &ephemeral_pk, ct).expect("recover shared");

    let mut shared_be = [0u8; 32];
    shared_be.copy_from_slice(shared.to_bytes().as_slice());
    assert_eq!(recovered, shared_be);
    assert_eq!(
        account.shared_viewing_key_commitment,
        crypto::hash_field(&shared_be).expect("commitment")
    );

    let recovered_pubkey = P256Pubkey::from_p256(
        &SecretKey::from_bytes(&recovered.into())
            .expect("shared sk")
            .public_key(),
    );
    assert_eq!(recovered_pubkey.as_bytes(), &account.shared_viewing_key);

    let shared_sk = SecretKey::from_bytes(&recovered.into()).expect("shared sk");
    let recovered_null = recover_nullifier_secret(
        &shared_sk,
        &ephemeral_pk,
        &account.encrypted_nullifier_secret,
    )
    .expect("recover nullifier");
    assert_eq!(recovered_null.as_slice(), &nullifier_secret[1..32]);
}
