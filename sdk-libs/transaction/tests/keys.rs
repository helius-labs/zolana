use zolana_keypair::{ShieldedKeypair, SigningKey};
use zolana_transaction::{
    instructions::merge::{
        merge_dummy_nullifier, merge_output_blinding, merge_private_tx_blinding,
    },
    keys::*,
    TransactionError,
};

fn wallet(seed: u8) -> ShieldedKeypair {
    ShieldedKeypair::from_keypair(SigningKey::from_ed25519_bytes(&[seed; 32]))
        .expect("Ed25519 keypair")
}

/// The batch answers what the key answers directly. A holder that drifts
/// here spends a different UTXO than the wallet believes it is spending.
#[test]
fn derive_nullifier_matches_the_key_itself() {
    let keypair = wallet(7);
    let utxo_hash = [3u8; 32];
    let blinding = [5u8; 32];

    let derived = keypair
        .derive(&[DeriveRequest::Nullifier {
            utxo_hash,
            blinding,
        }])
        .expect("derive");

    assert_eq!(
        derived.first().copied(),
        Some(keypair.nullifier(&utxo_hash, &blinding).expect("nullifier"))
    );
}

#[test]
fn derive_answers_a_batch_in_request_order() {
    let keypair = wallet(7);
    let first_nullifier = [11u8; 32];

    let derived = keypair
        .derive(&[
            DeriveRequest::MergeOutputBlinding { first_nullifier },
            DeriveRequest::MergeDummyNullifier {
                first_nullifier,
                slot_index: 2,
            },
            DeriveRequest::MergePrivateTxBlinding { first_nullifier },
        ])
        .expect("derive");

    assert_eq!(
        derived,
        vec![
            merge_output_blinding(&keypair.nullifier_key, &first_nullifier).unwrap(),
            merge_dummy_nullifier(&keypair.nullifier_key, &first_nullifier, 2).unwrap(),
            merge_private_tx_blinding(&keypair.nullifier_key, &first_nullifier).unwrap(),
        ]
    );
}

#[test]
fn transaction_keys_match_the_viewing_key_derivation() {
    let keypair = wallet(7);
    let first_nullifier = [13u8; 32];

    let keys = keypair
        .transaction_keys(&[TransactionKeyRequest {
            viewing_pubkey: keypair.viewing_pubkey(),
            first_nullifier,
        }])
        .expect("transaction keys");

    assert_eq!(
        keys.first().map(|key| key.pubkey()),
        Some(
            keypair
                .viewing_key
                .get_transaction_viewing_key(&first_nullifier)
                .expect("transaction viewing key")
                .pubkey()
        )
    );
}

/// A request naming a key this holder does not have is refused rather than
/// answered with the wrong key.
#[test]
fn a_foreign_viewing_key_is_refused() {
    let keypair = wallet(7);
    let stranger = wallet(9);

    assert_eq!(
        keypair
            .transaction_keys(&[TransactionKeyRequest {
                viewing_pubkey: stranger.viewing_pubkey(),
                first_nullifier: [0u8; 32],
            }])
            .err(),
        Some(TransactionError::UnknownViewingKey)
    );
}

/// Retired keys stay available, and enumeration preserves the caller's order.
#[test]
fn retired_viewing_keys_are_kept_after_the_current_one() {
    let keypair = wallet(7);
    let retired = wallet(9).viewing_key.clone();
    let keys = LocalShieldedKeys::new(
        keypair.shielded_address().unwrap(),
        vec![keypair.viewing_key.clone(), retired.clone()],
        keypair.nullifier_key.clone(),
    )
    .expect("keys");

    assert_eq!(
        keys.viewing_public_keys(),
        vec![keypair.viewing_pubkey(), retired.pubkey()]
    );
    let retired_first = LocalShieldedKeys::new(
        keypair.shielded_address().unwrap(),
        vec![retired.clone(), keypair.viewing_key.clone()],
        keypair.nullifier_key.clone(),
    )
    .unwrap();
    assert_eq!(
        retired_first.viewing_public_keys(),
        vec![retired.pubkey(), keypair.viewing_pubkey()]
    );
}

#[test]
fn a_holder_without_the_addresss_own_viewing_key_is_refused() {
    let keypair = wallet(7);
    let stranger = wallet(9);

    assert_eq!(
        LocalShieldedKeys::new(
            keypair.shielded_address().unwrap(),
            vec![stranger.viewing_key.clone()],
            keypair.nullifier_key.clone(),
        )
        .err(),
        Some(TransactionError::AuthorityViewingKeyMismatch)
    );
}

#[test]
fn local_decryption_batches_route_labels_and_retired_keys() {
    let owner = wallet(7);
    let retired = wallet(9).viewing_key;
    let keys = LocalShieldedKeys::new(
        owner.shielded_address().unwrap(),
        vec![owner.viewing_key.clone(), retired.clone()],
        owner.nullifier_key.clone(),
    )
    .unwrap();
    let tx = zolana_keypair::ViewingKey::new();
    let salt = [11; 16];
    let current_ciphertext = tx
        .encrypt_slot(&owner.viewing_pubkey(), b"current note", salt, 3)
        .unwrap();
    let retired_ciphertext = tx
        .encrypt_slot(&retired.pubkey(), b"retired note", salt, 5)
        .unwrap();
    let ring_ciphertext = tx
        .encrypt_ring_deposit(&retired.pubkey(), b"ring deposit", salt)
        .unwrap();
    let requests = [
        DecryptRequest {
            ciphertext: &retired_ciphertext,
            viewing_pubkey: retired.pubkey(),
            tx_viewing_pubkey: tx.pubkey(),
            salt,
            slot_index: 5,
            label: DecryptLabel::Utxo,
        },
        DecryptRequest {
            ciphertext: &current_ciphertext,
            viewing_pubkey: owner.viewing_pubkey(),
            tx_viewing_pubkey: tx.pubkey(),
            salt,
            slot_index: 3,
            label: DecryptLabel::Utxo,
        },
        DecryptRequest {
            ciphertext: &ring_ciphertext,
            viewing_pubkey: retired.pubkey(),
            tx_viewing_pubkey: tx.pubkey(),
            salt,
            slot_index: 0,
            label: DecryptLabel::RingDeposit,
        },
    ];
    assert_eq!(
        keys.decrypt(&requests).unwrap(),
        vec![
            b"retired note".to_vec(),
            b"current note".to_vec(),
            b"ring deposit".to_vec()
        ]
    );
    let mut foreign = *requests.first().unwrap();
    foreign.viewing_pubkey = wallet(12).viewing_pubkey();
    assert_eq!(
        keys.decrypt(&[foreign]),
        Err(TransactionError::UnknownViewingKey)
    );
}

#[test]
fn key_batches_preserve_empty_mixed_and_repeated_requests() {
    let owner = wallet(7);
    let retired = wallet(9).viewing_key;
    let keys = LocalShieldedKeys::new(
        owner.shielded_address().unwrap(),
        vec![owner.viewing_key.clone(), retired.clone()],
        owner.nullifier_key.clone(),
    )
    .unwrap();
    assert!(keys.derive(&[]).unwrap().is_empty());
    assert!(keys.decrypt(&[]).unwrap().is_empty());
    assert!(keys.transaction_keys(&[]).unwrap().is_empty());
    let first_nullifier = [3; 32];
    let utxo_hash = [4; 32];
    let blinding = [5; 32];
    let nullifier = DeriveRequest::Nullifier {
        utxo_hash,
        blinding,
    };
    let requests = [
        nullifier,
        DeriveRequest::MergePrivateTxBlinding { first_nullifier },
        DeriveRequest::MergeDummyNullifier {
            first_nullifier,
            slot_index: 7,
        },
        nullifier,
        DeriveRequest::MergeOutputBlinding { first_nullifier },
    ];
    let expected_nullifier = owner.nullifier(&utxo_hash, &blinding).unwrap();
    assert_eq!(
        keys.derive(&requests).unwrap(),
        vec![
            expected_nullifier,
            merge_private_tx_blinding(&owner.nullifier_key, &first_nullifier).unwrap(),
            merge_dummy_nullifier(&owner.nullifier_key, &first_nullifier, 7).unwrap(),
            expected_nullifier,
            merge_output_blinding(&owner.nullifier_key, &first_nullifier).unwrap(),
        ]
    );
    let requests = [
        TransactionKeyRequest {
            viewing_pubkey: retired.pubkey(),
            first_nullifier,
        },
        TransactionKeyRequest {
            viewing_pubkey: owner.viewing_pubkey(),
            first_nullifier: [6; 32],
        },
        TransactionKeyRequest {
            viewing_pubkey: retired.pubkey(),
            first_nullifier,
        },
    ];
    let retired_key = retired
        .get_transaction_viewing_key(&first_nullifier)
        .unwrap()
        .pubkey();
    let current_key = owner
        .viewing_key
        .get_transaction_viewing_key(&[6; 32])
        .unwrap()
        .pubkey();
    assert_eq!(
        keys.transaction_keys(&requests)
            .unwrap()
            .into_iter()
            .map(|key| key.pubkey())
            .collect::<Vec<_>>(),
        vec![retired_key, current_key, retired_key]
    );
    assert_ne!(retired_key, current_key);
}
