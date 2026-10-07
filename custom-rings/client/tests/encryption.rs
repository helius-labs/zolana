//! Behavior of the host mirror of the custom-ring circuit crypto.

use zolana_interface::instruction::MessageData;
use zolana_keypair::{KeypairError, ViewingKey};
use zolana_ring_client::{
    auditor_view_tag, AuditEncryptionError, AuditorEncryption, AuditorMessage, AUDITOR_MESSAGE_LEN,
};

fn tx_viewing_sk() -> [u8; 32] {
    let mut sk = [0u8; 32];
    for (index, byte) in sk.iter_mut().enumerate() {
        *byte = 0x40 ^ (index as u8);
    }
    sk[0] = 0x01;
    sk
}

fn tx_viewing_key() -> ViewingKey {
    ViewingKey::from_bytes(&tx_viewing_sk()).expect("valid viewing key")
}

#[test]
fn encrypt_decrypt_recovers_the_scalar() {
    let auditor = ViewingKey::new();
    let auditor_pk = auditor.pubkey();
    let scalar = tx_viewing_sk();

    let sealed = AuditorEncryption::new(&tx_viewing_key(), &auditor_pk).expect("encrypt");
    assert_ne!(sealed.message.ciphertext(), &scalar);

    let recovered = sealed.message.decrypt(&auditor).expect("decrypt");
    // The auditor holds only its own secret and reads the ephemeral key off the
    // published message.
    assert_eq!(*recovered, scalar);
}

#[test]
fn each_encryption_uses_a_fresh_ephemeral_key() {
    let auditor_pk = ViewingKey::new().pubkey();

    let first = AuditorEncryption::new(&tx_viewing_key(), &auditor_pk).expect("first");
    let second = AuditorEncryption::new(&tx_viewing_key(), &auditor_pk).expect("second");

    assert_ne!(*first.ephemeral_sk, *second.ephemeral_sk);
    assert_ne!(
        first.message.ephemeral_pubkey(),
        second.message.ephemeral_pubkey()
    );
    assert_ne!(first.message.ciphertext(), second.message.ciphertext());
    // Keystream reuse over one plaintext would produce the same ciphertext.
}

#[test]
fn wrong_auditor_key_does_not_recover_the_scalar() {
    let auditor = ViewingKey::new();
    let impostor = ViewingKey::new();
    let scalar = tx_viewing_sk();

    let sealed = AuditorEncryption::new(&tx_viewing_key(), &auditor.pubkey()).expect("encrypt");
    let recovered = sealed
        .message
        .decrypt(&impostor)
        .expect("decrypt runs, it just yields garbage");
    assert_ne!(*recovered, scalar);
}

#[test]
fn ecdh_is_symmetric_so_the_auditor_can_decrypt() {
    let auditor = ViewingKey::new();
    let ephemeral = ViewingKey::new();

    let sender_dh = ephemeral.ecdh(&auditor.pubkey()).expect("sender ecdh");
    let auditor_dh = auditor.ecdh(&ephemeral.pubkey()).expect("auditor ecdh");
    assert_eq!(sender_dh, auditor_dh);
    // Both sides therefore feed the same three inputs to the KDF.
}

#[test]
fn message_data_round_trip() {
    let auditor_pk = ViewingKey::new().pubkey();
    let sealed = AuditorEncryption::new(&tx_viewing_key(), &auditor_pk).expect("encrypt");

    let message = sealed.message.to_message_data(&auditor_pk);
    assert_eq!(message.view_tag, auditor_view_tag(&auditor_pk));
    assert_eq!(message.view_tag, auditor_pk.x());
    assert_eq!(message.data.len(), AUDITOR_MESSAGE_LEN);
    let (eph_pk, body) = message
        .data
        .split_at_checked(33)
        .expect("ephemeral key prefix");
    let (ciphertext, disclosure) = body.split_at(32);
    assert_eq!(eph_pk, sealed.message.ephemeral_pubkey_bytes());
    assert_eq!(ciphertext, sealed.message.ciphertext());
    assert_eq!(disclosure.len(), AUDITOR_MESSAGE_LEN - 65);

    assert_eq!(
        AuditorMessage::parse(&message, &auditor_pk).expect("parse"),
        sealed.message
    );
}

#[test]
fn parse_rejects_a_foreign_view_tag() {
    let auditor_pk = ViewingKey::new().pubkey();
    let other_pk = ViewingKey::new().pubkey();
    let sealed = AuditorEncryption::new(&tx_viewing_key(), &auditor_pk).expect("encrypt");

    let message = sealed.message.to_message_data(&other_pk);
    assert_eq!(
        AuditorMessage::parse(&message, &auditor_pk),
        Err(AuditEncryptionError::ViewTagMismatch)
    );
}

#[test]
fn parse_rejects_wrong_data_lengths() {
    let auditor_pk = ViewingKey::new().pubkey();
    let sealed = AuditorEncryption::new(&tx_viewing_key(), &auditor_pk).expect("encrypt");
    let valid = sealed.message.to_message_data(&auditor_pk);

    let mut short = valid.clone();
    short.data.pop();
    assert_eq!(
        AuditorMessage::parse(&short, &auditor_pk),
        Err(AuditEncryptionError::MessageLength(AUDITOR_MESSAGE_LEN - 1))
    );

    let mut long = valid.clone();
    long.data.push(0);
    assert_eq!(
        AuditorMessage::parse(&long, &auditor_pk),
        Err(AuditEncryptionError::MessageLength(AUDITOR_MESSAGE_LEN + 1))
    );

    let truncated = MessageData {
        view_tag: valid.view_tag,
        data: Vec::new(),
    };
    assert_eq!(
        AuditorMessage::parse(&truncated, &auditor_pk),
        Err(AuditEncryptionError::MessageLength(0))
    );
}

#[test]
fn parse_rejects_an_invalid_ephemeral_key() {
    let auditor_pk = ViewingKey::new().pubkey();
    let sealed = AuditorEncryption::new(&tx_viewing_key(), &auditor_pk).expect("encrypt");
    let mut message = sealed.message.to_message_data(&auditor_pk);
    message.data[..33].fill(0);
    assert_eq!(
        AuditorMessage::parse(&message, &auditor_pk),
        Err(AuditEncryptionError::Keypair(
            KeypairError::InvalidPublicKey
        ))
    );
}
