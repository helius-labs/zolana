//! Behavior of the host mirror of the `auditor_key_encryption` circuit crypto.

use custom_ring_sdk::encryption::{
    auditor_view_tag, decrypt_tx_viewing_sk, derive_audit_shared_secret, encrypt_tx_viewing_sk,
    pack32_to_2fe, pack33_to_2fe, AuditEncryptionError, AuditorEncryption, AuditorMessage,
    AUDITOR_MESSAGE_LEN,
};
use zolana_interface::instruction::MessageData;
use zolana_keypair::ViewingKey;

fn tx_viewing_sk() -> [u8; 32] {
    let mut sk = [0u8; 32];
    for (index, byte) in sk.iter_mut().enumerate() {
        *byte = 0x40 ^ (index as u8);
    }
    sk[0] = 0x01;
    sk
}

fn hex_bytes<const N: usize>(hex_str: &str) -> [u8; N] {
    let decoded = hex::decode(hex_str).expect("valid hex");
    <[u8; N]>::try_from(decoded.as_slice()).expect("expected byte length")
}

#[test]
fn encrypt_decrypt_recovers_the_scalar() {
    let auditor = ViewingKey::new();
    let auditor_pk = auditor.pubkey();
    let scalar = tx_viewing_sk();

    let sealed = AuditorEncryption::new(&scalar, &auditor_pk).expect("encrypt");
    assert_ne!(sealed.message.ciphertext, scalar);

    // The auditor holds only its own secret and reads the ephemeral key off the
    // published message.
    let eph_pk = sealed.message.ephemeral_pubkey().expect("valid eph pk");
    let recovered =
        decrypt_tx_viewing_sk(&auditor, &eph_pk, &sealed.message.ciphertext).expect("decrypt");
    assert_eq!(*recovered, scalar);
}

#[test]
fn each_encryption_uses_a_fresh_ephemeral_key() {
    let auditor_pk = ViewingKey::new().pubkey();
    let scalar = tx_viewing_sk();

    let first = AuditorEncryption::new(&scalar, &auditor_pk).expect("first");
    let second = AuditorEncryption::new(&scalar, &auditor_pk).expect("second");

    assert_ne!(*first.ephemeral_sk, *second.ephemeral_sk);
    assert_ne!(first.message.eph_pk, second.message.eph_pk);
    // Keystream reuse over one plaintext would produce the same ciphertext.
    assert_ne!(first.message.ciphertext, second.message.ciphertext);
}

#[test]
fn wrong_auditor_key_does_not_recover_the_scalar() {
    let auditor = ViewingKey::new();
    let impostor = ViewingKey::new();
    let scalar = tx_viewing_sk();

    let sealed = AuditorEncryption::new(&scalar, &auditor.pubkey()).expect("encrypt");
    let eph_pk = sealed.message.ephemeral_pubkey().expect("valid eph pk");

    let recovered = decrypt_tx_viewing_sk(&impostor, &eph_pk, &sealed.message.ciphertext)
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
    assert_eq!(
        derive_audit_shared_secret(&sender_dh, &ephemeral.pubkey(), &auditor.pubkey())
            .expect("sender secret"),
        derive_audit_shared_secret(&auditor_dh, &ephemeral.pubkey(), &auditor.pubkey())
            .expect("auditor secret")
    );
}

#[test]
fn shared_secret_is_deterministic_and_key_bound() {
    let auditor_pk = ViewingKey::new().pubkey();
    let other_auditor_pk = ViewingKey::new().pubkey();
    let eph_pk = ViewingKey::new().pubkey();
    let other_eph_pk = ViewingKey::new().pubkey();
    let dh = [7u8; 32];

    let secret = derive_audit_shared_secret(&dh, &eph_pk, &auditor_pk).expect("secret");
    assert_eq!(
        secret,
        derive_audit_shared_secret(&dh, &eph_pk, &auditor_pk).expect("same secret")
    );
    assert_ne!(
        secret,
        derive_audit_shared_secret(&dh, &other_eph_pk, &auditor_pk).expect("other eph")
    );
    assert_ne!(
        secret,
        derive_audit_shared_secret(&dh, &eph_pk, &other_auditor_pk).expect("other auditor")
    );
    assert_ne!(
        secret,
        derive_audit_shared_secret(&[8u8; 32], &eph_pk, &auditor_pk).expect("other dh")
    );
}

#[test]
fn caller_supplied_ephemeral_key_round_trips() {
    let auditor = ViewingKey::new();
    let ephemeral = ViewingKey::new();
    let eph_pk = ephemeral.pubkey();
    let scalar = tx_viewing_sk();

    let ciphertext = encrypt_tx_viewing_sk(&scalar, ephemeral, &auditor.pubkey()).expect("encrypt");
    let recovered = decrypt_tx_viewing_sk(&auditor, &eph_pk, &ciphertext).expect("decrypt");
    assert_eq!(*recovered, scalar);
}

#[test]
fn message_data_round_trip() {
    let auditor_pk = ViewingKey::new().pubkey();
    let sealed = AuditorEncryption::new(&tx_viewing_sk(), &auditor_pk).expect("encrypt");

    let message = sealed.message.to_message_data(&auditor_pk);
    assert_eq!(message.view_tag, auditor_view_tag(&auditor_pk));
    assert_eq!(message.view_tag, auditor_pk.x());
    assert_eq!(message.data.len(), AUDITOR_MESSAGE_LEN);
    let (eph_pk, ciphertext) = message
        .data
        .split_at_checked(33)
        .expect("65 bytes split at 33");
    assert_eq!(eph_pk, sealed.message.eph_pk.as_slice());
    assert_eq!(ciphertext, sealed.message.ciphertext.as_slice());

    assert_eq!(
        AuditorMessage::parse(&message, &auditor_pk).expect("parse"),
        sealed.message
    );
}

#[test]
fn parse_rejects_a_foreign_view_tag() {
    let auditor_pk = ViewingKey::new().pubkey();
    let other_pk = ViewingKey::new().pubkey();
    let sealed = AuditorEncryption::new(&tx_viewing_sk(), &auditor_pk).expect("encrypt");

    let message = sealed.message.to_message_data(&other_pk);
    assert_eq!(
        AuditorMessage::parse(&message, &auditor_pk),
        Err(AuditEncryptionError::ViewTagMismatch)
    );
}

#[test]
fn parse_rejects_wrong_data_lengths() {
    let auditor_pk = ViewingKey::new().pubkey();
    let sealed = AuditorEncryption::new(&tx_viewing_sk(), &auditor_pk).expect("encrypt");
    let valid = sealed.message.to_message_data(&auditor_pk);

    let mut short = valid.clone();
    short.data.pop();
    assert_eq!(
        AuditorMessage::parse(&short, &auditor_pk),
        Err(AuditEncryptionError::MessageLength(64))
    );

    let mut long = valid.clone();
    long.data.push(0);
    assert_eq!(
        AuditorMessage::parse(&long, &auditor_pk),
        Err(AuditEncryptionError::MessageLength(66))
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

/// `lo = 0x00 || bytes[0..31]`, `hi = bytes[31]` right-aligned; hand-computed for
/// the ascending input 0x01..0x20 so a change on either side of the language
/// boundary shows up here.
#[test]
fn pack32_layout() {
    let mut input = [0u8; 32];
    for (index, byte) in input.iter_mut().enumerate() {
        *byte = (index as u8) + 1;
    }

    let (lo, hi) = pack32_to_2fe(&input);
    assert_eq!(
        lo,
        hex_bytes::<32>("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
    );
    assert_eq!(
        hi,
        hex_bytes::<32>("0000000000000000000000000000000000000000000000000000000000000020")
    );
}

/// `lo = 0x00 || key[0..31]`, `hi = key[31] * 256 + key[32]`; hand-computed for
/// the ascending input 0x01..0x21.
#[test]
fn pack33_layout() {
    let mut input = [0u8; 33];
    for (index, byte) in input.iter_mut().enumerate() {
        *byte = (index as u8) + 1;
    }

    let (lo, hi) = pack33_to_2fe(&input);
    assert_eq!(
        lo,
        hex_bytes::<32>("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
    );
    assert_eq!(
        hi,
        hex_bytes::<32>("0000000000000000000000000000000000000000000000000000000000002021")
    );
}
