use cucumber::then;
use zolana_keypair::constants::{BLINDING_LEN, P256_PUBKEY_LEN, PUBLIC_KEY_LEN};
use zolana_keypair::{KeypairError, ViewingKey};

use crate::KeypairWorld;

const SENDER_HEADER: usize = PUBLIC_KEY_LEN + 3 * 8 + BLINDING_LEN;

fn sender_bundle(recipients: &[&ViewingKey]) -> Vec<u8> {
    let mut bundle = vec![0u8; SENDER_HEADER];
    for recipient in recipients {
        bundle.extend_from_slice(recipient.pubkey().as_bytes());
    }
    bundle
}

#[then(expr = "{string} encrypts and decrypts a transaction to {string} and {string}")]
fn round_trips(world: &mut KeypairWorld, sender: String, a: String, b: String) {
    let sender_plaintext = sender_bundle(&[world.vk(&a), world.vk(&b)]);
    let payload_a = b"recipient a".to_vec();
    let payload_b = b"recipient b".to_vec();
    let plaintexts: Vec<&[u8]> = vec![
        sender_plaintext.as_slice(),
        payload_a.as_slice(),
        payload_b.as_slice(),
    ];

    let enc = world
        .vk(&sender)
        .encrypt_transaction(&[7u8; 32], &plaintexts)
        .unwrap();
    let ciphertexts: Vec<&[u8]> = enc.ciphertexts.iter().map(|c| c.as_slice()).collect();
    let decrypted = world
        .vk(&sender)
        .decrypt_transaction(&[7u8; 32], &ciphertexts, enc.salt)
        .unwrap();

    let expected: Vec<Vec<u8>> = plaintexts.iter().map(|p| p.to_vec()).collect();
    assert_eq!(decrypted, expected);
}

#[then(expr = "{string} encrypts a transaction to {string} twice with distinct ciphertexts")]
fn duplicate_recipient_distinct(world: &mut KeypairWorld, sender: String, recipient: String) {
    let recipient = world.vk(&recipient);
    let sender_plaintext = sender_bundle(&[recipient, recipient]);
    let same = b"identical payload".to_vec();
    let plaintexts: Vec<&[u8]> = vec![
        sender_plaintext.as_slice(),
        same.as_slice(),
        same.as_slice(),
    ];

    let enc = world
        .vk(&sender)
        .encrypt_transaction(&[9u8; 32], &plaintexts)
        .unwrap();
    assert_ne!(enc.ciphertexts[1], enc.ciphertexts[2]);

    let ciphertexts: Vec<&[u8]> = enc.ciphertexts.iter().map(|c| c.as_slice()).collect();
    let decrypted = world
        .vk(&sender)
        .decrypt_transaction(&[9u8; 32], &ciphertexts, enc.salt)
        .unwrap();
    assert_eq!(decrypted, vec![sender_plaintext, same.clone(), same]);
}

#[then(expr = "{string} cannot decrypt a transaction from {string} to {string}")]
fn stranger_cannot_decrypt(
    world: &mut KeypairWorld,
    stranger: String,
    sender: String,
    recipient: String,
) {
    let sender_plaintext = sender_bundle(&[world.vk(&recipient)]);
    let payload = b"payload".to_vec();
    let plaintexts: Vec<&[u8]> = vec![sender_plaintext.as_slice(), payload.as_slice()];

    let enc = world
        .vk(&sender)
        .encrypt_transaction(&[7u8; 32], &plaintexts)
        .unwrap();
    let ciphertexts: Vec<&[u8]> = enc.ciphertexts.iter().map(|c| c.as_slice()).collect();
    assert!(world
        .vk(&stranger)
        .decrypt_transaction(&[7u8; 32], &ciphertexts, enc.salt)
        .is_err());
}

#[then(expr = "a tampered transaction from {string} to {string} is rejected")]
fn tampered_rejected(world: &mut KeypairWorld, sender: String, recipient: String) {
    let sender_plaintext = sender_bundle(&[world.vk(&recipient)]);
    let payload = b"payload".to_vec();
    let plaintexts: Vec<&[u8]> = vec![sender_plaintext.as_slice(), payload.as_slice()];

    let enc = world
        .vk(&sender)
        .encrypt_transaction(&[7u8; 32], &plaintexts)
        .unwrap();
    let mut ciphertexts = enc.ciphertexts.clone();
    ciphertexts[1][0] ^= 0xff;
    let slices: Vec<&[u8]> = ciphertexts.iter().map(|c| c.as_slice()).collect();
    assert!(world
        .vk(&sender)
        .decrypt_transaction(&[7u8; 32], &slices, enc.salt)
        .is_err());
}

#[then(expr = "{string} fails to encrypt an empty transaction")]
fn empty_fails(world: &mut KeypairWorld, sender: String) {
    let err = world
        .vk(&sender)
        .encrypt_transaction(&[0u8; 32], &[])
        .unwrap_err();
    assert_eq!(err, KeypairError::EmptyTransaction);
}

#[then(expr = "{string} fails to encrypt a transaction with a truncated sender bundle")]
fn short_bundle_fails(world: &mut KeypairWorld, sender: String) {
    let short_bundle = vec![0u8; SENDER_HEADER];
    let recipient_plaintext = b"x".to_vec();
    let plaintexts: Vec<&[u8]> = vec![short_bundle.as_slice(), recipient_plaintext.as_slice()];

    let err = world
        .vk(&sender)
        .encrypt_transaction(&[0u8; 32], &plaintexts)
        .unwrap_err();
    assert_eq!(
        err,
        KeypairError::SenderBundleTooShort {
            expected: SENDER_HEADER + P256_PUBKEY_LEN,
            actual: SENDER_HEADER,
        }
    );
}

#[then(expr = "{string} decrypts the golden ciphertext from {string}")]
fn golden_decrypts(world: &mut KeypairWorld, recipient: String, ephemeral: String) {
    let ciphertext =
        hex::decode("82a9987a69b9627d60fe544fbadf2f1e4d0b19034284b0269b36410fb9").unwrap();
    let plaintext = world
        .vk(&recipient)
        .decrypt_utxo(&ciphertext, &world.vk(&ephemeral).pubkey(), 0, 0)
        .unwrap();
    assert_eq!(plaintext, b"deterministic");
}
