use zolana_keypair::random_salt;

use crate::KeypairWorld;

pub(crate) fn slot_round_trips(world: &mut KeypairWorld, sender: String, recipient: String) {
    let nf = [7u8; 32];
    let transaction_viewing_key = world.vk(&sender).get_transaction_viewing_key(&nf).unwrap();
    let salt = random_salt();
    let payload = b"recipient payload".to_vec();
    let recipient_pk = world.vk(&recipient).pubkey();
    let ct = transaction_viewing_key
        .encrypt_slot(&recipient_pk, &payload, salt, 1)
        .unwrap();

    let by_recipient = world
        .vk(&recipient)
        .decrypt_utxo(&ct, &transaction_viewing_key.pubkey(), salt, 1)
        .unwrap();
    assert_eq!(by_recipient, payload);

    let by_sender = transaction_viewing_key
        .decrypt_slot_ephemeral(&recipient_pk, &ct, salt, 1)
        .unwrap();
    assert_eq!(by_sender, payload);
}

pub(crate) fn distinct_slots(world: &mut KeypairWorld, sender: String, recipient: String) {
    let nf = [9u8; 32];
    let transaction_viewing_key = world.vk(&sender).get_transaction_viewing_key(&nf).unwrap();
    let salt = random_salt();
    let recipient_pk = world.vk(&recipient).pubkey();
    let c0 = transaction_viewing_key
        .encrypt_slot(&recipient_pk, b"identical", salt, 0)
        .unwrap();
    let c1 = transaction_viewing_key
        .encrypt_slot(&recipient_pk, b"identical", salt, 1)
        .unwrap();
    assert_ne!(c0, c1);
}

pub(crate) fn stranger_cannot(
    world: &mut KeypairWorld,
    stranger: String,
    sender: String,
    recipient: String,
) {
    let nf = [7u8; 32];
    let transaction_viewing_key = world.vk(&sender).get_transaction_viewing_key(&nf).unwrap();
    let salt = random_salt();
    let recipient_pk = world.vk(&recipient).pubkey();
    let ct = transaction_viewing_key
        .encrypt_slot(&recipient_pk, b"payload", salt, 1)
        .unwrap();
    let recovered = world
        .vk(&stranger)
        .decrypt_utxo(&ct, &transaction_viewing_key.pubkey(), salt, 1)
        .unwrap();
    assert_ne!(recovered, b"payload");
}

pub(crate) fn golden_decrypts(world: &mut KeypairWorld, recipient: String, ephemeral: String) {
    let ciphertext = hex::decode("0dedf6fb1c2c64f57a31740887").unwrap();
    let plaintext = world
        .vk(&recipient)
        .decrypt_utxo(&ciphertext, &world.vk(&ephemeral).pubkey(), [0u8; 16], 0)
        .unwrap();
    assert_eq!(plaintext, b"deterministic");
}

/// A golden vector with a non-palindromic salt, slot 1, and a plaintext that
/// crosses an AES block boundary. A reversed salt or a big-endian/little-endian
/// slot swap in `derive_key_nonce` changes the ciphertext and fails this test;
/// the all-zero salt / slot-0 golden above catches neither.
pub(crate) fn golden_wire_format_is_pinned(
    world: &mut KeypairWorld,
    ephemeral: String,
    recipient: String,
) {
    let mut salt = [0u8; 16];
    for (i, byte) in salt.iter_mut().enumerate() {
        *byte = i as u8 + 1;
    }
    let plaintext = b"deterministic-slot01";
    let recipient_pk = world.vk(&recipient).pubkey();
    let ephemeral_vk = world.vk(&ephemeral);

    let ct = ephemeral_vk
        .encrypt_slot(&recipient_pk, plaintext, salt, 1)
        .unwrap();
    assert_eq!(hex::encode(&ct), "1398efa64945062160825853bfe6819163666caa");

    let recovered = world
        .vk(&recipient)
        .decrypt_utxo(&ct, &ephemeral_vk.pubkey(), salt, 1)
        .unwrap();
    assert_eq!(recovered, plaintext);

    // A reversed salt and a different slot must both change the keystream.
    let mut reversed = salt;
    reversed.reverse();
    assert_ne!(
        ephemeral_vk
            .encrypt_slot(&recipient_pk, plaintext, reversed, 1)
            .unwrap(),
        ct
    );
    assert_ne!(
        ephemeral_vk
            .encrypt_slot(&recipient_pk, plaintext, salt, 0)
            .unwrap(),
        ct
    );
}
