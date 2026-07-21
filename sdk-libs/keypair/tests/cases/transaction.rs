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
