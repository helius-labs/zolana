use cucumber::{then, when};
use zolana_keypair::constants::BLINDING_LEN;
use zolana_keypair::ShieldedKeypair;
use zolana_transaction::data::{Data, DataRecord};
use zolana_transaction::transfer::{
    RecipientOutput, RecipientSlot, TransferRecipientPlaintext, TransferSenderPlaintext,
};
use zolana_transaction::{TransactionEncryption, TransactionError, VIEW_TAG_LEN};

use crate::TransactionWorld;

fn build(world: &mut TransactionWorld, recipients: Vec<(String, u64, Data)>) {
    let sender_signing = world.sender().signing_pubkey();
    let sender_viewing = world.sender().viewing_pubkey();

    let mut recipient_viewing_pks = Vec::new();
    let mut outputs = Vec::new();
    let mut names = Vec::new();
    for (name, amount, data) in &recipients {
        let rkp = world.kp(name);
        recipient_viewing_pks.push(rkp.viewing_pubkey());
        let plaintext = TransferRecipientPlaintext {
            owner_pubkey: rkp.signing_pubkey(),
            sender_pubkey: sender_viewing,
            asset_id: 2,
            amount: *amount,
            blinding: [1u8; BLINDING_LEN],
            data: data.clone(),
        };
        let view_tag = rkp.viewing_key.recipient_bootstrap_view_tag();
        outputs.push(RecipientOutput {
            view_tag,
            plaintext,
        });
        names.push(name.clone());
    }

    let sender_plaintext = TransferSenderPlaintext {
        owner_pubkey: sender_signing,
        spl_asset_id: 2,
        spl_amount: 50,
        sol_amount: 5,
        blinding_seed: [2u8; BLINDING_LEN],
        recipient_viewing_pks,
        data: Data::default(),
    };

    let first_nullifier = [7u8; 32];
    let blob = world
        .sender()
        .viewing_key
        .encrypt_transfer(&first_nullifier, &sender_plaintext, &outputs)
        .unwrap();

    world.sender_plaintext = Some(sender_plaintext);
    world.recipients = outputs;
    world.recipient_names = names;
    world.transfer_blob = Some(blob);
    world.first_nullifier = first_nullifier;
}

#[when(expr = "{string} builds a transfer paying {int} to {string}")]
fn build_one(world: &mut TransactionWorld, sender: String, amount: u64, a: String) {
    world.sender_name = Some(sender);
    build(world, vec![(a, amount, Data::default())]);
}

#[when(expr = "{string} builds a transfer paying {int} to {string} and {int} to {string}")]
fn build_two(
    world: &mut TransactionWorld,
    sender: String,
    amount_a: u64,
    a: String,
    amount_b: u64,
    b: String,
) {
    world.sender_name = Some(sender);
    build(
        world,
        vec![
            (a, amount_a, Data::default()),
            (b, amount_b, Data::default()),
        ],
    );
}

#[when(expr = "{string} builds a transfer with no recipients")]
fn build_zero(world: &mut TransactionWorld, sender: String) {
    world.sender_name = Some(sender);
    build(world, vec![]);
}

#[when(expr = "{string} builds a transfer to {string} with program data")]
fn build_with_data(world: &mut TransactionWorld, sender: String, a: String) {
    world.sender_name = Some(sender);
    let data = Data::new(vec![
        DataRecord::ZoneData(vec![10, 11, 12]),
        DataRecord::ProgramData(vec![20, 21]),
    ]);
    build(world, vec![(a, 1000, data)]);
}

#[then(expr = "the transfer blob deserializes back unchanged")]
fn blob_round_trips(world: &mut TransactionWorld) {
    let blob = world.transfer_blob.as_ref().unwrap();
    let bytes = blob.serialize().unwrap();
    let parsed = zolana_transaction::transfer::TransferEncryptedUtxos::deserialize(&bytes).unwrap();
    assert_eq!(&parsed, blob);
}

#[then(expr = "{string} recovers the transfer")]
fn sender_recovers(world: &mut TransactionWorld, sender: String) {
    let blob = world.transfer_blob.as_ref().unwrap();
    let (sender_out, recipients_out) = world
        .kp(&sender)
        .viewing_key
        .decrypt_transfer(&world.first_nullifier, blob)
        .unwrap();
    assert_eq!(&sender_out, world.sender_plaintext.as_ref().unwrap());
    let expected: Vec<_> = world
        .recipients
        .iter()
        .map(|o| o.plaintext.clone())
        .collect();
    assert_eq!(recipients_out, expected);
}

#[then(expr = "{string} syncs the transfer and reads amount {int}")]
fn recipient_reads(world: &mut TransactionWorld, name: String, amount: u64) {
    let slot = world.slot_of(&name);
    let blob = world.transfer_blob.as_ref().unwrap();
    let pt = world
        .kp(&name)
        .viewing_key
        .decrypt_transfer_recipient(blob, slot)
        .unwrap();
    assert_eq!(pt.amount, amount);
    assert_eq!(pt.owner_pubkey, world.kp(&name).signing_pubkey());
}

#[then(expr = "the slot view tag of {string} is their bootstrap tag")]
fn slot_view_tag(world: &mut TransactionWorld, name: String) {
    let slot = world.slot_of(&name);
    let blob = world.transfer_blob.as_ref().unwrap();
    let expected = world.kp(&name).viewing_key.recipient_bootstrap_view_tag();
    let entry = blob.recipient_slots.get(slot).expect("slot present");
    assert_eq!(entry.view_tag, expected);
}

#[then(expr = "a stranger cannot read the slot of {string}")]
fn stranger_cannot(world: &mut TransactionWorld, name: String) {
    let slot = world.slot_of(&name);
    let blob = world.transfer_blob.as_ref().unwrap();
    let stranger = ShieldedKeypair::new().unwrap();
    assert!(stranger
        .viewing_key
        .decrypt_transfer_recipient(blob, slot)
        .is_err());
}

#[then(expr = "{string} recovers the program data")]
fn recover_data(world: &mut TransactionWorld, name: String) {
    let slot = world.slot_of(&name);
    let blob = world.transfer_blob.as_ref().unwrap();
    let pt = world
        .kp(&name)
        .viewing_key
        .decrypt_transfer_recipient(blob, slot)
        .unwrap();
    assert!(!pt.data.is_empty());
    let expected = world.recipients.get(slot).expect("recipient present");
    assert_eq!(pt.data, expected.plaintext.data);
}

#[then(expr = "{string} can read their slot but not the slot of {string}")]
fn recipient_cannot_read_other_slot(world: &mut TransactionWorld, reader: String, other: String) {
    let own = world.slot_of(&reader);
    let other_slot = world.slot_of(&other);
    let blob = world.transfer_blob.as_ref().unwrap();
    let viewing_key = &world.kp(&reader).viewing_key;
    assert!(viewing_key.decrypt_transfer_recipient(blob, own).is_ok());
    assert!(viewing_key
        .decrypt_transfer_recipient(blob, other_slot)
        .is_err());
}

#[then(expr = "a tampered recipient slot count is rejected for {string}")]
fn tampered_slot_count_rejected(world: &mut TransactionWorld, sender: String) {
    let mut blob = world.transfer_blob.clone().unwrap();
    blob.recipient_slots.push(RecipientSlot {
        view_tag: [9u8; VIEW_TAG_LEN],
        ciphertext: vec![0u8; 10],
    });
    let result = world
        .kp(&sender)
        .viewing_key
        .decrypt_transfer(&world.first_nullifier, &blob);
    assert!(matches!(
        result,
        Err(TransactionError::InvalidLength { .. })
    ));
}
