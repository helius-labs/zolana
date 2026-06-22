use std::collections::HashSet;

use cucumber::then;
use zolana_keypair::{
    constants::{BLINDING_LEN, SALT_LEN},
    ViewingKey,
};
use zolana_transaction::{
    data::{Data, DataRecord},
    split::{SplitBundlePlaintext, SplitEncryptedUtxos},
    transfer::{
        RecipientSlot, TransferEncryptedUtxos, TransferRecipientPlaintext, TransferSenderPlaintext,
    },
    TransactionError, SPLIT, TRANSFER, VIEW_TAG_LEN,
};

use crate::TransactionWorld;

#[then(expr = "a recipient plaintext for {string} round-trips with and without program data")]
fn recipient_plaintext_round_trips(world: &mut TransactionWorld, name: String) {
    let owner = world.kp(&name).signing_pubkey();
    for data in [
        Data::default(),
        Data::new(vec![
            DataRecord::ZoneData(vec![9, 9, 9]),
            DataRecord::ProgramData(vec![1]),
        ]),
    ] {
        let pt = TransferRecipientPlaintext {
            owner_pubkey: owner,
            sender_pubkey: ViewingKey::new().pubkey(),
            asset_id: 2,
            amount: 42,
            blinding: [1u8; BLINDING_LEN],
            data,
        };
        let bytes = pt.serialize().unwrap();
        assert_eq!(TransferRecipientPlaintext::deserialize(&bytes).unwrap(), pt);
    }
}

#[then(expr = "duplicate data records are rejected for {string}")]
fn duplicate_data_records_rejected(world: &mut TransactionWorld, name: String) {
    let pt = TransferRecipientPlaintext {
        owner_pubkey: world.kp(&name).signing_pubkey(),
        sender_pubkey: ViewingKey::new().pubkey(),
        asset_id: 2,
        amount: 42,
        blinding: [1u8; BLINDING_LEN],
        data: Data::new(vec![
            DataRecord::ZoneData(vec![1]),
            DataRecord::ZoneData(vec![2]),
        ]),
    };
    assert_eq!(
        pt.serialize().unwrap_err(),
        TransactionError::DuplicateDataRecord
    );
    let bytes = wincode::serialize(&pt).unwrap();
    assert_eq!(
        TransferRecipientPlaintext::deserialize(&bytes).unwrap_err(),
        TransactionError::DuplicateDataRecord
    );
}

#[then(expr = "out-of-order data records are rejected for {string}")]
fn out_of_order_data_records_rejected(world: &mut TransactionWorld, name: String) {
    let pt = TransferRecipientPlaintext {
        owner_pubkey: world.kp(&name).signing_pubkey(),
        sender_pubkey: ViewingKey::new().pubkey(),
        asset_id: 2,
        amount: 42,
        blinding: [1u8; BLINDING_LEN],
        data: Data::new(vec![
            DataRecord::ProgramData(vec![1]),
            DataRecord::ZoneData(vec![2]),
        ]),
    };
    assert_eq!(
        pt.serialize().unwrap_err(),
        TransactionError::NonCanonicalDataOrder
    );
    let bytes = wincode::serialize(&pt).unwrap();
    assert_eq!(
        TransferRecipientPlaintext::deserialize(&bytes).unwrap_err(),
        TransactionError::NonCanonicalDataOrder
    );
}

#[then(expr = "a sender plaintext for {string} to {string} round-trips")]
fn sender_plaintext_round_trips(world: &mut TransactionWorld, sender: String, recipient: String) {
    let pt = TransferSenderPlaintext {
        owner_pubkey: world.kp(&sender).signing_pubkey(),
        spl_asset_id: 2,
        spl_amount: 100,
        sol_amount: 5,
        blinding_seed: [2u8; BLINDING_LEN],
        recipient_viewing_pks: vec![world.kp(&recipient).viewing_pubkey()],
        spl_data: Data::default(),
        sol_data: Data::default(),
    };
    let bytes = pt.serialize().unwrap();
    assert_eq!(TransferSenderPlaintext::deserialize(&bytes).unwrap(), pt);
}

#[then(expr = "a transfer blob round-trips and rejects a wrong discriminator")]
fn transfer_blob_round_trips(_world: &mut TransactionWorld) {
    let blob = TransferEncryptedUtxos {
        type_prefix: TRANSFER,
        tx_viewing_pk: ViewingKey::new().pubkey(),
        salt: [1u8; SALT_LEN],
        sender_ciphertext: vec![7u8; 142],
        recipient_slots: vec![RecipientSlot {
            view_tag: [3u8; VIEW_TAG_LEN],
            ciphertext: vec![8u8; 132],
        }],
    };
    let bytes = blob.serialize().unwrap();
    assert_eq!(TransferEncryptedUtxos::deserialize(&bytes).unwrap(), blob);

    let mut bad = blob;
    bad.type_prefix = 9;
    let bytes = bad.serialize().unwrap();
    assert_eq!(
        TransferEncryptedUtxos::deserialize(&bytes).unwrap_err(),
        TransactionError::BadDiscriminator(9)
    );
}

#[then(expr = "a blob with an invalid viewing pubkey is rejected")]
fn invalid_viewing_pubkey_rejected(_world: &mut TransactionWorld) {
    let blob = TransferEncryptedUtxos {
        type_prefix: TRANSFER,
        tx_viewing_pk: ViewingKey::new().pubkey(),
        salt: [1u8; SALT_LEN],
        sender_ciphertext: vec![7u8; 16],
        recipient_slots: vec![],
    };
    let mut bytes = blob.serialize().unwrap();
    for byte in bytes.get_mut(1..34).unwrap() {
        *byte = 0xff;
    }
    assert_eq!(
        TransferEncryptedUtxos::deserialize(&bytes).unwrap_err(),
        TransactionError::Deserialize("Custom error: invalid p256 public key".to_string())
    );
}

#[then(expr = "a split bundle for {string} round-trips with distinct output blindings")]
fn split_bundle_round_trips(world: &mut TransactionWorld, name: String) {
    let bundle = SplitBundlePlaintext {
        owner_pubkey: world.kp(&name).signing_pubkey(),
        num_outputs: 8,
        asset_id: 2,
        asset_amount: 1000,
        blinding_seed: [3u8; BLINDING_LEN],
        data: Data::default(),
    };
    let bytes = bundle.serialize().unwrap();
    assert_eq!(SplitBundlePlaintext::deserialize(&bytes).unwrap(), bundle);

    let blindings = bundle.output_blindings();
    assert_eq!(blindings.len(), 8);
    let mut seen = HashSet::new();
    for blinding in blindings {
        assert!(seen.insert(blinding), "duplicate blinding");
    }
}

#[then(expr = "a split blob round-trips and rejects a wrong discriminator")]
fn split_blob_round_trips(_world: &mut TransactionWorld) {
    let blob = SplitEncryptedUtxos {
        type_prefix: SPLIT,
        tx_viewing_pk: ViewingKey::new().pubkey(),
        salt: [7u8; SALT_LEN],
        ciphertext: vec![5u8; 98],
    };
    let bytes = blob.serialize().unwrap();
    assert_eq!(SplitEncryptedUtxos::deserialize(&bytes).unwrap(), blob);

    let mut bad = blob;
    bad.type_prefix = 7;
    let bytes = bad.serialize().unwrap();
    assert_eq!(
        SplitEncryptedUtxos::deserialize(&bytes).unwrap_err(),
        TransactionError::BadDiscriminator(7)
    );
}
