use std::collections::HashSet;

use zolana_keypair::{constants::SALT_LEN, ViewingKey};
use zolana_transaction::{
    data::{Data, DataRecord},
    serialization::{
        anonymous::AnonymousTransferSenderPlaintext,
        confidential::ConfidentialOutputPlaintext,
        split::{SplitBundlePlaintext, SplitEncryptedUtxos},
    },
    TransactionError, SPLIT,
};

use crate::TransactionWorld;

pub(crate) fn recipient_plaintext_round_trips(_name: String) {
    for data in [
        Data::default(),
        Data::new(vec![
            DataRecord::ZoneData(vec![9, 9, 9]),
            DataRecord::UtxoData(vec![1]),
        ]),
        Data::new(vec![DataRecord::Memo(b"thanks".to_vec())]),
        Data::new(vec![
            DataRecord::ZoneData(vec![9, 9, 9]),
            DataRecord::UtxoData(vec![1]),
            DataRecord::Memo(vec![5; 300]),
        ]),
    ] {
        let pt = ConfidentialOutputPlaintext {
            asset_id: 2,
            amount: 42,
            blinding: [1u8; 32],
            zone_program_id: None,
            data,
        };
        let bytes = pt.serialize().unwrap();
        assert_eq!(
            ConfidentialOutputPlaintext::deserialize(&bytes).unwrap(),
            pt
        );
    }
}

pub(crate) fn duplicate_data_records_rejected(_name: String) {
    let pt = ConfidentialOutputPlaintext {
        asset_id: 2,
        amount: 42,
        blinding: [1u8; 32],
        zone_program_id: None,
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
        ConfidentialOutputPlaintext::deserialize(&bytes).unwrap_err(),
        TransactionError::DuplicateDataRecord
    );
}

pub(crate) fn out_of_order_data_records_rejected(_name: String) {
    let pt = ConfidentialOutputPlaintext {
        asset_id: 2,
        amount: 42,
        blinding: [1u8; 32],
        zone_program_id: None,
        data: Data::new(vec![
            DataRecord::UtxoData(vec![1]),
            DataRecord::ZoneData(vec![2]),
        ]),
    };
    assert_eq!(
        pt.serialize().unwrap_err(),
        TransactionError::NonCanonicalDataOrder
    );
    let bytes = wincode::serialize(&pt).unwrap();
    assert_eq!(
        ConfidentialOutputPlaintext::deserialize(&bytes).unwrap_err(),
        TransactionError::NonCanonicalDataOrder
    );
}

pub(crate) fn sender_plaintext_round_trips(
    world: &mut TransactionWorld,
    sender: String,
    recipient: String,
) {
    let pt = AnonymousTransferSenderPlaintext {
        owner_pubkey: world.kp(&sender).signing_pubkey(),
        spl_asset_id: 2,
        spl_amount: 100,
        sol_amount: 5,
        blinding_seed: [2u8; 32],
        recipient_viewing_pks: vec![world.kp(&recipient).viewing_pubkey()],
        spl_data: Data::default(),
        sol_data: Data::default(),
    };
    let bytes = pt.serialize().unwrap();
    assert_eq!(
        AnonymousTransferSenderPlaintext::deserialize(&bytes).unwrap(),
        pt
    );
}

pub(crate) fn transfer_blob_round_trips() {
    let blob = SplitEncryptedUtxos {
        type_prefix: SPLIT,
        tx_viewing_pk: ViewingKey::new().pubkey(),
        salt: [1u8; SALT_LEN],
        ciphertext: vec![7u8; 142],
    };
    let bytes = blob.serialize().unwrap();
    assert_eq!(SplitEncryptedUtxos::deserialize(&bytes).unwrap(), blob);

    let mut bad = blob;
    bad.type_prefix = 9;
    let bytes = bad.serialize().unwrap();
    assert_eq!(
        SplitEncryptedUtxos::deserialize(&bytes).unwrap_err(),
        TransactionError::BadDiscriminator(9)
    );
}

pub(crate) fn invalid_viewing_pubkey_rejected() {
    let blob = SplitEncryptedUtxos {
        type_prefix: SPLIT,
        tx_viewing_pk: ViewingKey::new().pubkey(),
        salt: [1u8; SALT_LEN],
        ciphertext: vec![7u8; 16],
    };
    let mut bytes = blob.serialize().unwrap();
    for byte in bytes.get_mut(1..34).unwrap() {
        *byte = 0xff;
    }
    assert_eq!(
        SplitEncryptedUtxos::deserialize(&bytes).unwrap_err(),
        TransactionError::Deserialize("Custom error: invalid p256 public key".to_string())
    );
}

pub(crate) fn split_bundle_round_trips(world: &mut TransactionWorld, name: String) {
    let bundle = SplitBundlePlaintext {
        owner_pubkey: world.kp(&name).signing_pubkey(),
        num_outputs: 8,
        asset_id: 2,
        asset_amount: 1000,
        blinding_seed: [3u8; 32],
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

pub(crate) fn split_blob_round_trips() {
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
