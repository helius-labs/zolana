use borsh::to_vec;
use spr_user_registry_interface::{MergeEncryptionScheme, UserRecord};

#[test]
fn size_covers_max_serialized_size() {
    let record = UserRecord {
        owner: [7u8; 32].into(),
        bump: 254,
        nullifier_pubkey: [9u8; 32],
        viewing_pubkey: [4u8; 33],
        merge_encryption: MergeEncryptionScheme::PoseidonCtrV1,
    };
    let body = to_vec(&record).unwrap();
    assert_eq!(UserRecord::DISCRIMINATOR_LEN + body.len(), UserRecord::SIZE);
}

#[test]
fn optional_data_extension_preserves_the_original_record_layout() {
    let record = UserRecord {
        owner: [7u8; 32].into(),
        bump: 254,
        nullifier_pubkey: [9u8; 32],
        viewing_pubkey: [4u8; 33],
        merge_encryption: MergeEncryptionScheme::PoseidonCtrV1,
    };
    let mut account = vec![UserRecord::DISCRIMINATOR];
    account.extend(to_vec(&record).unwrap());
    assert_eq!(UserRecord::additional_data(&account).unwrap(), []);
    for bytes in [vec![], vec![1, 2, 255]] {
        let mut extended = account.clone();
        extended.extend((bytes.len() as u32).to_le_bytes());
        extended.extend(&bytes);
        assert_eq!(
            UserRecord::try_from_account_data(&extended).unwrap(),
            record
        );
        assert_eq!(UserRecord::additional_data(&extended).unwrap(), bytes);
    }
    for extension in [
        vec![1],
        vec![1, 0, 0],
        vec![1, 0, 0, 0],
        vec![0, 0, 0, 0, 7],
        vec![255; 4],
    ] {
        let mut extended = account.clone();
        extended.extend(extension);
        assert!(UserRecord::try_from_account_data(&extended).is_err());
    }
}
