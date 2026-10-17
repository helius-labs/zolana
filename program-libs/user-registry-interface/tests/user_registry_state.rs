use borsh::to_vec;
use zolana_user_registry_interface::UserRecord;

#[test]
fn size_preserves_existing_account_allocation() {
    let record = UserRecord {
        owner: [7u8; 32].into(),
        bump: 254,
        reserved_owner: Default::default(),
        nullifier_pubkey: [9u8; 32],
        viewing_pubkey: [4u8; 33],
        merging_enabled: true,
    };
    let body = to_vec(&record).unwrap();
    assert_eq!(
        UserRecord::DISCRIMINATOR_LEN + body.len() + 33,
        UserRecord::SIZE
    );
}

#[test]
fn reserved_owner_byte_rejects_legacy_account_and_instruction_data() {
    use borsh::BorshDeserialize;
    use zolana_user_registry_interface::instruction::{RegisterData, UpdateKeysData};

    let record = UserRecord {
        owner: [7u8; 32].into(),
        bump: 254,
        reserved_owner: Default::default(),
        nullifier_pubkey: [9u8; 32],
        viewing_pubkey: [4u8; 33],
        merging_enabled: true,
    };
    let mut account = vec![UserRecord::DISCRIMINATOR];
    account.extend(to_vec(&record).unwrap());
    account.resize(UserRecord::SIZE, 0);
    assert_eq!(account.len(), 134);
    assert_eq!(account[34], 0);
    assert_eq!(UserRecord::try_from_account_data(&account).unwrap(), record);
    let mut data = to_vec(&RegisterData {
        reserved_owner: Default::default(),
        nullifier_pubkey: record.nullifier_pubkey,
        viewing_pubkey: record.viewing_pubkey,
    })
    .unwrap();
    assert_eq!(data.len(), 66);
    assert!(RegisterData::try_from_slice(&data).is_ok());
    assert!(UpdateKeysData::try_from_slice(&data).is_ok());
    for reserved in [1, 2, 255] {
        account[34] = reserved;
        data[0] = reserved;
        assert!(UserRecord::try_from_account_data(&account).is_err());
        assert!(RegisterData::try_from_slice(&data).is_err());
        assert!(UpdateKeysData::try_from_slice(&data).is_err());
    }
}
