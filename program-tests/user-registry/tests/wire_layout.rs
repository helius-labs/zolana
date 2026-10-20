use borsh::to_vec;
use user_registry_tests::build_register_ix;
use zolana_user_registry::error::UserRegistryError;
use zolana_user_registry_interface::{
    instruction::{discriminator, RegisterData, SetMergeEncryptionData},
    MergeEncryptionScheme, UserRecord,
};

/// Active error codes retain their wire values after retired variants are removed.
#[test]
fn error_codes_are_stable() {
    let pinned = [
        (UserRegistryError::InvalidInstructionData, 0),
        (UserRegistryError::UnauthorizedSigner, 1),
        (UserRegistryError::InvalidRecordPda, 2),
        (UserRegistryError::OwnerMismatch, 3),
        (UserRegistryError::InvalidRecordAccount, 4),
        (UserRegistryError::InvalidSystemProgram, 5),
        (UserRegistryError::NullifierPubkeyRotation, 9),
    ];
    for (variant, code) in pinned {
        assert_eq!(variant as u32, code, "{}", variant.name());
    }
}

fn sample(merge_encryption: MergeEncryptionScheme) -> UserRecord {
    UserRecord {
        owner: [7u8; 32].into(),
        bump: 251,
        nullifier_pubkey: [9u8; 32],
        viewing_pubkey: [4u8; 33],
        merge_encryption,
    }
}

#[test]
fn record_byte_layout_is_locked() {
    let record = sample(MergeEncryptionScheme::PoseidonCtrV1);
    let body = to_vec(&record).unwrap();

    let mut expected = Vec::new();
    expected.extend_from_slice(&[7u8; 32]);
    expected.push(251);
    expected.extend_from_slice(&[9u8; 32]);
    expected.extend_from_slice(&[4u8; 33]);
    expected.push(1);
    assert_eq!(body, expected);

    assert_eq!(UserRecord::DISCRIMINATOR_LEN + body.len(), UserRecord::SIZE);
}

/// The scheme byte keeps the encoding of the former `merging_enabled: bool`, so
/// a record written as disabled (0) or enabled (1) decodes as `Disabled` or
/// `PoseidonCtrV1` without migration, and an unknown scheme byte is rejected.
#[test]
fn merge_encryption_byte_reads_former_merging_flag() {
    let mut account_data = vec![UserRecord::DISCRIMINATOR];
    account_data.extend_from_slice(&to_vec(&sample(MergeEncryptionScheme::Disabled)).unwrap());
    let last = account_data.len() - 1;
    for (byte, expected) in [
        (0u8, MergeEncryptionScheme::Disabled),
        (1u8, MergeEncryptionScheme::PoseidonCtrV1),
    ] {
        *account_data.get_mut(last).unwrap() = byte;
        assert_eq!(
            UserRecord::try_from_account_data(&account_data)
                .unwrap()
                .merge_encryption,
            expected
        );
    }
    *account_data.get_mut(last).unwrap() = 2;
    assert!(UserRecord::try_from_account_data(&account_data).is_err());
}

#[test]
fn set_merge_encryption_payload_is_the_scheme_byte() {
    for (scheme, byte) in [
        (MergeEncryptionScheme::Disabled, 0u8),
        (MergeEncryptionScheme::PoseidonCtrV1, 1u8),
    ] {
        assert_eq!(to_vec(&SetMergeEncryptionData { scheme }).unwrap(), [byte]);
    }
}

#[test]
fn from_account_data_round_trips() {
    let record = sample(MergeEncryptionScheme::Disabled);
    let body = to_vec(&record).unwrap();
    let mut account_data = vec![UserRecord::DISCRIMINATOR];
    account_data.extend_from_slice(&body);
    assert_eq!(
        UserRecord::try_from_account_data(&account_data).unwrap(),
        record
    );
}

#[test]
fn from_account_data_rejects_wrong_discriminator() {
    assert!(UserRecord::try_from_account_data(&[]).is_err());
    let record = sample(MergeEncryptionScheme::Disabled);
    let mut account_data = vec![UserRecord::DISCRIMINATOR.wrapping_add(1)];
    account_data.extend_from_slice(&to_vec(&record).unwrap());
    account_data.resize(UserRecord::SIZE, 0);
    assert!(UserRecord::try_from_account_data(&account_data).is_err());
}

#[test]
fn from_account_data_rejects_legacy_record_size() {
    let record = sample(MergeEncryptionScheme::Disabled);
    let mut account_data = vec![UserRecord::DISCRIMINATOR];
    account_data.extend_from_slice(&to_vec(&record).unwrap());
    account_data.resize(UserRecord::SIZE + 37, 0);
    assert!(UserRecord::try_from_account_data(&account_data).is_err());
}

#[test]
fn register_instruction_uses_one_byte_discriminator() {
    let ix = build_register_ix(&solana_pubkey::Pubkey::new_unique(), [1u8; 32], [4u8; 33]);
    assert_eq!(ix.data[0], discriminator::REGISTER);
    let payload = RegisterData {
        nullifier_pubkey: [1u8; 32],
        viewing_pubkey: [4u8; 33],
    };
    assert_eq!(ix.data[1..], to_vec(&payload).unwrap());
}
