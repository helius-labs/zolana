use borsh::to_vec;
use user_registry_tests::build_register_ix;
use zolana_user_registry_interface::{
    instruction::{discriminator, RegisterData},
    UserRecord,
};

fn sample(merging_enabled: bool) -> UserRecord {
    UserRecord {
        owner: [7u8; 32].into(),
        bump: 251,
        owner_p256: Some([2u8; 33]),
        nullifier_pubkey: [9u8; 32],
        viewing_pubkey: [3u8; 33],
        merging_enabled,
    }
}

#[test]
fn record_byte_layout_is_locked() {
    let record = sample(true);
    let body = to_vec(&record).unwrap();

    let mut expected = Vec::new();
    expected.extend_from_slice(&[7u8; 32]);
    expected.push(251);
    expected.push(1);
    expected.extend_from_slice(&[2u8; 33]);
    expected.extend_from_slice(&[9u8; 32]);
    expected.extend_from_slice(&[3u8; 33]);
    expected.push(1);
    assert_eq!(body, expected);

    assert_eq!(UserRecord::DISCRIMINATOR_LEN + body.len(), UserRecord::SIZE);
}

#[test]
fn from_account_data_round_trips_with_trailing_padding() {
    let mut record = sample(false);
    record.owner_p256 = None;
    let body = to_vec(&record).unwrap();
    let mut account_data = vec![UserRecord::DISCRIMINATOR];
    account_data.extend_from_slice(&body);
    account_data.resize(UserRecord::SIZE, 0);
    assert_eq!(
        UserRecord::try_from_account_data(&account_data).unwrap(),
        record
    );
}

#[test]
fn from_account_data_rejects_wrong_discriminator() {
    assert!(UserRecord::try_from_account_data(&[]).is_err());
    let record = sample(false);
    let mut account_data = vec![UserRecord::DISCRIMINATOR.wrapping_add(1)];
    account_data.extend_from_slice(&to_vec(&record).unwrap());
    account_data.resize(UserRecord::SIZE, 0);
    assert!(UserRecord::try_from_account_data(&account_data).is_err());
}

#[test]
fn from_account_data_rejects_legacy_record_size() {
    let record = sample(false);
    let mut account_data = vec![UserRecord::DISCRIMINATOR];
    account_data.extend_from_slice(&to_vec(&record).unwrap());
    account_data.resize(UserRecord::SIZE + 37, 0);
    assert!(UserRecord::try_from_account_data(&account_data).is_err());
}

#[test]
fn register_instruction_uses_one_byte_discriminator() {
    let ix = build_register_ix(
        &solana_pubkey::Pubkey::new_unique(),
        None,
        [1u8; 32],
        [2u8; 33],
    );
    assert_eq!(ix.data[0], discriminator::REGISTER);
    let payload = RegisterData {
        owner_p256: None,
        nullifier_pubkey: [1u8; 32],
        viewing_pubkey: [2u8; 33],
    };
    assert_eq!(ix.data[1..], to_vec(&payload).unwrap());
}
