use borsh::to_vec;
use user_registry_tests::build_register_ix;
use zolana_user_registry_interface::instruction::{discriminator, RegisterData};
use zolana_user_registry_interface::{SyncDelegateEntry, UserRecord};

fn sample(sync_delegate: Option<[u8; 32]>, entries: Vec<SyncDelegateEntry>) -> UserRecord {
    UserRecord {
        owner: [7u8; 32],
        bump: 251,
        owner_p256: Some([2u8; 33]),
        nullifier_pubkey: [9u8; 32],
        viewing_pubkey: [3u8; 33],
        sync_delegate,
        entries,
    }
}

#[test]
fn record_byte_layout_is_locked() {
    let record = sample(
        Some([5u8; 32]),
        vec![SyncDelegateEntry {
            delegate: [5u8; 32],
            sync_pubkey: [2u8; 33],
            viewing_pubkey: [4u8; 33],
            created_at: 42,
        }],
    );
    let body = to_vec(&record).unwrap();

    let mut expected = Vec::new();
    expected.extend_from_slice(&[7u8; 32]);
    expected.push(251);
    expected.push(1);
    expected.extend_from_slice(&[2u8; 33]);
    expected.extend_from_slice(&[9u8; 32]);
    expected.extend_from_slice(&[3u8; 33]);
    expected.push(1);
    expected.extend_from_slice(&[5u8; 32]);
    expected.extend_from_slice(&1u32.to_le_bytes());
    expected.extend_from_slice(&[5u8; 32]);
    expected.extend_from_slice(&[2u8; 33]);
    expected.extend_from_slice(&[4u8; 33]);
    expected.extend_from_slice(&42i64.to_le_bytes());
    assert_eq!(body, expected);

    assert_eq!(
        UserRecord::DISCRIMINATOR_LEN + body.len(),
        UserRecord::space_for(1)
    );
}

#[test]
fn from_account_data_round_trips_with_trailing_padding() {
    let record = sample(None, Vec::new());
    let body = to_vec(&record).unwrap();
    let mut account_data = vec![UserRecord::DISCRIMINATOR];
    account_data.extend_from_slice(&body);
    account_data.resize(UserRecord::space_for(0), 0);
    assert_eq!(
        UserRecord::try_from_account_data(&account_data).unwrap(),
        record
    );
}

#[test]
fn from_account_data_rejects_bad_discriminator() {
    assert!(UserRecord::try_from_account_data(&[]).is_err());
    let record = sample(None, Vec::new());
    let mut account_data = vec![0u8];
    account_data.extend_from_slice(&to_vec(&record).unwrap());
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

#[test]
fn sender_viewing_pubkey_active_delegate_and_after_revoke() {
    let entries = vec![
        SyncDelegateEntry {
            delegate: [5u8; 32],
            sync_pubkey: [2u8; 33],
            viewing_pubkey: [10u8; 33],
            created_at: 1,
        },
        SyncDelegateEntry {
            delegate: [5u8; 32],
            sync_pubkey: [3u8; 33],
            viewing_pubkey: [11u8; 33],
            created_at: 2,
        },
    ];
    let active = sample(Some([5u8; 32]), entries.clone());
    assert_eq!(active.sender_viewing_pubkey(), [11u8; 33]);

    let revoked = sample(None, entries);
    assert_eq!(revoked.sender_viewing_pubkey(), [3u8; 33]);
}
