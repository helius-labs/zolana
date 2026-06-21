use borsh::to_vec;
use zolana_user_registry_interface::{SyncDelegateEntry, UserRecord};

#[test]
fn entry_serializes_delegate_before_keys() {
    let entry = SyncDelegateEntry {
        delegate: [1u8; 32],
        sync_pubkey: [2u8; 33],
        viewing_pubkey: [3u8; 33],
        created_at: 99,
    };
    let bytes = to_vec(&entry).unwrap();
    assert_eq!(bytes.len(), SyncDelegateEntry::SERIALIZED_LEN);
    assert_eq!(&bytes[..32], &[1u8; 32]);
}

#[test]
fn space_for_empty_entries() {
    assert_eq!(UserRecord::space_for(0), 171);
}

#[test]
fn space_for_covers_max_serialized_size() {
    let record = UserRecord {
        owner: [7u8; 32],
        bump: 254,
        owner_p256: Some([2u8; 33]),
        nullifier_pubkey: [9u8; 32],
        viewing_pubkey: [3u8; 33],
        sync_delegate: Some([5u8; 32]),
        entries: vec![
            SyncDelegateEntry {
                delegate: [5u8; 32],
                sync_pubkey: [2u8; 33],
                viewing_pubkey: [4u8; 33],
                created_at: 42,
            };
            3
        ],
        merge_service: true,
    };
    let body = to_vec(&record).unwrap();
    assert_eq!(
        UserRecord::DISCRIMINATOR_LEN + body.len(),
        UserRecord::space_for(3)
    );
}

#[test]
fn sender_viewing_pubkey_uses_active_sync_delegate_entry() {
    let record = UserRecord {
        owner: [0u8; 32],
        bump: 255,
        owner_p256: None,
        nullifier_pubkey: [1u8; 32],
        viewing_pubkey: [2u8; 33],
        sync_delegate: Some([9u8; 32]),
        entries: vec![SyncDelegateEntry {
            delegate: [9u8; 32],
            sync_pubkey: [3u8; 33],
            viewing_pubkey: [4u8; 33],
            created_at: 0,
        }],
        merge_service: false,
    };
    assert_eq!(record.sender_viewing_pubkey(), [4u8; 33]);
}

#[test]
fn sender_viewing_pubkey_falls_back_after_revoke() {
    let record = UserRecord {
        owner: [0u8; 32],
        bump: 255,
        owner_p256: None,
        nullifier_pubkey: [1u8; 32],
        viewing_pubkey: [2u8; 33],
        sync_delegate: None,
        entries: vec![SyncDelegateEntry {
            delegate: [9u8; 32],
            sync_pubkey: [3u8; 33],
            viewing_pubkey: [4u8; 33],
            created_at: 0,
        }],
        merge_service: false,
    };
    assert_eq!(record.sender_viewing_pubkey(), [2u8; 33]);
}
