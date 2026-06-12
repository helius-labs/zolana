//! Minimal SDK for user-registry litesvm tests.

use solana_instruction::Instruction;
use solana_pubkey::Pubkey;
use zolana_interface::user_registry::{
    instruction::{self as user_registry_instruction, RegisterData, RotateSyncDelegateData, SetSyncDelegateData},
    user_record_pda,
};

pub use zolana_interface::user_registry::{
    user_registry_program_id, SyncDelegateEntry, UserRecord,
};

pub fn build_register_ix(
    owner: &Pubkey,
    owner_p256: Option<[u8; 33]>,
    nullifier_pubkey: [u8; 32],
    viewing_pubkey: [u8; 33],
) -> Instruction {
    let (user_record, _bump) = user_record_pda(owner);
    user_registry_instruction::register(
        user_record,
        *owner,
        RegisterData {
            owner_p256,
            nullifier_pubkey,
            viewing_pubkey,
        },
    )
}

pub fn build_set_sync_delegate_ix(
    owner: &Pubkey,
    sync_delegate: Pubkey,
    sync_pubkey: [u8; 33],
    viewing_pubkey: [u8; 33],
) -> Instruction {
    let (user_record, _bump) = user_record_pda(owner);
    user_registry_instruction::set_sync_delegate(
        user_record,
        *owner,
        SetSyncDelegateData {
            sync_delegate: sync_delegate.to_bytes(),
            sync_pubkey,
            viewing_pubkey,
        },
    )
}

pub fn build_rotate_sync_delegate_ix(
    owner: &Pubkey,
    sync_delegate: &Pubkey,
    sync_pubkey: [u8; 33],
    viewing_pubkey: [u8; 33],
) -> Instruction {
    let (user_record, _bump) = user_record_pda(owner);
    user_registry_instruction::rotate_sync_delegate(
        user_record,
        *sync_delegate,
        RotateSyncDelegateData {
            sync_pubkey,
            viewing_pubkey,
        },
    )
}

pub fn build_revoke_ix(owner: &Pubkey, signer: &Pubkey) -> Instruction {
    let (user_record, _bump) = user_record_pda(owner);
    user_registry_instruction::revoke(user_record, *signer)
}

pub fn build_close_ix(owner: &Pubkey) -> Instruction {
    let (user_record, _bump) = user_record_pda(owner);
    user_registry_instruction::close(user_record, *owner)
}

pub fn fetch_user_record(svm: &litesvm::LiteSVM, owner: &Pubkey) -> Option<UserRecord> {
    let (pda, _bump) = user_record_pda(owner);
    let account = svm.get_account(&pda)?;
    UserRecord::from_account_data(&account.data).ok()
}

#[cfg(test)]
mod wire_layout {
    //! Locks the user-record account layout and instruction encoding so any
    //! drift between the interface and the on-chain program fails loudly.
    use borsh::to_vec;
    use zolana_interface::user_registry::instruction::{tag, RegisterData};
    use zolana_interface::user_registry::{SyncDelegateEntry, UserRecord};

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
        // Accounts are sized for the `Some` length of options, so the live
        // account carries trailing zeros after a `None` serialization.
        account_data.resize(UserRecord::space_for(0), 0);
        assert_eq!(UserRecord::from_account_data(&account_data).unwrap(), record);
    }

    #[test]
    fn from_account_data_rejects_bad_discriminator() {
        assert!(UserRecord::from_account_data(&[]).is_err());
        let record = sample(None, Vec::new());
        let mut account_data = vec![0u8];
        account_data.extend_from_slice(&to_vec(&record).unwrap());
        assert!(UserRecord::from_account_data(&account_data).is_err());
    }

    #[test]
    fn register_instruction_uses_one_byte_tag() {
        let ix = super::build_register_ix(
            &solana_pubkey::Pubkey::new_unique(),
            None,
            [1u8; 32],
            [2u8; 33],
        );
        assert_eq!(ix.data[0], tag::REGISTER);
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
                sync_pubkey: [2u8; 33],
                viewing_pubkey: [10u8; 33],
                created_at: 1,
            },
            SyncDelegateEntry {
                sync_pubkey: [3u8; 33],
                viewing_pubkey: [11u8; 33],
                created_at: 2,
            },
        ];
        let active = sample(Some([5u8; 32]), entries.clone());
        assert_eq!(active.sender_viewing_pubkey(), [11u8; 33]);

        let revoked = sample(None, entries);
        // No active delegate means static viewing key, not the entry's.
        assert_eq!(revoked.sender_viewing_pubkey(), [3u8; 33]);
    }
}
