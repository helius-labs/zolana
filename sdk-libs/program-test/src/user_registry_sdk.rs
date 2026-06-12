//! Minimal SDK for user-registry litesvm tests.

use anchor_lang::{AccountDeserialize, InstructionData, ToAccountMetas};
use solana_instruction::Instruction;
use solana_pubkey::Pubkey;
use zolana_interface::user_registry::{user_record_pda, USER_REGISTRY_PROGRAM_ID};

pub use zolana_user_registry::{state::UserRecord, ID as USER_REGISTRY_PROGRAM};

pub fn user_registry_program_id() -> Pubkey {
    Pubkey::new_from_array(USER_REGISTRY_PROGRAM_ID)
}

pub fn build_register_ix(
    owner: &Pubkey,
    owner_p256: Option<[u8; 33]>,
    nullifier_pubkey: [u8; 32],
    viewing_pubkey: [u8; 33],
) -> Instruction {
    let (user_record, _bump) = user_record_pda(owner);
    let accounts = zolana_user_registry::accounts::Register {
        user_record,
        owner: *owner,
        system_program: anchor_lang::solana_program::system_program::ID,
    };
    Instruction {
        program_id: user_registry_program_id(),
        accounts: accounts.to_account_metas(None),
        data: zolana_user_registry::instruction::Register {
            owner_p256,
            nullifier_pubkey,
            viewing_pubkey,
        }
        .data(),
    }
}

pub fn build_set_sync_delegate_ix(
    owner: &Pubkey,
    sync_delegate: Pubkey,
    sync_pubkey: [u8; 33],
    viewing_pubkey: [u8; 33],
) -> Instruction {
    let (user_record, _bump) = user_record_pda(owner);
    let accounts = zolana_user_registry::accounts::SetSyncDelegate {
        user_record,
        owner: *owner,
        system_program: anchor_lang::solana_program::system_program::ID,
    };
    Instruction {
        program_id: user_registry_program_id(),
        accounts: accounts.to_account_metas(None),
        data: zolana_user_registry::instruction::SetSyncDelegate {
            sync_delegate,
            sync_pubkey,
            viewing_pubkey,
        }
        .data(),
    }
}

pub fn build_sync_delegate_rotate_ix(
    owner: &Pubkey,
    sync_delegate: &Pubkey,
    sync_pubkey: [u8; 33],
    viewing_pubkey: [u8; 33],
) -> Instruction {
    let (user_record, _bump) = user_record_pda(owner);
    let accounts = zolana_user_registry::accounts::SyncDelegateRotate {
        user_record,
        sync_delegate: *sync_delegate,
        system_program: anchor_lang::solana_program::system_program::ID,
    };
    Instruction {
        program_id: user_registry_program_id(),
        accounts: accounts.to_account_metas(None),
        data: zolana_user_registry::instruction::SyncDelegateRotate {
            sync_pubkey,
            viewing_pubkey,
        }
        .data(),
    }
}

pub fn build_revoke_ix(owner: &Pubkey, signer: &Pubkey) -> Instruction {
    let (user_record, _bump) = user_record_pda(owner);
    let accounts = zolana_user_registry::accounts::Revoke {
        user_record,
        signer: *signer,
    };
    Instruction {
        program_id: user_registry_program_id(),
        accounts: accounts.to_account_metas(None),
        data: zolana_user_registry::instruction::Revoke {}.data(),
    }
}

pub fn build_close_ix(owner: &Pubkey) -> Instruction {
    let (user_record, _bump) = user_record_pda(owner);
    let accounts = zolana_user_registry::accounts::CloseRecord {
        user_record,
        owner: *owner,
    };
    Instruction {
        program_id: user_registry_program_id(),
        accounts: accounts.to_account_metas(None),
        data: zolana_user_registry::instruction::Close {}.data(),
    }
}

pub fn fetch_user_record(svm: &litesvm::LiteSVM, owner: &Pubkey) -> Option<UserRecord> {
    let (pda, _bump) = user_record_pda(owner);
    let account = svm.get_account(&pda)?;
    UserRecord::try_deserialize(&mut account.data.as_slice()).ok()
}

#[cfg(test)]
mod layout_parity {
    //! Locks the lean `zolana-interface` `UserRecord` to the on-chain Anchor
    //! account body. If either struct's fields or order drift, a consumer
    //! parsing account data via the interface would silently misread it; this
    //! test fails loudly instead.

    use anchor_lang::prelude::Pubkey as AnchorPubkey;
    use anchor_lang::AnchorSerialize;
    use borsh::BorshDeserialize;
    use zolana_interface::user_registry::{
        SyncDelegateEntry as IfaceEntry, UserRecord as IfaceRecord,
    };
    use zolana_user_registry::state::{SyncDelegateEntry as ChainEntry, UserRecord as ChainRecord};

    fn sample(sync_delegate: Option<AnchorPubkey>, entries: Vec<ChainEntry>) -> ChainRecord {
        ChainRecord {
            owner: AnchorPubkey::new_from_array([7u8; 32]),
            owner_p256: Some([2u8; 33]),
            nullifier_pubkey: [9u8; 32],
            viewing_pubkey: [3u8; 33],
            sync_delegate,
            entries,
        }
    }

    /// `AnchorSerialize` writes the borsh body without the 8-byte account
    /// discriminator, matching what the interface struct expects after the
    /// discriminator is stripped.
    fn body_bytes(record: &ChainRecord) -> Vec<u8> {
        let mut buf = Vec::new();
        record.serialize(&mut buf).expect("serialize chain record");
        buf
    }

    #[test]
    fn interface_layout_matches_onchain() {
        let chain = sample(
            Some(AnchorPubkey::new_from_array([5u8; 32])),
            vec![ChainEntry {
                sync_pubkey: [2u8; 33],
                viewing_pubkey: [4u8; 33],
                created_at: 42,
            }],
        );
        let body = body_bytes(&chain);

        let parsed = IfaceRecord::try_from_slice(&body).expect("interface parse of body");
        assert_eq!(parsed.owner, [7u8; 32]);
        assert_eq!(parsed.owner_p256, Some([2u8; 33]));
        assert_eq!(parsed.nullifier_pubkey, [9u8; 32]);
        assert_eq!(parsed.viewing_pubkey, [3u8; 33]);
        assert_eq!(parsed.sync_delegate, Some([5u8; 32]));
        assert_eq!(
            parsed.entries,
            vec![IfaceEntry {
                sync_pubkey: [2u8; 33],
                viewing_pubkey: [4u8; 33],
                created_at: 42,
            }]
        );

        // The discriminator-skipping accessor must agree with manual parsing.
        let mut account_data = vec![0u8; IfaceRecord::DISCRIMINATOR_LEN];
        account_data.extend_from_slice(&body);
        assert_eq!(
            IfaceRecord::from_account_data(&account_data).expect("accessor parse"),
            parsed
        );
    }

    #[test]
    fn from_account_data_rejects_short_input() {
        assert!(IfaceRecord::from_account_data(&[0u8; 4]).is_err());
    }

    #[test]
    fn sender_viewing_pubkey_parity_active_delegate() {
        let entries = vec![
            ChainEntry {
                sync_pubkey: [2u8; 33],
                viewing_pubkey: [10u8; 33],
                created_at: 1,
            },
            ChainEntry {
                sync_pubkey: [3u8; 33],
                viewing_pubkey: [11u8; 33],
                created_at: 2,
            },
        ];
        let chain = sample(Some(AnchorPubkey::new_from_array([5u8; 32])), entries);
        let iface = IfaceRecord::try_from_slice(&body_bytes(&chain)).unwrap();
        assert_eq!(chain.sender_viewing_pubkey(), iface.sender_viewing_pubkey());
        assert_eq!(iface.sender_viewing_pubkey(), [11u8; 33]);
    }

    #[test]
    fn sender_viewing_pubkey_parity_after_revoke() {
        let chain = sample(
            None,
            vec![ChainEntry {
                sync_pubkey: [2u8; 33],
                viewing_pubkey: [10u8; 33],
                created_at: 1,
            }],
        );
        let iface = IfaceRecord::try_from_slice(&body_bytes(&chain)).unwrap();
        assert_eq!(chain.sender_viewing_pubkey(), iface.sender_viewing_pubkey());
        // No active delegate -> static viewing key, not the entry's.
        assert_eq!(iface.sender_viewing_pubkey(), [3u8; 33]);
    }
}
