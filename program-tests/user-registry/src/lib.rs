//! LiteSVM test helpers for the user-registry program.

use solana_instruction::Instruction;
use solana_pubkey::Pubkey;
use zolana_interface::user_registry::{
    instruction::{
        self as user_registry_instruction, RegisterData, RotateSyncDelegateKeyData,
        SetSyncDelegateData,
    },
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

pub fn build_rotate_sync_delegate_key_ix(
    owner: &Pubkey,
    sync_delegate: &Pubkey,
    sync_pubkey: [u8; 33],
    viewing_pubkey: [u8; 33],
) -> Instruction {
    let (user_record, _bump) = user_record_pda(owner);
    user_registry_instruction::rotate_sync_delegate_key(
        user_record,
        *sync_delegate,
        RotateSyncDelegateKeyData {
            sync_pubkey,
            viewing_pubkey,
        },
    )
}

pub fn build_revoke_sync_delegate_ix(owner: &Pubkey, signer: &Pubkey) -> Instruction {
    let (user_record, _bump) = user_record_pda(owner);
    user_registry_instruction::revoke_sync_delegate(user_record, *signer)
}

pub fn fetch_user_record(svm: &litesvm::LiteSVM, owner: &Pubkey) -> Option<UserRecord> {
    let (pda, _bump) = user_record_pda(owner);
    let account = svm.get_account(&pda)?;
    UserRecord::from_account_data(&account.data).ok()
}
