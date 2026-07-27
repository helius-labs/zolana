//! LiteSVM test helpers for the user-registry program.

use solana_instruction::Instruction;
use solana_pubkey::Pubkey;
use zolana_user_registry_interface::{
    instruction::{self as user_registry_instruction, RegisterData, UpdateKeysData},
    user_record_pda,
};
pub use zolana_user_registry_interface::{user_registry_program_id, UserRecord};

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

pub fn build_set_merging_enabled_ix(owner: &Pubkey, signer: &Pubkey, enabled: bool) -> Instruction {
    let (user_record, _bump) = user_record_pda(owner);
    user_registry_instruction::set_merging_enabled(user_record, *signer, enabled)
}

pub fn build_update_keys_ix(
    owner: &Pubkey,
    owner_p256: Option<[u8; 33]>,
    nullifier_pubkey: [u8; 32],
    viewing_pubkey: [u8; 33],
) -> Instruction {
    let (user_record, _bump) = user_record_pda(owner);
    user_registry_instruction::update_keys(
        user_record,
        *owner,
        UpdateKeysData {
            owner_p256,
            nullifier_pubkey,
            viewing_pubkey,
        },
    )
}

pub fn fetch_user_record(svm: &litesvm::LiteSVM, owner: &Pubkey) -> Option<UserRecord> {
    let (pda, _bump) = user_record_pda(owner);
    let account = svm.get_account(&pda)?;
    UserRecord::try_from_account_data(&account.data).ok()
}
