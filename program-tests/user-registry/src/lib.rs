//! LiteSVM test helpers for the user-registry program.

use solana_instruction::Instruction;
use solana_pubkey::Pubkey;
use zolana_user_registry_interface::{
    instruction::{
        self as user_registry_instruction, p256_key_binding_message, p256_verify_instruction,
        RegisterData, UpdateKeysData,
    },
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

pub fn build_register_ixs(
    owner: &Pubkey,
    owner_p256: Option<[u8; 33]>,
    nullifier_pubkey: [u8; 32],
    viewing_pubkey: [u8; 33],
    p256_signature: Option<[u8; 64]>,
) -> Vec<Instruction> {
    let registry = build_register_ix(owner, owner_p256, nullifier_pubkey, viewing_pubkey);
    compose_p256_proof(owner, owner_p256, p256_signature, registry)
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

pub fn build_update_keys_ixs(
    owner: &Pubkey,
    owner_p256: Option<[u8; 33]>,
    nullifier_pubkey: [u8; 32],
    viewing_pubkey: [u8; 33],
    p256_signature: Option<[u8; 64]>,
) -> Vec<Instruction> {
    let registry = build_update_keys_ix(owner, owner_p256, nullifier_pubkey, viewing_pubkey);
    compose_p256_proof(owner, owner_p256, p256_signature, registry)
}

fn compose_p256_proof(
    owner: &Pubkey,
    owner_p256: Option<[u8; 33]>,
    p256_signature: Option<[u8; 64]>,
    registry: Instruction,
) -> Vec<Instruction> {
    match (owner_p256, p256_signature) {
        (Some(pubkey), Some(signature)) => {
            let user_record = user_record_pda(owner).0;
            let message = p256_key_binding_message(&user_record, owner, &pubkey);
            vec![
                p256_verify_instruction(&message, &signature, &pubkey),
                registry,
            ]
        }
        (None, None) => vec![registry],
        _ => panic!("P256 registry key and proof signature must be supplied together"),
    }
}

pub fn fetch_user_record(svm: &litesvm::LiteSVM, owner: &Pubkey) -> Option<UserRecord> {
    let (pda, _bump) = user_record_pda(owner);
    let account = svm.get_account(&pda)?;
    UserRecord::try_from_account_data(&account.data).ok()
}
