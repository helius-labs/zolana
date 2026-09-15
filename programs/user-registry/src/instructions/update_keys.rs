use pinocchio::{error::ProgramError, AccountView, Address, ProgramResult};
use zolana_user_registry_interface::instruction::UpdateKeysData;

use super::{
    common::{check_record_pda_with_bump, read_record, write_record},
    p256_proof::verify_p256_key_binding,
};
use crate::error::{fail, UserRegistryError};

/// Updates the shielded keys stored in an existing user record.
pub fn process_update_keys(
    program_id: &Address,
    accounts: &mut [AccountView],
    data: UpdateKeysData,
) -> ProgramResult {
    if accounts.len() < 2 {
        return Err(ProgramError::NotEnoughAccountKeys);
    }
    let (head, tail) = accounts.split_at_mut(1);
    let record = &mut head[0];
    let owner = &tail[0];

    if !owner.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }

    let mut state = read_record(record, program_id)?;
    check_record_pda_with_bump(record, state.owner.as_array(), state.bump, program_id)?;
    if state.owner.as_array() != owner.address().as_array() {
        return Err(fail(UserRegistryError::OwnerMismatch));
    }
    // The nullifier pubkey is wallet-wide and part of the published owner hash,
    // so rotating it in place would replace the record's shielded identity while
    // every UTXO already addressed to the old one stays behind. Rejecting before
    // the proof check leaves the record untouched.
    if data.nullifier_pubkey != state.nullifier_pubkey {
        return Err(fail(UserRegistryError::NullifierPubkeyRotation));
    }

    if let Some(owner_p256) = &data.owner_p256 {
        let instructions = tail.get(1).ok_or(ProgramError::NotEnoughAccountKeys)?;
        verify_p256_key_binding(instructions, record.address(), owner.address(), owner_p256)?;
    }

    state.owner_p256 = data.owner_p256;
    state.viewing_pubkey = data.viewing_pubkey;
    write_record(record, &state)
}
