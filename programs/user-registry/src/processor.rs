use borsh::BorshDeserialize;
use pinocchio::{error::ProgramError, AccountView, Address, ProgramResult};
use rings_user_registry_interface::instruction::{
    discriminator, RegisterData, RotateSyncDelegateKeyData, SetMergingEnabledData,
    SetSyncDelegateData, UpdateKeysData,
};

use crate::{
    error::{fail, UserRegistryError},
    instructions::{
        register::process_register, revoke_sync_delegate::process_revoke_sync_delegate,
        rotate_sync_delegate_key::process_rotate_sync_delegate_key,
        set_merging_enabled::process_set_merging_enabled,
        set_sync_delegate::process_set_sync_delegate, update_keys::process_update_keys,
    },
};

pub fn process_instruction(
    program_id: &Address,
    accounts: &mut [AccountView],
    instruction_data: &[u8],
) -> ProgramResult {
    let (ix_discriminator, payload) = instruction_data
        .split_first()
        .ok_or(ProgramError::InvalidInstructionData)?;

    match *ix_discriminator {
        discriminator::REGISTER => {
            let data = RegisterData::try_from_slice(payload)
                .map_err(|_| fail(UserRegistryError::InvalidInstructionData))?;
            process_register(program_id, accounts, data)
        }
        discriminator::SET_SYNC_DELEGATE => {
            let data = SetSyncDelegateData::try_from_slice(payload)
                .map_err(|_| fail(UserRegistryError::InvalidInstructionData))?;
            process_set_sync_delegate(program_id, accounts, data)
        }
        discriminator::ROTATE_SYNC_DELEGATE_KEY => {
            let data = RotateSyncDelegateKeyData::try_from_slice(payload)
                .map_err(|_| fail(UserRegistryError::InvalidInstructionData))?;
            process_rotate_sync_delegate_key(program_id, accounts, data)
        }
        discriminator::REVOKE_SYNC_DELEGATE => {
            if !payload.is_empty() {
                return Err(fail(UserRegistryError::InvalidInstructionData));
            }
            process_revoke_sync_delegate(program_id, accounts)
        }
        discriminator::SET_MERGING_ENABLED => {
            let data = SetMergingEnabledData::try_from_slice(payload)
                .map_err(|_| fail(UserRegistryError::InvalidInstructionData))?;
            process_set_merging_enabled(program_id, accounts, data)
        }
        discriminator::UPDATE_KEYS => {
            let data = UpdateKeysData::try_from_slice(payload)
                .map_err(|_| fail(UserRegistryError::InvalidInstructionData))?;
            process_update_keys(program_id, accounts, data)
        }
        _ => Err(ProgramError::InvalidInstructionData),
    }
}
