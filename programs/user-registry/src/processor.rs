use borsh::BorshDeserialize;
use pinocchio::{error::ProgramError, AccountView, Address, ProgramResult};
use zolana_interface::user_registry::instruction::{
    discriminator, RegisterData, RotateSyncDelegateKeyData, SetSyncDelegateData,
};

use crate::{
    error::{fail, UserRegistryError},
    instructions::{
        register::process_register,
        revoke_sync_delegate::process_revoke_sync_delegate,
        rotate_sync_delegate_key::process_rotate_sync_delegate_key,
        set_sync_delegate::process_set_sync_delegate,
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
        _ => Err(ProgramError::InvalidInstructionData),
    }
}
