use borsh::BorshDeserialize;
use pinocchio::{error::ProgramError, AccountView, Address, ProgramResult};
use zolana_interface::user_registry::instruction::{
    tag, RegisterData, RotateSyncDelegateData, SetSyncDelegateData,
};

use crate::{
    error::{fail, UserRegistryError},
    instructions::{
        close::process_close, register::process_register, revoke::process_revoke,
        rotate_sync_delegate::process_rotate_sync_delegate,
        set_sync_delegate::process_set_sync_delegate,
    },
};

pub fn process_instruction(
    program_id: &Address,
    accounts: &mut [AccountView],
    instruction_data: &[u8],
) -> ProgramResult {
    let (ix_tag, payload) = instruction_data
        .split_first()
        .ok_or(ProgramError::InvalidInstructionData)?;

    match *ix_tag {
        tag::REGISTER => {
            let data = RegisterData::try_from_slice(payload)
                .map_err(|_| fail(UserRegistryError::InvalidInstructionData))?;
            process_register(program_id, accounts, data)
        }
        tag::SET_SYNC_DELEGATE => {
            let data = SetSyncDelegateData::try_from_slice(payload)
                .map_err(|_| fail(UserRegistryError::InvalidInstructionData))?;
            process_set_sync_delegate(program_id, accounts, data)
        }
        tag::ROTATE_SYNC_DELEGATE => {
            let data = RotateSyncDelegateData::try_from_slice(payload)
                .map_err(|_| fail(UserRegistryError::InvalidInstructionData))?;
            process_rotate_sync_delegate(program_id, accounts, data)
        }
        tag::REVOKE => {
            if !payload.is_empty() {
                return Err(fail(UserRegistryError::InvalidInstructionData));
            }
            process_revoke(program_id, accounts)
        }
        tag::CLOSE => {
            if !payload.is_empty() {
                return Err(fail(UserRegistryError::InvalidInstructionData));
            }
            process_close(program_id, accounts)
        }
        _ => Err(ProgramError::InvalidInstructionData),
    }
}
