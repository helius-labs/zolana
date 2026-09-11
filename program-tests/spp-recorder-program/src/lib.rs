//! Records the privileges of every account it is called with into the first.

use pinocchio::{error::ProgramError, AccountView, Address, ProgramResult};

#[cfg(not(feature = "no-entrypoint"))]
mod entrypoint {
    pinocchio::entrypoint!(crate::process_instruction);
}

/// Byte `i` of the first account is `is_signer | is_writable << 1` of account `i`.
pub fn process_instruction(
    _program_id: &Address,
    accounts: &mut [AccountView],
    _data: &[u8],
) -> ProgramResult {
    let flags: Vec<u8> = accounts
        .iter()
        .map(|account| u8::from(account.is_signer()) | u8::from(account.is_writable()) << 1)
        .collect();
    let target = accounts
        .first_mut()
        .ok_or(ProgramError::NotEnoughAccountKeys)?;
    let mut data = target.try_borrow_mut()?;
    data.get_mut(..flags.len())
        .ok_or(ProgramError::AccountDataTooSmall)?
        .copy_from_slice(&flags);
    Ok(())
}
