use solana_account_view::AccountView;
use solana_address::Address;

use crate::{
    discriminator::{Discriminator, DISCRIMINATOR_LEN},
    error::AccountError,
};

/// Sets discriminator in account data.
pub fn account_info_init<T: Discriminator>(
    account_info: &mut AccountView,
) -> Result<(), AccountError> {
    set_discriminator::<T>(
        &mut account_info
            .try_borrow_mut()
            .map_err(|_| AccountError::BorrowAccountDataFailed)?,
    )?;
    Ok(())
}

/// Checks:
/// 1. account is mutable
/// 2. account owned by program_id
/// 3. account discriminator
pub fn check_account_info_mut<T: Discriminator>(
    program_id: &[u8; 32],
    account_info: &AccountView,
) -> Result<(), AccountError> {
    check_mut(account_info)?;
    check_account_info::<T>(program_id, account_info)
}

/// Checks:
/// 1. account is not mutable
/// 2. account owned by program_id
/// 3. account discriminator
pub fn check_account_info_non_mut<T: Discriminator>(
    program_id: &[u8; 32],
    account_info: &AccountView,
) -> Result<(), AccountError> {
    check_non_mut(account_info)?;
    check_account_info::<T>(program_id, account_info)
}

pub fn check_non_mut(account_info: &AccountView) -> Result<(), AccountError> {
    if account_info.is_writable() {
        return Err(AccountError::AccountMutable);
    }
    Ok(())
}

/// Checks:
/// 1. account owned by program_id
/// 2. account discriminator
pub fn check_account_info<T: Discriminator>(
    program_id: &[u8; 32],
    account_info: &AccountView,
) -> Result<(), AccountError> {
    check_owner(program_id, account_info)?;

    let account_data = &account_info
        .try_borrow()
        .map_err(|_| AccountError::BorrowAccountDataFailed)?;
    check_discriminator::<T>(account_data)
}

/// Checks:
/// 1. discriminator is uninitialized
/// 2. sets discriminator
pub fn set_discriminator<T: Discriminator>(bytes: &mut [u8]) -> Result<(), AccountError> {
    check_data_is_zeroed::<DISCRIMINATOR_LEN>(bytes)
        .map_err(|_| AccountError::AlreadyInitialized)?;
    bytes
        .get_mut(0..DISCRIMINATOR_LEN)
        .ok_or(AccountError::InvalidAccountSize)?
        .copy_from_slice(&T::LIGHT_DISCRIMINATOR);
    Ok(())
}

/// Checks:
/// 1. account size is at least U
/// 2. account discriminator
pub fn check_discriminator<T: Discriminator>(bytes: &[u8]) -> Result<(), AccountError> {
    let discriminator = bytes
        .get(0..DISCRIMINATOR_LEN)
        .ok_or(AccountError::InvalidAccountSize)?;

    if T::LIGHT_DISCRIMINATOR != *discriminator {
        return Err(AccountError::InvalidDiscriminator);
    }
    Ok(())
}

/// Checks that the account balance is greater or equal to the provided rent
/// exemption minimum.
///
/// `rent_minimum` is supplied by the caller (e.g. from the program's own rent
/// sysvar access); this crate no longer depends on a sysvar.
pub fn check_account_balance_is_rent_exempt(
    account_info: &AccountView,
    expected_size: usize,
    rent_minimum: u64,
) -> Result<u64, AccountError> {
    let account_size = account_info.data_len();
    if account_size != expected_size {
        return Err(AccountError::InvalidAccountSize);
    }
    let lamports = account_info.lamports();
    if lamports < rent_minimum {
        return Err(AccountError::InvalidAccountBalance);
    }
    Ok(rent_minimum)
}

pub fn check_signer(account_info: &AccountView) -> Result<(), AccountError> {
    if !account_info.is_signer() {
        return Err(AccountError::InvalidSigner);
    }
    Ok(())
}

pub fn check_mut(account_info: &AccountView) -> Result<(), AccountError> {
    if !account_info.is_writable() {
        return Err(AccountError::AccountNotMutable);
    }
    Ok(())
}

pub fn check_owner(owner: &[u8; 32], account_info: &AccountView) -> Result<(), AccountError> {
    if !account_info.owned_by(&Address::from(*owner)) {
        return Err(AccountError::AccountOwnedByWrongProgram);
    }
    Ok(())
}

pub fn check_program(
    program_id: &[u8; 32],
    account_info: &AccountView,
) -> Result<(), AccountError> {
    if account_info.address().to_bytes() != *program_id {
        return Err(AccountError::InvalidProgramId);
    }
    if !account_info.executable() {
        return Err(AccountError::ProgramNotExecutable);
    }
    Ok(())
}

/// Check that an account is not initialized by checking it's discriminator is zeroed.
///
/// Equivalent functionality to anchor #[account(zero)].
pub fn check_data_is_zeroed<const N: usize>(data: &[u8]) -> Result<(), AccountError> {
    if data
        .get(..N)
        .ok_or(AccountError::InvalidAccountSize)?
        .iter()
        .any(|&byte| byte != 0)
    {
        return Err(AccountError::AccountNotZeroed);
    }
    Ok(())
}
