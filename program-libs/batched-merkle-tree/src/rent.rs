//! Crate-local rent helpers.
//!
//! `light-account-checks` no longer provides a sysvar rent helper, and its
//! `check_account_balance_is_rent_exempt` now requires a caller-supplied
//! `rent_minimum`. These helpers reproduce the OLD `light-account-checks`
//! semantics exactly so existing behavior and unit-test assertions are
//! preserved:
//! - `get_min_rent_balance` reads the rent sysvar on-chain and errors
//!   off-chain (the sysvar is unavailable),
//! - `check_account_balance_is_rent_exempt` enforces the rent minimum
//!   on-chain and returns the account's lamports off-chain (check skipped).

use light_account_checks::AccountView;

use crate::errors::BatchedMerkleTreeError;

/// Mirrors the OLD light-account-checks behavior exactly: reads the rent
/// sysvar on-chain, errors off-chain where the sysvar is unavailable.
pub(crate) fn get_min_rent_balance(size: usize) -> Result<u64, BatchedMerkleTreeError> {
    #[cfg(target_os = "solana")]
    {
        use solana_sysvar::Sysvar;
        solana_sysvar::rent::Rent::get()
            .map(|rent| rent.minimum_balance(size))
            .map_err(|_| {
                BatchedMerkleTreeError::AccountError(
                    light_account_checks::error::AccountError::InvalidAccountBalance,
                )
            })
    }
    #[cfg(not(target_os = "solana"))]
    {
        let _ = size;
        Err(BatchedMerkleTreeError::AccountError(
            light_account_checks::error::AccountError::InvalidAccountBalance,
        ))
    }
}

pub(crate) fn check_account_balance_is_rent_exempt(
    account_info: &AccountView,
    expected_size: usize,
) -> Result<u64, BatchedMerkleTreeError> {
    let account_size = account_info.data_len();
    if account_size != expected_size {
        return Err(BatchedMerkleTreeError::AccountError(
            light_account_checks::error::AccountError::InvalidAccountSize,
        ));
    }
    let lamports = account_info.lamports();
    #[cfg(target_os = "solana")]
    {
        let rent_exemption = get_min_rent_balance(expected_size)?;
        if lamports < rent_exemption {
            return Err(BatchedMerkleTreeError::AccountError(
                light_account_checks::error::AccountError::InvalidAccountBalance,
            ));
        }
        Ok(rent_exemption)
    }
    #[cfg(not(target_os = "solana"))]
    {
        Ok(lamports)
    }
}
