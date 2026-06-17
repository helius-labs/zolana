use pinocchio::{
    address::{address_eq, Address},
    error::ProgramError,
    AccountView,
};
use zolana_interface::{
    error::ShieldedPoolError, DEFAULT_SOL_INTERFACE_INDEX_SEED, SHIELDED_POOL_CPI_AUTHORITY,
    SOL_INTERFACE_PDA_SEED,
};

/// Validate the `sol_interface` account is the canonical SOL-custody PDA and
/// return its bump (needed to sign the withdrawal transfer).
#[inline(always)]
pub fn validate_sol_interface(
    program_id: &Address,
    account: &AccountView,
) -> Result<u8, ProgramError> {
    let (expected, bump) = Address::derive_program_address(
        &[SOL_INTERFACE_PDA_SEED, DEFAULT_SOL_INTERFACE_INDEX_SEED],
        program_id,
    )
    .ok_or(ShieldedPoolError::InvalidSettlementAccounts)?;
    if !address_eq(account.address(), &expected) {
        return Err(ShieldedPoolError::InvalidSettlementAccounts.into());
    }
    Ok(bump)
}

#[inline(always)]
pub fn validate_cpi_authority(account: &AccountView) -> Result<&AccountView, ProgramError> {
    let expected = Address::from(SHIELDED_POOL_CPI_AUTHORITY);
    if !address_eq(account.address(), &expected) {
        return Err(ShieldedPoolError::InvalidSettlementAccounts.into());
    }
    Ok(account)
}
