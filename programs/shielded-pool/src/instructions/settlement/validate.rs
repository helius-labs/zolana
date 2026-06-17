use pinocchio::{
    address::{address_eq, Address},
    error::ProgramError,
    AccountView,
};
use zolana_interface::{
    error::ShieldedPoolError, DEFAULT_SOL_INTERFACE_INDEX_SEED, SHIELDED_POOL_CPI_AUTHORITY,
    SOL_INTERFACE_PDA_SEED, SPL_ASSET_VAULT_PDA_SEED, SPL_TOKEN_ACCOUNT_INITIALIZED,
    SPL_TOKEN_ACCOUNT_LEN, SPL_TOKEN_ACCOUNT_STATE_OFFSET, SPL_TOKEN_PROGRAM_ID,
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

pub fn validate_spl_settlement(
    program_id: &Address,
    vault: &AccountView,
    user_token_account: &AccountView,
    token_program: &AccountView,
) -> Result<[u8; 32], ProgramError> {
    let spl_token_program_id = Address::from(SPL_TOKEN_PROGRAM_ID);
    if !address_eq(token_program.address(), &spl_token_program_id)
        || !vault.is_writable()
        || !user_token_account.is_writable()
    {
        return Err(ShieldedPoolError::InvalidSettlementAccounts.into());
    }

    let vault_state = read_token_account(vault, token_program.address())?;
    let user_state = read_token_account(user_token_account, token_program.address())?;

    if vault_state.mint != user_state.mint || vault_state.owner != SHIELDED_POOL_CPI_AUTHORITY {
        return Err(ShieldedPoolError::InvalidSettlementAccounts.into());
    }

    let (expected_vault, _) = Address::derive_program_address(
        &[SPL_ASSET_VAULT_PDA_SEED, vault_state.mint.as_slice()],
        program_id,
    )
    .ok_or(ShieldedPoolError::InvalidSettlementAccounts)?;
    if !address_eq(vault.address(), &expected_vault) {
        return Err(ShieldedPoolError::InvalidSettlementAccounts.into());
    }

    Ok(vault_state.mint)
}

pub(crate) struct TokenAccountState {
    pub mint: [u8; 32],
    pub owner: [u8; 32],
}

pub(crate) fn read_token_account(
    account: &AccountView,
    token_program: &Address,
) -> Result<TokenAccountState, ProgramError> {
    if !account.owned_by(token_program) || account.data_len() != SPL_TOKEN_ACCOUNT_LEN {
        return Err(ShieldedPoolError::InvalidSettlementAccounts.into());
    }

    let data = account
        .try_borrow()
        .map_err(|_| ShieldedPoolError::InvalidSettlementAccounts)?;
    if data.get(SPL_TOKEN_ACCOUNT_STATE_OFFSET).copied() != Some(SPL_TOKEN_ACCOUNT_INITIALIZED) {
        return Err(ShieldedPoolError::InvalidSettlementAccounts.into());
    }

    let mint = data
        .get(0..32)
        .ok_or(ShieldedPoolError::InvalidSettlementAccounts)?
        .try_into()
        .map_err(|_| ShieldedPoolError::InvalidSettlementAccounts)?;
    let owner = data
        .get(32..64)
        .ok_or(ShieldedPoolError::InvalidSettlementAccounts)?
        .try_into()
        .map_err(|_| ShieldedPoolError::InvalidSettlementAccounts)?;
    Ok(TokenAccountState { mint, owner })
}
