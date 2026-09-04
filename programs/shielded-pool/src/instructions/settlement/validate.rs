use crate::instructions::shared::caused_by;
use pinocchio::{
    address::{address_eq, Address},
    error::ProgramError,
    AccountView,
};
use spl_token_2022_interface::{extension::PodStateWithExtensions, pod::PodAccount};
use zolana_interface::{
    error::ShieldedPoolError, SHIELDED_POOL_CPI_AUTHORITY, SOL_INTERFACE, SPL_INTERFACE_PDA_SEED,
    SPL_TOKEN_2022_PROGRAM_ID, SPL_TOKEN_ACCOUNT_INITIALIZED, SPL_TOKEN_PROGRAM_ID,
};

const SPL_TOKEN_MINT_DECIMALS_OFFSET: usize = 44;
const SYSTEM_PROGRAM_ID: Address = Address::new_from_array([0u8; 32]);

#[derive(Clone, Copy)]
struct TokenMintState {
    pub mint: [u8; 32],
    pub decimals: u8,
}

#[derive(Clone, Copy)]
pub(crate) struct ValidatedSplSettlement {
    pub mint: [u8; 32],
    pub decimals: u8,
    pub user_token_account_authority: [u8; 32],
}

#[inline(always)]
fn validate_token_program(token_program: &Address) -> Result<(), ProgramError> {
    if address_eq(token_program, &Address::from(SPL_TOKEN_PROGRAM_ID))
        || address_eq(token_program, &Address::from(SPL_TOKEN_2022_PROGRAM_ID))
    {
        Ok(())
    } else {
        Err(ShieldedPoolError::InvalidSettlementAccounts.into())
    }
}

/// Read the immutable base fields needed by `TransferChecked`.
///
/// Mint ownership, initialization, and extension policy are validated once,
/// when the SPL interface is created. Settlement still binds this mint address
/// to both token accounts and lets the token-program CPI validate the mint.
fn read_token_mint(mint: &AccountView) -> Result<TokenMintState, ProgramError> {
    let data = mint
        .try_borrow()
        .map_err(caused_by(ShieldedPoolError::InvalidSettlementAccounts))?;
    let decimals = *data
        .get(SPL_TOKEN_MINT_DECIMALS_OFFSET)
        .ok_or(ShieldedPoolError::InvalidSettlementAccounts)?;
    Ok(TokenMintState {
        mint: mint.address().to_bytes(),
        decimals,
    })
}

/// 1. sol interface address is correct pda, owned by system program and writable
/// 2. user account is writable
#[inline(always)]
pub(crate) fn validate_sol_settlement(
    sol_interface: &AccountView,
    user_account: &AccountView,
) -> Result<u8, ProgramError> {
    if !address_eq(
        sol_interface.address(),
        &Address::new_from_array(SOL_INTERFACE),
    ) || !sol_interface.is_writable()
        || !user_account.is_writable()
        || !sol_interface.owned_by(&SYSTEM_PROGRAM_ID)
    {
        return Err(ShieldedPoolError::InvalidSettlementAccounts.into());
    }
    Ok(zolana_interface::SOL_INTERFACE_BUMP)
}

#[inline(always)]
fn validate_cpi_authority(account: &AccountView) -> Result<(), ProgramError> {
    let expected = Address::from(SHIELDED_POOL_CPI_AUTHORITY);
    if !address_eq(account.address(), &expected) {
        return Err(ShieldedPoolError::InvalidSettlementAccounts.into());
    }
    Ok(())
}

fn validate_spl_settlement(
    mint_account: &AccountView,
    spl_interface_account: &AccountView,
    sender_token_account: &AccountView,
    token_program: &AccountView,
    interface_pda_bump: u8,
) -> Result<ValidatedSplSettlement, ProgramError> {
    if !spl_interface_account.is_writable() || !sender_token_account.is_writable() {
        return Err(ShieldedPoolError::InvalidSettlementAccounts.into());
    }

    let spl_interface_pda_state =
        read_token_account(spl_interface_account, token_program.address())?;
    let sender_state = read_token_account(sender_token_account, token_program.address())?;
    let mint_state = read_token_mint(mint_account)?;

    // 1. Mint must match token accounts mints
    // 2. spl interface account must be owned by authority pda
    if mint_state.mint != spl_interface_pda_state.mint
        || spl_interface_pda_state.mint != sender_state.mint
        || spl_interface_pda_state.owner != SHIELDED_POOL_CPI_AUTHORITY
    {
        return Err(ShieldedPoolError::InvalidSettlementAccounts.into());
    }

    let expected_interface_pda = Address::derive_address(
        &[
            SPL_INTERFACE_PDA_SEED,
            spl_interface_pda_state.mint.as_slice(),
        ],
        Some(interface_pda_bump),
        &crate::ID,
    );
    if !address_eq(spl_interface_account.address(), &expected_interface_pda) {
        return Err(ShieldedPoolError::InvalidSettlementAccounts.into());
    }

    Ok(ValidatedSplSettlement {
        mint: mint_state.mint,
        decimals: mint_state.decimals,
        user_token_account_authority: sender_state.owner,
    })
}

pub(crate) fn validate_spl_deposit_settlement(
    mint_account: &AccountView,
    spl_interface_account: &AccountView,
    user_token_account: &AccountView,
    token_program_account: &AccountView,
    interface_pda_bump: u8,
    token_authority_account: &AccountView,
) -> Result<ValidatedSplSettlement, ProgramError> {
    if !token_authority_account.is_signer() {
        return Err(ShieldedPoolError::SplTokenAuthorityMustSign.into());
    }
    let settlement = validate_spl_settlement(
        mint_account,
        spl_interface_account,
        user_token_account,
        token_program_account,
        interface_pda_bump,
    )?;
    if settlement.user_token_account_authority != token_authority_account.address().to_bytes() {
        return Err(ShieldedPoolError::InvalidSettlementAccounts.into());
    }
    Ok(settlement)
}

pub(crate) fn validate_spl_withdrawal_settlement(
    cpi_authority_account: &AccountView,
    mint_account: &AccountView,
    spl_interface_account: &AccountView,
    user_token_account: &AccountView,
    token_program_account: &AccountView,
    interface_pda_bump: u8,
) -> Result<ValidatedSplSettlement, ProgramError> {
    validate_cpi_authority(cpi_authority_account)?;
    validate_spl_settlement(
        mint_account,
        spl_interface_account,
        user_token_account,
        token_program_account,
        interface_pda_bump,
    )
}

pub(crate) struct TokenAccountState {
    pub mint: [u8; 32],
    pub owner: [u8; 32],
}

fn read_token_account(
    account: &AccountView,
    token_program: &Address,
) -> Result<TokenAccountState, ProgramError> {
    validate_token_program(token_program)?;
    if !account.owned_by(token_program) {
        return Err(ShieldedPoolError::InvalidSettlementAccounts.into());
    }

    let data = account
        .try_borrow()
        .map_err(caused_by(ShieldedPoolError::InvalidSettlementAccounts))?;
    let state = PodStateWithExtensions::<PodAccount>::unpack(&data)
        .map_err(caused_by(ShieldedPoolError::InvalidSettlementAccounts))?;
    if state.base.state != SPL_TOKEN_ACCOUNT_INITIALIZED {
        return Err(ShieldedPoolError::InvalidSettlementAccounts.into());
    }
    Ok(TokenAccountState {
        mint: state.base.mint.to_bytes(),
        owner: state.base.owner.to_bytes(),
    })
}
