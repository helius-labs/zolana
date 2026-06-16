use pinocchio::{
    address::{address_eq, Address},
    error::ProgramError,
    AccountView,
};
use zolana_interface::{
    instruction::instruction_data::transact::{TransactCpiSigner, TransactIxDataRef},
    SHIELDED_POOL_CPI_AUTHORITY,
};

use crate::error::ShieldedPoolError;

pub struct TransactAccounts<'a> {
    pub payer: &'a AccountView,
    pub tree: &'a AccountView,
    pub cpi_signer: Option<&'a AccountView>,
    pub settlement: Option<Settlement<'a>>,
}

pub enum Settlement<'a> {
    Sol(SettlementAccountsSol<'a>),
    Spl(SettlementAccountsSpl<'a>),
}

pub struct SettlementAccountsSol<'a> {
    pub cpi_authority: Option<&'a AccountView>,
    pub interface: &'a AccountView,
    pub recipient: &'a AccountView,
}

pub struct SettlementAccountsSpl<'a> {
    pub cpi_authority: Option<&'a AccountView>,
    pub vault: &'a AccountView,
    pub recipient: &'a AccountView,
    pub user_token_account: &'a AccountView,
    pub token_program: &'a AccountView,
}

impl<'a> TransactAccounts<'a> {
    pub fn validate_and_parse(
        accounts: &'a [AccountView],
        ix: &TransactIxDataRef<'_>,
    ) -> Result<Self, ProgramError> {
        let mut cursor = 0usize;
        let mut next = || -> Result<&'a AccountView, ProgramError> {
            let account = accounts
                .get(cursor)
                .ok_or(ProgramError::NotEnoughAccountKeys)?;
            cursor += 1;
            Ok(account)
        };

        let payer = next()?;
        validate_payer(payer)?;

        let tree = next()?;

        let cpi_signer = if let Some(signer) = ix.cpi_signer.as_ref() {
            let account = next()?;
            validate_cpi_signer(account, signer)?;
            Some(account)
        } else {
            None
        };

        let settlement = if ix.is_deposit_or_withdrawal() {
            let cpi_authority = if ix.is_deposit() {
                None
            } else {
                Some(validate_cpi_authority(next()?)?)
            };
            let interface = next()?;
            let recipient = next()?;
            if ix.is_spl() {
                let user_token_account = next()?;
                let token_program = next()?;
                Some(Settlement::Spl(SettlementAccountsSpl {
                    cpi_authority,
                    vault: interface,
                    recipient,
                    user_token_account,
                    token_program,
                }))
            } else {
                Some(Settlement::Sol(SettlementAccountsSol {
                    cpi_authority,
                    interface,
                    recipient,
                }))
            }
        } else {
            None
        };

        Ok(Self {
            payer,
            tree,
            cpi_signer,
            settlement,
        })
    }
}

#[inline(always)]
pub fn validate_payer(payer: &AccountView) -> Result<(), ProgramError> {
    if !payer.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }
    Ok(())
}

#[inline(always)]
pub fn validate_cpi_signer(
    account: &AccountView,
    signer: &TransactCpiSigner,
) -> Result<(), ProgramError> {
    if !account.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }
    verify_cpi_signer_pda(account.address(), signer)
}

#[inline(always)]
fn validate_cpi_authority(account: &AccountView) -> Result<&AccountView, ProgramError> {
    let expected = Address::from(SHIELDED_POOL_CPI_AUTHORITY);
    if !address_eq(account.address(), &expected) {
        return Err(ShieldedPoolError::InvalidSettlementAccounts.into());
    }
    Ok(account)
}

#[inline(always)]
pub fn validate_input_signer(account: &AccountView) -> Result<[u8; 32], ProgramError> {
    if !account.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }
    Ok(account.address().to_bytes())
}

#[cfg(any(target_os = "solana", target_arch = "bpf"))]
fn verify_cpi_signer_pda(
    account_key: &Address,
    signer: &TransactCpiSigner,
) -> Result<(), ProgramError> {
    use pinocchio::address::address_eq;

    const CPI_SIGNER_SEED: &[u8] = b"auth";

    let program_id = Address::from(signer.program_id);
    let bump = [signer.bump];
    let derived = Address::create_program_address(&[CPI_SIGNER_SEED, &bump], &program_id)
        .map_err(|_| ShieldedPoolError::UnauthorizedCaller)?;
    if !address_eq(account_key, &derived) {
        return Err(ShieldedPoolError::UnauthorizedCaller.into());
    }
    Ok(())
}

#[cfg(not(any(target_os = "solana", target_arch = "bpf")))]
fn verify_cpi_signer_pda(
    _account_key: &Address,
    _signer: &TransactCpiSigner,
) -> Result<(), ProgramError> {
    Err(ShieldedPoolError::UnauthorizedCaller.into())
}
