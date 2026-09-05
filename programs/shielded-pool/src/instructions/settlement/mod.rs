mod account;
mod sol;
mod spl;
pub(crate) mod validate;

pub use account::{Settlement, SettlementAccountsSol, SplDepositAccounts, SplWithdrawalAccounts};
pub(crate) use sol::settle_sol;
pub(crate) use spl::{settle_spl_deposit, settle_spl_withdrawal};
pub(crate) use validate::{
    validate_sol_settlement, validate_spl_deposit_settlement, validate_spl_withdrawal_settlement,
    ValidatedSplSettlement,
};

use pinocchio::{error::ProgramError, AccountView, ProgramResult};
use zolana_interface::{
    error::ShieldedPoolError, instruction::instruction_data::transact::InterfaceTransfer,
};

impl<'a> Settlement<'a> {
    pub(crate) fn settle(&self, amount: u64) -> ProgramResult {
        match self {
            Self::SolDeposit(accounts) => settle_sol(accounts, amount, true),
            Self::SolWithdrawal(accounts) => settle_sol(accounts, amount, false),
            Self::SplDeposit(accounts) => settle_spl_deposit(accounts, amount),
            Self::SplWithdrawal(accounts) => settle_spl_withdrawal(accounts, amount),
        }
    }

    /// Validates the accounts against the transfer and returns the byte the
    /// parser stores per transfer: mint decimals for SPL rails, the interface
    /// PDA bump for SOL rails.
    pub(crate) fn validate(&self, transfer: InterfaceTransfer) -> Result<u8, ProgramError> {
        match (self, transfer) {
            (Self::SolDeposit(accounts) | Self::SolWithdrawal(accounts), _) => {
                validate_sol_settlement(accounts.sol_interface_account, accounts.user_account)
            }
            (
                Self::SplDeposit(accounts),
                InterfaceTransfer::SplDeposit {
                    spl_interface_bump, ..
                },
            ) => Ok(validate_spl_deposit_settlement(
                accounts.mint_account,
                accounts.spl_interface_account,
                accounts.user_token_account,
                accounts.token_program_account,
                spl_interface_bump,
                accounts.token_authority_account,
            )?
            .decimals),
            (
                Self::SplWithdrawal(accounts),
                InterfaceTransfer::SplWithdrawal {
                    spl_interface_bump, ..
                },
            ) => Ok(validate_spl_withdrawal_settlement(
                accounts.cpi_authority_account,
                accounts.mint_account,
                accounts.spl_interface_account,
                accounts.user_token_account,
                accounts.token_program_account,
                spl_interface_bump,
            )?
            .decimals),
            _ => Err(ShieldedPoolError::InvalidSettlementAccounts.into()),
        }
    }

    /// The user-side account `external_data_hash` commits to for this leg.
    pub(crate) fn user_account(&self) -> &'a AccountView {
        match self {
            Self::SolDeposit(accounts) | Self::SolWithdrawal(accounts) => accounts.user_account,
            Self::SplDeposit(accounts) => accounts.user_token_account,
            Self::SplWithdrawal(accounts) => accounts.user_token_account,
        }
    }

    /// The per-mint interface vault `external_data_hash` commits to for an SPL
    /// leg; a SOL leg has none.
    pub(crate) fn spl_interface_account(&self) -> Option<&'a AccountView> {
        match self {
            Self::SolDeposit(_) | Self::SolWithdrawal(_) => None,
            Self::SplDeposit(accounts) => Some(accounts.spl_interface_account),
            Self::SplWithdrawal(accounts) => Some(accounts.spl_interface_account),
        }
    }

    pub(crate) fn spl_asset(&self) -> Result<Option<[u8; 32]>, ProgramError> {
        match self {
            Self::SolDeposit(_) | Self::SolWithdrawal(_) => Ok(None),
            Self::SplDeposit(accounts) => Ok(Some(accounts.mint_account.address().to_bytes())),
            Self::SplWithdrawal(accounts) => Ok(Some(accounts.mint_account.address().to_bytes())),
        }
    }
}
