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

use pinocchio::{error::ProgramError, ProgramResult};

impl Settlement<'_> {
    pub(crate) fn settle(&self, amount: u64) -> ProgramResult {
        match self {
            Self::SolDeposit(accounts) => settle_sol(accounts, amount, true),
            Self::SolWithdrawal(accounts) => settle_sol(accounts, amount, false),
            Self::SplDeposit(accounts) => settle_spl_deposit(accounts, amount),
            Self::SplWithdrawal(accounts) => settle_spl_withdrawal(accounts, amount),
        }
    }

    pub(crate) fn is_deposit(&self) -> bool {
        matches!(self, Self::SolDeposit(_) | Self::SplDeposit(_))
    }

    /// Addresses `external_data_hash` binds for this leg, in preimage order.
    ///
    /// SOL binds the user account; SPL binds the user token account and the
    /// per-mint interface vault. The mint itself is bound transitively, because
    /// the vault's PDA derivation covers it, and the remaining group accounts
    /// are pinned by address equality or by the token program's own checks.
    /// `Address::as_array` borrows the runtime's input region, so this copies
    /// nothing.
    pub(crate) fn bound_addresses(&self) -> impl Iterator<Item = &[u8; 32]> {
        let (first, second) = match self {
            Self::SolDeposit(sol) | Self::SolWithdrawal(sol) => {
                (sol.recipient_account.address().as_array(), None)
            }
            Self::SplDeposit(spl) => (
                spl.user_token_account.address().as_array(),
                Some(spl.spl_interface_account.address().as_array()),
            ),
            Self::SplWithdrawal(spl) => (
                spl.user_token_account.address().as_array(),
                Some(spl.spl_interface_account.address().as_array()),
            ),
        };
        core::iter::once(first).chain(second)
    }

    pub(crate) fn spl_asset(&self) -> Result<Option<[u8; 32]>, ProgramError> {
        match self {
            Self::SolDeposit(_) | Self::SolWithdrawal(_) => Ok(None),
            Self::SplDeposit(accounts) => Ok(Some(accounts.mint_account.address().to_bytes())),
            Self::SplWithdrawal(accounts) => Ok(Some(accounts.mint_account.address().to_bytes())),
        }
    }
}
