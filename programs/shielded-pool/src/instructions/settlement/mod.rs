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
use zolana_interface::{error::ShieldedPoolError, token_account::AnonymousExitDestination};

impl<'a> Settlement<'a> {
    pub(crate) fn committed_accounts(&self) -> [&'a AccountView; 2] {
        match self {
            Self::SolDeposit(accounts) | Self::SolWithdrawal(accounts) => {
                [accounts.sol_interface_account, accounts.recipient_account]
            }
            Self::SplDeposit(accounts) => [accounts.mint_account, accounts.user_token_account],
            Self::SplWithdrawal(accounts) => [accounts.mint_account, accounts.user_token_account],
        }
    }

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

    /// The one key an anonymous withdrawal may name, `None` for a deposit.
    pub(crate) fn anonymous_exit(&self) -> Result<Option<&[u8; 32]>, ShieldedPoolError> {
        let destination = match self {
            Self::SolDeposit(_) | Self::SplDeposit(_) => return Ok(None),
            Self::SolWithdrawal(accounts) => AnonymousExitDestination::Sol {
                recipient: accounts.recipient_account.address(),
                owner: accounts.recipient_account.owner(),
                data_len: accounts.recipient_account.data_len(),
            },
            Self::SplWithdrawal(accounts) => AnonymousExitDestination::Spl {
                token_account: accounts.user_token_account.address(),
                control: &accounts.user_token_account_control,
            },
        };
        destination.named_key().map(Some)
    }

    pub(crate) fn spl_asset(&self) -> Result<Option<[u8; 32]>, ProgramError> {
        match self {
            Self::SolDeposit(_) | Self::SolWithdrawal(_) => Ok(None),
            Self::SplDeposit(accounts) => Ok(Some(accounts.mint_account.address().to_bytes())),
            Self::SplWithdrawal(accounts) => Ok(Some(accounts.mint_account.address().to_bytes())),
        }
    }
}
