use pinocchio::{error::ProgramError, AccountView};
use zolana_interface::{
    error::ShieldedPoolError, instruction::instruction_data::transact::InterfaceTransfer,
};

/// Settlement account shape shared by every public-amount rail. Built by each
/// instruction's account parser and consumed by `settle_sol` /
/// `settle_spl_deposit` / `settle_spl_withdrawal`.
pub enum Settlement<'a> {
    SolDeposit(SettlementAccountsSol<'a>),
    SolWithdrawal(SettlementAccountsSol<'a>),
    SplDeposit(SplDepositAccounts<'a>),
    SplWithdrawal(SplWithdrawalAccounts<'a>),
}

pub struct SettlementAccountsSol<'a> {
    pub sol_interface_account: &'a AccountView,
    pub sol_interface_bump: u8,
    /// User-side SOL account: source for deposits, destination for withdrawals.
    pub user_account: &'a AccountView,
}

pub struct SplDepositAccounts<'a> {
    pub mint_account: &'a AccountView,
    pub decimals: u8,
    pub spl_interface_account: &'a AccountView,
    pub token_authority_account: &'a AccountView,
    pub user_token_account: &'a AccountView,
    pub token_program_account: &'a AccountView,
}

pub struct SplWithdrawalAccounts<'a> {
    pub cpi_authority_account: &'a AccountView,
    pub mint_account: &'a AccountView,
    pub decimals: u8,
    pub spl_interface_account: &'a AccountView,
    pub user_token_account: &'a AccountView,
    pub token_program_account: &'a AccountView,
}

impl<'a> Settlement<'a> {
    /// Assembles a settlement from the transfer's account group without
    /// validating it. `aux` is the per-transfer byte the parser derived while
    /// validating: the mint decimals for SPL rails, the interface PDA bump for
    /// SOL rails.
    pub(crate) fn from_group(
        transfer: InterfaceTransfer,
        group: &'a [AccountView],
        aux: u8,
    ) -> Result<Self, ProgramError> {
        let settlement = match (transfer, group) {
            (InterfaceTransfer::SolDeposit { .. }, [sol_interface_account, user_account]) => {
                Self::SolDeposit(SettlementAccountsSol {
                    sol_interface_account,
                    sol_interface_bump: aux,
                    user_account,
                })
            }
            (InterfaceTransfer::SolWithdrawal { .. }, [sol_interface_account, user_account]) => {
                Self::SolWithdrawal(SettlementAccountsSol {
                    sol_interface_account,
                    sol_interface_bump: aux,
                    user_account,
                })
            }
            (
                InterfaceTransfer::SplDeposit { .. },
                [mint_account, spl_interface_account, token_authority_account, user_token_account, token_program_account],
            ) => Self::SplDeposit(SplDepositAccounts {
                mint_account,
                decimals: aux,
                spl_interface_account,
                token_authority_account,
                user_token_account,
                token_program_account,
            }),
            (
                InterfaceTransfer::SplWithdrawal { .. },
                [cpi_authority_account, mint_account, spl_interface_account, user_token_account, token_program_account],
            ) => Self::SplWithdrawal(SplWithdrawalAccounts {
                cpi_authority_account,
                mint_account,
                decimals: aux,
                spl_interface_account,
                user_token_account,
                token_program_account,
            }),
            _ => return Err(ShieldedPoolError::InvalidSettlementAccounts.into()),
        };
        Ok(settlement)
    }
}
