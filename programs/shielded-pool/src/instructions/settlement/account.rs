use pinocchio::AccountView;

/// Settlement account shape shared by every public-amount rail. Built by each
/// instruction's account parser and consumed by `settle_sol` /
/// `settle_spl_deposit` / `settle_spl_withdrawal`.
pub enum Settlement<'a> {
    Sol(SettlementAccountsSol<'a>),
    SplDeposit(SplDepositAccounts<'a>),
    SplWithdrawal(SplWithdrawalAccounts<'a>),
}

pub struct SettlementAccountsSol<'a> {
    pub sol_interface: &'a AccountView,
    pub sol_interface_bump: u8,
    pub recipient: &'a AccountView,
}

pub struct SplDepositAccounts<'a> {
    pub mint_account: &'a AccountView,
    pub decimals: u8,
    pub vault: &'a AccountView,
    pub depositor: &'a AccountView,
    pub user_token_account: &'a AccountView,
    pub token_program: &'a AccountView,
}

pub struct SplWithdrawalAccounts<'a> {
    pub cpi_authority: &'a AccountView,
    pub mint_account: &'a AccountView,
    pub decimals: u8,
    pub vault: &'a AccountView,
    pub user_token_account: &'a AccountView,
    pub token_program: &'a AccountView,
}
