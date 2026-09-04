use pinocchio::AccountView;

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
