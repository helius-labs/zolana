use pinocchio::AccountView;

/// Settlement account shape shared by every public-amount rail. Built by each
/// instruction's account parser and consumed by `settle_sol` / `settle_spl`.
pub enum Settlement<'a> {
    Sol(SettlementAccountsSol<'a>),
    Spl(SettlementAccountsSpl<'a>),
}

pub struct SettlementAccountsSol<'a> {
    pub sol_interface: &'a AccountView,
    pub sol_interface_bump: u8,
    pub recipient: &'a AccountView,
}

pub struct SettlementAccountsSpl<'a> {
    pub cpi_authority: Option<&'a AccountView>,
    pub vault: &'a AccountView,
    pub recipient: &'a AccountView,
    pub user_token_account: &'a AccountView,
    pub token_program: &'a AccountView,
}
