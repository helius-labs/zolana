//! Shared withdrawal settlement plumbing for `transact` and `execute_proposal`:
//! the SOL/SPL rail selector and the zone-auth-signed SPP `zone_transact` CPI
//! that forwards the settlement account tail.

use pinocchio::{error::ProgramError, AccountView, ProgramResult};
use zolana_squads_interface::error::SquadsZoneError;

use crate::shared::cpi::spp_zone_withdraw;

/// SOL withdrawal forwards `[sol_interface, recipient, system_program]`.
const SOL_WITHDRAWAL_ACCOUNTS: usize = 3;
/// SPL withdrawal forwards `[cpi_authority, vault, recipient,
/// user_token_account, token_program]`.
const SPL_WITHDRAWAL_ACCOUNTS: usize = 5;

/// Determine the withdrawal rail from the settlement account count: SOL (3
/// accounts) or SPL (5). Any other count is malformed.
pub fn withdrawal_is_spl(settlement: &[AccountView]) -> Result<bool, ProgramError> {
    match settlement.len() {
        SOL_WITHDRAWAL_ACCOUNTS => Ok(false),
        SPL_WITHDRAWAL_ACCOUNTS => Ok(true),
        _ => Err(SquadsZoneError::InvalidWithdrawalAccounts.into()),
    }
}

/// Forward a withdrawal to SPP's `zone_transact`, signed by the zone-auth PDA.
/// The forwarded accounts are `[payer, tree, zone_auth, <settlement>,
/// spp_program]` in SPP's order; `settlement` is the SOL/SPL tail parsed from the
/// zone instruction. The trailing SPP program account is required for SPP's
/// post-settlement event self-CPI.
pub fn forward_zone_withdrawal(
    spp_program: &AccountView,
    payer: &AccountView,
    tree: &AccountView,
    zone_auth: &AccountView,
    settlement: &[AccountView],
    spp_data: &[u8],
    zone_auth_bump: u8,
) -> ProgramResult {
    let mut cpi_accounts: Vec<&AccountView> = Vec::with_capacity(4 + settlement.len());
    cpi_accounts.push(payer);
    cpi_accounts.push(tree);
    cpi_accounts.push(zone_auth);
    for account in settlement {
        cpi_accounts.push(account);
    }
    cpi_accounts.push(spp_program);
    spp_zone_withdraw(spp_program, &cpi_accounts, spp_data, zone_auth_bump)
}
