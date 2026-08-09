//! Shared withdrawal settlement plumbing for `transact` and `execute_proposal`.

use pinocchio::{error::ProgramError, AccountView, ProgramResult};
use zolana_squads_interface::error::SquadsZoneError;

use crate::shared::cpi::spp_zone_withdraw;

/// SOL withdrawal forwards `[sol_interface, recipient, system_program]`.
const SOL_WITHDRAWAL_ACCOUNTS: usize = 3;
/// SPL withdrawal forwards `[cpi_authority, vault, recipient,
/// user_token_account, token_program]`.
const SPL_WITHDRAWAL_ACCOUNTS: usize = 5;

/// How a withdrawal settles. The SPL interface bump is meaningful only on the
/// SPL path, so it travels inside that variant.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WithdrawalSettlement {
    Sol,
    Spl { interface_bump: u8 },
}

/// The settlement account count is the only thing that distinguishes the two
/// paths, so an unexpected count must not fall through to either.
pub fn withdrawal_settlement(
    settlement: &[AccountView],
    spl_interface_bump: u8,
) -> Result<WithdrawalSettlement, ProgramError> {
    match settlement.len() {
        SOL_WITHDRAWAL_ACCOUNTS => Ok(WithdrawalSettlement::Sol),
        SPL_WITHDRAWAL_ACCOUNTS => Ok(WithdrawalSettlement::Spl {
            interface_bump: spl_interface_bump,
        }),
        _ => Err(SquadsZoneError::InvalidWithdrawalAccounts.into()),
    }
}

/// Forward a withdrawal to SPP's `zone_transact`, signed by the zone-auth PDA.
/// The forwarded accounts are `[payer, tree, ring_auth, <settlement>,
/// spp_program]` in SPP's order. `settlement` is the SOL/SPL tail parsed from
/// the zone instruction. The trailing SPP program account is required for SPP's
/// post-settlement event self-CPI.
pub fn forward_zone_withdrawal(
    spp_program: &AccountView,
    payer: &AccountView,
    tree: &AccountView,
    ring_auth: &AccountView,
    settlement: &[AccountView],
    spp_data: &[u8],
    ring_auth_bump: u8,
) -> ProgramResult {
    let mut cpi_accounts: Vec<&AccountView> = Vec::with_capacity(4 + settlement.len());
    cpi_accounts.push(payer);
    cpi_accounts.push(tree);
    cpi_accounts.push(ring_auth);
    for account in settlement {
        cpi_accounts.push(account);
    }
    cpi_accounts.push(spp_program);
    spp_zone_withdraw(spp_program, &cpi_accounts, spp_data, ring_auth_bump)
}
