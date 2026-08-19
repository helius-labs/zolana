//! Policy enforcement on the forwarded SPP instructions. The checks read only
//! the instruction data and account addresses SPP itself validates afterwards,
//! so a rejection here is a named error where SPP would still have accepted the
//! transfer.

use pinocchio::{AccountView, ProgramResult};
use zolana_interface::instruction::{DepositAssetKind, InterfaceTransfer, RingDepositIxDataRef};

use crate::{
    error::CustomRingError,
    state::{RingProgramConfig, SOL_MINT},
};

/// Accounts of SPP's `RING_DEPOSIT` before the per-asset settlement groups:
/// `[tree, depositor, ring_config, spp_program]`.
const DEPOSIT_PREFIX: usize = 4;
/// Accounts of SPP's `RING_TRANSACT` before the owner signers:
/// `[payer, input_tree, output_tree, spp_program, system_program, ring_config]`.
const TRANSACT_PREFIX: usize = 6;

/// `spp_accounts` and `data` are the forwarded ring deposit; `data` still
/// carries SPP's tag byte. Every deposited mint must pass the allowlist.
pub fn check_deposit(
    config: &RingProgramConfig,
    spp_accounts: &[AccountView],
    data: &[u8],
) -> ProgramResult {
    if config.allows_every_asset() {
        return Ok(());
    }
    let body = data
        .get(1..)
        .ok_or(CustomRingError::InvalidInstructionData)?;
    let deposit = RingDepositIxDataRef::from_bytes(body)
        .map_err(|_| CustomRingError::InvalidInstructionData)?;
    let mut groups = spp_accounts
        .get(DEPOSIT_PREFIX..)
        .ok_or(CustomRingError::InvalidInstructionData)?;
    for kind in &deposit.assets {
        // Group shapes follow SPP's deposit loader: SOL reads `[system_program,
        // sol_interface]`, SPL reads `[token_program, mint, user_token,
        // spl_interface]`.
        let (mint, width) = match kind {
            DepositAssetKind::Sol => (SOL_MINT, 2),
            DepositAssetKind::Spl { .. } => (
                *groups
                    .get(1)
                    .ok_or(CustomRingError::InvalidInstructionData)?
                    .address()
                    .as_array(),
                4,
            ),
        };
        if !config.allows_asset(&mint) {
            return Err(CustomRingError::AssetNotAllowed.into());
        }
        groups = groups
            .get(width..)
            .ok_or(CustomRingError::InvalidInstructionData)?;
    }
    Ok(())
}

/// `spp_accounts` is the forwarded ring transact list. Public withdrawals are
/// refused when blocked, and every settlement leg's mint must pass the
/// allowlist.
pub fn check_transact(
    config: &RingProgramConfig,
    spp_accounts: &[AccountView],
    interface_transfers: &[InterfaceTransfer],
) -> ProgramResult {
    if config.withdrawals_blocked()
        && interface_transfers.iter().any(|transfer| {
            matches!(
                transfer,
                InterfaceTransfer::SolWithdrawal { .. } | InterfaceTransfer::SplWithdrawal { .. }
            )
        })
    {
        return Err(CustomRingError::WithdrawalsBlocked.into());
    }
    if config.allows_every_asset() || interface_transfers.is_empty() {
        return Ok(());
    }
    // Owner signers follow the fixed prefix; the settlement groups start at
    // the first non-signer, in `interface_transfers` order.
    let after_prefix = spp_accounts
        .get(TRANSACT_PREFIX..)
        .ok_or(CustomRingError::InvalidInstructionData)?;
    let signer_count = after_prefix
        .iter()
        .position(|account| !account.is_signer())
        .unwrap_or(after_prefix.len());
    let mut groups = &after_prefix[signer_count..];
    for transfer in interface_transfers {
        // Group shapes follow SPP's transact loader: SPL deposit `[mint,
        // spl_interface, token_authority, user_token, token_program]`, SPL
        // withdrawal `[mint, spl_interface, user_token, token_program]`, SOL
        // `[sol_interface, recipient]`.
        let (mint, width) = match transfer {
            InterfaceTransfer::SplDeposit { .. } => (spl_mint(groups)?, 5),
            InterfaceTransfer::SplWithdrawal { .. } => (spl_mint(groups)?, 4),
            InterfaceTransfer::SolDeposit { .. } | InterfaceTransfer::SolWithdrawal { .. } => {
                (SOL_MINT, 2)
            }
        };
        if !config.allows_asset(&mint) {
            return Err(CustomRingError::AssetNotAllowed.into());
        }
        groups = groups
            .get(width..)
            .ok_or(CustomRingError::InvalidInstructionData)?;
    }
    Ok(())
}

fn spl_mint(group: &[AccountView]) -> Result<[u8; 32], CustomRingError> {
    group
        .first()
        .map(|mint| *mint.address().as_array())
        .ok_or(CustomRingError::InvalidInstructionData)
}
