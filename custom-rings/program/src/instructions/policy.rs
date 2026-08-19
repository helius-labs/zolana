//! Policy enforcement on the forwarded SPP instructions. The checks read only
//! the instruction data and account addresses SPP itself validates afterwards,
//! so a rejection here is a named error where SPP would still have accepted the
//! transfer.

use pinocchio::{error::ProgramError, AccountView, ProgramResult};
use wincode::{
    config::{Configuration, DEFAULT_PREALLOCATION_SIZE_LIMIT},
    containers,
    len::FixIntLen,
    SchemaRead,
};
use zolana_interface::instruction::{DepositAssetKind, InterfaceTransfer};

use crate::{
    error::CustomRingError,
    state::{AssetPolicy, RingProgramConfig, WithdrawalRule, SOL_MINT},
};

/// Accounts of SPP's `RING_DEPOSIT` before the per-asset settlement groups:
/// `[tree, depositor, ring_config, spp_program]`.
const DEPOSIT_PREFIX: usize = 4;
/// Accounts of SPP's `RING_TRANSACT` before the owner signers:
/// `[payer, input_tree, output_tree, spp_program, system_program, ring_config]`.
const TRANSACT_PREFIX: usize = 6;

/// The wincode configuration SPP's `RingDepositIxData` is encoded with.
type DepositConfig = Configuration<true, DEFAULT_PREALLOCATION_SIZE_LIMIT, FixIntLen<u16>>;

/// The leading field of `RingDepositIxData`. Reading only this leaves the
/// entries with their ciphertexts unparsed.
#[derive(SchemaRead)]
struct DepositAssets {
    #[wincode(with = "containers::Vec<DepositAssetKind, FixIntLen<u8>>")]
    assets: Vec<DepositAssetKind>,
}

/// A settlement leg as the policy sees it. Which mint, which way, and how many
/// accounts its group takes in SPP's layout.
struct Leg {
    mint: [u8; 32],
    direction: Direction,
    width: usize,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Direction {
    Into,
    OutOf,
}

/// `spp_accounts` and `data` are the forwarded ring deposit, `data` still
/// carrying SPP's tag byte. Every deposited mint must pass the allowlist.
pub fn check_deposit(
    config: &RingProgramConfig,
    spp_accounts: &[AccountView],
    data: &[u8],
) -> ProgramResult {
    if config.asset_policy() == AssetPolicy::Any {
        return Ok(());
    }
    let body = data
        .get(1..)
        .ok_or(CustomRingError::InvalidInstructionData)?;
    let DepositAssets { assets } = wincode::config::deserialize(body, DepositConfig::new())
        .map_err(|_| CustomRingError::InvalidInstructionData)?;
    let mut groups = spp_accounts
        .get(DEPOSIT_PREFIX..)
        .ok_or(CustomRingError::InvalidInstructionData)?;
    for kind in &assets {
        // Group shapes follow SPP's deposit loader. SOL reads `[system_program,
        // sol_interface]`, SPL reads `[token_program, mint, user_token,
        // spl_interface]`.
        let (mint, width) = match kind {
            DepositAssetKind::Sol => (SOL_MINT, 2),
            DepositAssetKind::Spl { .. } => (mint_at(groups, 1)?, 4),
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

/// `spp_accounts` is the forwarded ring transact list. Every settlement leg's
/// mint must pass the allowlist, and its withdrawal rule decides whether a
/// withdrawal is forwarded, refused, or needs an approval account. Returns
/// whether the transact must carry an approval.
pub fn check_transact(
    config: &RingProgramConfig,
    spp_accounts: &[AccountView],
    interface_transfers: &[InterfaceTransfer],
) -> Result<bool, ProgramError> {
    if interface_transfers.is_empty() {
        return Ok(false);
    }
    // Owner signers follow the fixed prefix and the settlement groups start at
    // the first non-signer, in `interface_transfers` order. Every group opens
    // with a non-signer (`mint` or `sol_interface`), so the boundary is exact.
    let after_prefix = spp_accounts
        .get(TRANSACT_PREFIX..)
        .ok_or(CustomRingError::InvalidInstructionData)?;
    let signer_count = after_prefix
        .iter()
        .position(|account| !account.is_signer())
        .unwrap_or(after_prefix.len());
    let mut groups = &after_prefix[signer_count..];
    let mut needs_approval = false;
    for transfer in interface_transfers {
        let leg = leg(transfer, groups)?;
        if !config.allows_asset(&leg.mint) {
            return Err(CustomRingError::AssetNotAllowed.into());
        }
        if leg.direction == Direction::OutOf {
            match config.withdrawal_rule(&leg.mint) {
                WithdrawalRule::Open => {}
                WithdrawalRule::Blocked => return Err(CustomRingError::WithdrawalsBlocked.into()),
                WithdrawalRule::Approval => needs_approval = true,
            }
        }
        groups = groups
            .get(leg.width..)
            .ok_or(CustomRingError::InvalidInstructionData)?;
    }
    Ok(needs_approval)
}

/// Group shapes follow SPP's transact loader. SPL deposit `[mint,
/// spl_interface, token_authority, user_token, token_program]`, SPL withdrawal
/// `[mint, spl_interface, user_token, token_program]`, SOL `[sol_interface,
/// recipient]`.
fn leg(transfer: &InterfaceTransfer, group: &[AccountView]) -> Result<Leg, CustomRingError> {
    Ok(match transfer {
        InterfaceTransfer::SplDeposit { .. } => Leg {
            mint: mint_at(group, 0)?,
            direction: Direction::Into,
            width: 5,
        },
        InterfaceTransfer::SplWithdrawal { .. } => Leg {
            mint: mint_at(group, 0)?,
            direction: Direction::OutOf,
            width: 4,
        },
        InterfaceTransfer::SolDeposit { .. } => Leg {
            mint: SOL_MINT,
            direction: Direction::Into,
            width: 2,
        },
        InterfaceTransfer::SolWithdrawal { .. } => Leg {
            mint: SOL_MINT,
            direction: Direction::OutOf,
            width: 2,
        },
    })
}

fn mint_at(group: &[AccountView], index: usize) -> Result<[u8; 32], CustomRingError> {
    group
        .get(index)
        .map(|mint| *mint.address().as_array())
        .ok_or(CustomRingError::InvalidInstructionData)
}
