use pinocchio::{error::ProgramError, ProgramResult};
use zolana_hasher::primitives::hash_bytes;
use zolana_interface::{
    error::ShieldedPoolError,
    instruction::instruction_data::transact::{
        InterfaceTransfer, ResolvedInterfaceTransfer, TransactIxDataRef,
    },
    SOL_ASSET_FIELD,
};

use super::verify::TransactProofInputs;
use crate::instructions::settlement::{
    settle_sol, settle_spl_deposit, settle_spl_withdrawal, Settlement,
};

// Aggregates each interface transfer into the number of public slots compiled
// into the selected circuit. Once assigned, a slot remains occupied by its
// first-seen asset even if its net amount returns to zero.
pub(crate) fn process_interface_transfers(
    interface_transfers: &[InterfaceTransfer],
    settlements: &[Settlement<'_>],
    proof_inputs: &mut TransactProofInputs,
    num_public_asset_slots: usize,
) -> Result<(), ProgramError> {
    // `TransactAccounts::from_iter` builds one matching settlement per transfer.
    // Validate the length once at the first consumer; the match below validates
    // each pair's variant, establishing the invariant used by resolve/settle.
    if interface_transfers.len() != settlements.len() {
        return Err(ShieldedPoolError::InvalidTransactShape.into());
    }

    let mut used_slots = 0usize;
    for (transfer, settlement) in interface_transfers.iter().zip(settlements.iter()) {
        let amount = signed_amount(*transfer);
        if amount == 0 {
            return Err(ShieldedPoolError::InvalidSettlementAccounts.into());
        }

        let asset = match (transfer, settlement) {
            (
                InterfaceTransfer::SolDeposit { .. } | InterfaceTransfer::SolWithdrawal { .. },
                Settlement::Sol(_),
            ) => SOL_ASSET_FIELD,
            (InterfaceTransfer::SplDeposit { .. }, Settlement::SplDeposit(spl)) => {
                hash_bytes(&spl.mint_account.address().to_bytes())
                    .map_err(|_| ShieldedPoolError::TransactProofVerificationFailed)?
            }
            (InterfaceTransfer::SplWithdrawal { .. }, Settlement::SplWithdrawal(spl)) => {
                hash_bytes(&spl.mint_account.address().to_bytes())
                    .map_err(|_| ShieldedPoolError::TransactProofVerificationFailed)?
            }
            _ => return Err(ShieldedPoolError::InvalidSettlementAccounts.into()),
        };
        match proof_inputs.public_slot_assets[..used_slots]
            .iter()
            .position(|slot_asset| *slot_asset == asset)
        {
            Some(i) => {
                let net = proof_inputs.public_slot_amounts[i]
                    .checked_add(amount)
                    .ok_or(ShieldedPoolError::PublicAssetAmountOverflow)?;
                proof_inputs.public_slot_amounts[i] = checked_slot_amount(net)?;
            }
            None => {
                if used_slots == num_public_asset_slots {
                    return Err(ShieldedPoolError::TooManyPublicAssets.into());
                }
                proof_inputs.public_slot_assets[used_slots] = asset;
                proof_inputs.public_slot_amounts[used_slots] = checked_slot_amount(amount)?;
                used_slots += 1;
            }
        }
    }
    Ok(())
}

/// Applies public settlement only after the proof that authorizes it has
/// verified, so invalid proofs cannot trigger CPIs or mask verification errors.
pub(crate) fn settle_interface_transfers(
    interface_transfers: &[InterfaceTransfer],
    settlements: &[Settlement<'_>],
) -> ProgramResult {
    for (transfer, settlement) in interface_transfers.iter().zip(settlements.iter()) {
        match settlement {
            Settlement::Sol(sol) => settle_sol(sol, transfer.amount(), transfer.is_deposit())?,
            Settlement::SplDeposit(spl) => settle_spl_deposit(spl, transfer.amount())?,
            Settlement::SplWithdrawal(spl) => settle_spl_withdrawal(spl, transfer.amount())?,
        }
    }

    Ok(())
}

// Slot magnitudes are u64 wires; reject nets that exceed them.
fn checked_slot_amount(net: i128) -> Result<i128, ProgramError> {
    if u64::try_from(net.unsigned_abs()).is_err() {
        return Err(ShieldedPoolError::PublicAssetAmountOverflow.into());
    }
    Ok(net)
}

fn signed_amount(transfer: InterfaceTransfer) -> i128 {
    let amount = i128::from(transfer.amount());
    if transfer.is_deposit() {
        amount
    } else {
        -amount
    }
}

pub(crate) fn resolve_interface_transfers(
    ix: &TransactIxDataRef<'_>,
    settlements: &[Settlement<'_>],
) -> Vec<ResolvedInterfaceTransfer> {
    let mut resolved = Vec::with_capacity(ix.interface_transfers.len());
    for (transfer, settlement) in ix.interface_transfers.iter().zip(settlements.iter()) {
        let amount = transfer.amount();
        let resolved_transfer = match settlement {
            Settlement::Sol(sol) if transfer.is_deposit() => {
                ResolvedInterfaceTransfer::SolDeposit {
                    amount,
                    recipient: sol.recipient.address().to_bytes(),
                }
            }
            Settlement::Sol(sol) => ResolvedInterfaceTransfer::SolWithdrawal {
                amount,
                recipient: sol.recipient.address().to_bytes(),
            },
            Settlement::SplDeposit(spl) => ResolvedInterfaceTransfer::SplDeposit {
                amount,
                user_token_account: spl.user_token_account.address().to_bytes(),
                vault: spl.vault.address().to_bytes(),
            },
            Settlement::SplWithdrawal(spl) => ResolvedInterfaceTransfer::SplWithdrawal {
                amount,
                user_token_account: spl.user_token_account.address().to_bytes(),
                vault: spl.vault.address().to_bytes(),
            },
        };
        resolved.push(resolved_transfer);
    }
    resolved
}
