use pinocchio::error::ProgramError;
use zolana_interface::{
    error::ShieldedPoolError,
    instruction::instruction_data::transact::{
        InterfaceTransfer, ResolvedInterfaceTransfer, TransactIxDataRef,
    },
    SOL_ASSET_FIELD,
};

use super::verify::TransactProofInputs;
use crate::instructions::{
    settlement::{settle_sol, settle_spl_deposit, settle_spl_withdrawal, Settlement},
    verifier,
};

// Settles each interface transfer and aggregates its asset into the number of public
// slots compiled into the selected circuit. Once assigned, a slot remains
// occupied by its first-seen asset even if its net amount returns to zero.
pub(crate) fn process_interface_transfers(
    interface_transfers: &[InterfaceTransfer],
    settlements: &[Settlement<'_>],
    proof_inputs: &mut TransactProofInputs,
    num_public_asset_slots: usize,
) -> Result<(), ProgramError> {
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
                Settlement::Sol(sol),
            ) => {
                settle_sol(sol, transfer.amount(), transfer.is_deposit())?;
                SOL_ASSET_FIELD
            }
            (InterfaceTransfer::SplDeposit { .. }, Settlement::SplDeposit(spl)) => {
                settle_spl_deposit(spl, transfer.amount())?;
                verifier::hash_field(
                    &spl.mint,
                    ShieldedPoolError::TransactProofVerificationFailed,
                )?
            }
            (InterfaceTransfer::SplWithdrawal { .. }, Settlement::SplWithdrawal(spl)) => {
                settle_spl_withdrawal(spl, transfer.amount())?;
                verifier::hash_field(
                    &spl.mint,
                    ShieldedPoolError::TransactProofVerificationFailed,
                )?
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
) -> Result<Vec<ResolvedInterfaceTransfer>, ProgramError> {
    if ix.interface_transfers.len() != settlements.len() {
        return Err(ShieldedPoolError::InvalidTransactShape.into());
    }
    let mut resolved = Vec::with_capacity(ix.interface_transfers.len());
    for (transfer, settlement) in ix.interface_transfers.iter().zip(settlements.iter()) {
        let resolved_transfer = match (transfer, settlement) {
            (InterfaceTransfer::SolDeposit { amount }, Settlement::Sol(sol)) => {
                ResolvedInterfaceTransfer::SolDeposit {
                    amount: *amount,
                    recipient: sol.recipient.address().to_bytes(),
                }
            }
            (InterfaceTransfer::SolWithdrawal { amount }, Settlement::Sol(sol)) => {
                ResolvedInterfaceTransfer::SolWithdrawal {
                    amount: *amount,
                    recipient: sol.recipient.address().to_bytes(),
                }
            }
            (InterfaceTransfer::SplDeposit { amount, .. }, Settlement::SplDeposit(spl)) => {
                ResolvedInterfaceTransfer::SplDeposit {
                    amount: *amount,
                    user_token_account: spl.user_token_account.address().to_bytes(),
                    vault: spl.vault.address().to_bytes(),
                }
            }
            (InterfaceTransfer::SplWithdrawal { amount, .. }, Settlement::SplWithdrawal(spl)) => {
                ResolvedInterfaceTransfer::SplWithdrawal {
                    amount: *amount,
                    user_token_account: spl.user_token_account.address().to_bytes(),
                    vault: spl.vault.address().to_bytes(),
                }
            }
            _ => return Err(ShieldedPoolError::InvalidSettlementAccounts.into()),
        };
        resolved.push(resolved_transfer);
    }
    Ok(resolved)
}
