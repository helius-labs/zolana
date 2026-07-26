use pinocchio::error::ProgramError;
use zolana_interface::{
    error::ShieldedPoolError,
    instruction::instruction_data::transact::{PublicLeg, ResolvedPublicLeg, TransactIxDataRef},
    SOL_ASSET_FIELD,
};

use super::verify::TransactProofInputs;
use crate::instructions::{
    settlement::{settle_sol, settle_spl, Settlement},
    verifier,
};

// Settles each public leg and aggregates its asset into the number of public
// slots compiled into the selected circuit. Once assigned, a slot remains
// occupied by its first-seen asset even if its net amount returns to zero.
pub(crate) fn process_public_legs(
    public_legs: &[PublicLeg],
    settlements: &[Settlement<'_>],
    proof_inputs: &mut TransactProofInputs,
    num_public_asset_slots: usize,
) -> Result<(), ProgramError> {
    if public_legs.len() != settlements.len() {
        return Err(ShieldedPoolError::InvalidTransactShape.into());
    }

    let mut used_slots = 0usize;
    for (leg, settlement) in public_legs.iter().zip(settlements.iter()) {
        let amount = signed_amount(*leg);
        if amount == 0 {
            return Err(ShieldedPoolError::InvalidSettlementAccounts.into());
        }

        let asset = match (leg, settlement) {
            (PublicLeg::Sol { .. }, Settlement::Sol(sol)) => {
                settle_sol(sol, leg.amount(), leg.is_deposit())?;
                SOL_ASSET_FIELD
            }
            (PublicLeg::Spl { .. }, Settlement::Spl(spl)) => {
                settle_spl(spl, leg.amount())?;
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

fn signed_amount(leg: PublicLeg) -> i128 {
    let amount = i128::from(leg.amount());
    if leg.is_deposit() {
        amount
    } else {
        -amount
    }
}

pub(crate) fn resolve_public_legs(
    ix: &TransactIxDataRef<'_>,
    settlements: &[Settlement<'_>],
) -> Result<Vec<ResolvedPublicLeg>, ProgramError> {
    if ix.public_legs.len() != settlements.len() {
        return Err(ShieldedPoolError::InvalidTransactShape.into());
    }
    let mut resolved = Vec::with_capacity(ix.public_legs.len());
    for (leg, settlement) in ix.public_legs.iter().zip(settlements.iter()) {
        let public_leg = match (leg, settlement) {
            (
                PublicLeg::Sol {
                    is_deposit, amount, ..
                },
                Settlement::Sol(sol),
            ) => ResolvedPublicLeg::Sol {
                is_deposit: *is_deposit,
                amount: *amount,
                recipient: sol.recipient.address().to_bytes(),
            },
            (
                PublicLeg::Spl {
                    is_deposit, amount, ..
                },
                Settlement::Spl(spl),
            ) => ResolvedPublicLeg::Spl {
                is_deposit: *is_deposit,
                amount: *amount,
                user_token_account: spl.user_token_account.address().to_bytes(),
                vault: spl.vault.address().to_bytes(),
            },
            _ => return Err(ShieldedPoolError::InvalidSettlementAccounts.into()),
        };
        resolved.push(public_leg);
    }
    Ok(resolved)
}
