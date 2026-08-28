use borsh::BorshSerialize;
use light_program_profiler::profile;
use pinocchio::{
    cpi::{Seed, Signer},
    error::ProgramError,
    sysvars::{rent::Rent, Sysvar},
    AccountView, ProgramResult,
};
use pinocchio_system::instructions::{Allocate, Assign};
use zolana_interface::{
    error::ShieldedPoolError, event::Input, NullifierMarker, NULLIFIER_MARKER_SEED,
    NULLIFIER_MARKER_SIZE,
};

use super::loader::load_unused_nullifier_marker;

pub(crate) struct NullifierMarkerRent {
    marker_minimum: u64,
    tree_minimum: u64,
}

impl NullifierMarkerRent {
    fn missing(&self, marker: &AccountView) -> u64 {
        self.marker_minimum.saturating_sub(marker.lamports())
    }

    fn tree_remaining(&self, tree: &AccountView, amount: u64) -> Result<u64, ProgramError> {
        tree.lamports()
            .checked_sub(amount)
            .filter(|remaining| *remaining >= self.tree_minimum)
            .ok_or_else(|| ShieldedPoolError::InsufficientNullifierMarkerRent.into())
    }
}

#[inline(never)]
#[profile]
pub(crate) fn create_nullifier_markers(
    tree: &AccountView,
    markers: &mut [&mut AccountView],
    inputs: &[Input],
) -> Result<NullifierMarkerRent, ProgramError> {
    if markers.len() != inputs.len() {
        return Err(ShieldedPoolError::InvalidNullifierMarker.into());
    }
    let rent_sysvar = Rent::get()?;
    let rent = NullifierMarkerRent {
        marker_minimum: rent_sysvar.try_minimum_balance(NULLIFIER_MARKER_SIZE)?,
        tree_minimum: rent_sysvar.try_minimum_balance(tree.data_len())?,
    };
    let tree_address = *tree.address().as_array();
    let mut total_missing: u64 = 0;
    for (marker, input) in markers.iter_mut().zip(inputs) {
        create_nullifier_marker(marker, &tree_address, input)?;
        total_missing = total_missing
            .checked_add(rent.missing(marker))
            .ok_or(ProgramError::ArithmeticOverflow)?;
    }
    rent.tree_remaining(tree, total_missing)?;
    Ok(rent)
}

#[inline(never)]
fn create_nullifier_marker(
    marker: &mut AccountView,
    tree_address: &[u8; 32],
    input: &Input,
) -> ProgramResult {
    let bump = load_unused_nullifier_marker(marker, tree_address, &input.nullifier)?;
    let bump_seed = [bump];
    let seeds = [
        Seed::from(NULLIFIER_MARKER_SEED),
        Seed::from(tree_address.as_ref()),
        Seed::from(input.nullifier.as_ref()),
        Seed::from(bump_seed.as_ref()),
    ];
    Allocate {
        account: marker,
        space: NULLIFIER_MARKER_SIZE as u64,
    }
    .invoke_signed(&[Signer::from(&seeds)])?;
    Assign {
        account: marker,
        owner: &crate::ID,
    }
    .invoke_signed(&[Signer::from(&seeds)])?;

    let mut data = marker
        .try_borrow_mut()
        .map_err(|_| ShieldedPoolError::InvalidNullifierMarker)?;
    let mut writer: &mut [u8] = &mut data;
    NullifierMarker {
        queue_index: input.input_queue_seq,
        bump,
    }
    .serialize(&mut writer)
    .map_err(|_| ShieldedPoolError::InvalidNullifierMarker.into())
}

#[inline(never)]
#[profile]
pub(crate) fn fund_nullifier_markers(
    tree: &mut AccountView,
    markers: &mut [&mut AccountView],
    rent: &NullifierMarkerRent,
) -> ProgramResult {
    for marker in markers.iter_mut() {
        let missing = rent.missing(marker);
        if missing == 0 {
            continue;
        }
        let tree_remaining = rent.tree_remaining(tree, missing)?;
        let marker_balance = marker
            .lamports()
            .checked_add(missing)
            .ok_or(ProgramError::ArithmeticOverflow)?;
        tree.set_lamports(tree_remaining);
        marker.set_lamports(marker_balance);
    }
    Ok(())
}
