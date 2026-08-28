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

struct MarkerRent {
    marker_minimum: u64,
    tree_minimum: u64,
}

#[inline(never)]
#[profile]
pub(crate) fn create_nullifier_markers(
    tree: &mut AccountView,
    markers: &mut [&mut AccountView],
    inputs: &[Input],
) -> ProgramResult {
    if markers.len() != inputs.len() {
        return Err(ShieldedPoolError::InvalidNullifierMarker.into());
    }
    let rent = Rent::get()?;
    let marker_rent = MarkerRent {
        marker_minimum: rent.try_minimum_balance(NULLIFIER_MARKER_SIZE)?,
        tree_minimum: rent.try_minimum_balance(tree.data_len())?,
    };
    let tree_address = *tree.address().as_array();
    for (marker, input) in markers.iter_mut().zip(inputs) {
        create_nullifier_marker(tree, marker, &tree_address, input, &marker_rent)?;
    }
    Ok(())
}

#[inline(never)]
fn create_nullifier_marker(
    tree: &mut AccountView,
    marker: &mut AccountView,
    tree_address: &[u8; 32],
    input: &Input,
    rent: &MarkerRent,
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

    {
        let mut data = marker
            .try_borrow_mut()
            .map_err(|_| ShieldedPoolError::InvalidNullifierMarker)?;
        let mut writer: &mut [u8] = &mut data;
        NullifierMarker {
            queue_index: input.input_queue_seq,
            bump,
        }
        .serialize(&mut writer)
        .map_err(|_| ShieldedPoolError::InvalidNullifierMarker)?;
    }

    let missing = rent.marker_minimum.saturating_sub(marker.lamports());
    if missing == 0 {
        return Ok(());
    }
    let tree_remaining = tree
        .lamports()
        .checked_sub(missing)
        .filter(|remaining| *remaining >= rent.tree_minimum)
        .ok_or(ShieldedPoolError::InsufficientNullifierMarkerRent)?;
    let marker_balance = marker
        .lamports()
        .checked_add(missing)
        .ok_or(ProgramError::ArithmeticOverflow)?;
    tree.set_lamports(tree_remaining);
    marker.set_lamports(marker_balance);
    Ok(())
}
