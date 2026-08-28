use borsh::BorshDeserialize;
use pinocchio::{address::address_eq, error::ProgramError, AccountView, Address};
use zolana_interface::{
    error::ShieldedPoolError, NullifierMarker, NULLIFIER_MARKER_SEED, NULLIFIER_MARKER_SIZE,
};

use crate::instructions::shared::verify_pda;

#[inline(never)]
pub(crate) fn load_unused_nullifier_marker(
    marker: &AccountView,
    tree: &[u8; 32],
    nullifier: &[u8; 32],
) -> Result<u8, ProgramError> {
    if !marker.is_writable() {
        return Err(ShieldedPoolError::InvalidNullifierMarker.into());
    }
    let bump = verify_pda(
        marker.address(),
        &[NULLIFIER_MARKER_SEED, tree, nullifier],
        &crate::ID,
    )
    .map_err(|_| ShieldedPoolError::InvalidNullifierMarker)?;
    if !pinocchio_system::check_id(marker.owner()) || marker.data_len() != 0 {
        return Err(ShieldedPoolError::NullifierAlreadyQueued.into());
    }
    Ok(bump)
}

#[inline(never)]
pub(crate) fn load_nullifier_marker(
    marker: &AccountView,
    tree: &[u8; 32],
    nullifier: &[u8; 32],
) -> Result<NullifierMarker, ProgramError> {
    if !marker.is_writable()
        || !marker.owned_by(&crate::ID)
        || marker.data_len() != NULLIFIER_MARKER_SIZE
    {
        return Err(ShieldedPoolError::InvalidNullifierMarker.into());
    }
    let record = {
        let data = marker
            .try_borrow()
            .map_err(|_| ShieldedPoolError::InvalidNullifierMarker)?;
        NullifierMarker::try_from_slice(&data)
            .map_err(|_| ShieldedPoolError::InvalidNullifierMarker)?
    };
    let expected = Address::derive_address(
        &[NULLIFIER_MARKER_SEED, tree, nullifier],
        Some(record.bump),
        &crate::ID,
    );
    if !address_eq(marker.address(), &expected) {
        return Err(ShieldedPoolError::InvalidNullifierMarker.into());
    }
    Ok(record)
}
