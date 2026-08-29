use borsh::BorshDeserialize;
use pinocchio::{address::address_eq, error::ProgramError, AccountView, Address};
use zolana_interface::{
    error::ShieldedPoolError, NullifierPda, NULLIFIER_PDA_SEED, NULLIFIER_PDA_SIZE,
};

use crate::instructions::shared::verify_pda;

#[inline(never)]
pub(crate) fn load_unused_nullifier_pda(
    nullifier_pda: &AccountView,
    tree: &[u8; 32],
    nullifier: &[u8; 32],
) -> Result<u8, ProgramError> {
    if !nullifier_pda.is_writable() {
        return Err(ShieldedPoolError::InvalidNullifierPda.into());
    }
    let bump = verify_pda(
        nullifier_pda.address(),
        &[NULLIFIER_PDA_SEED, tree, nullifier],
        &crate::ID,
    )
    .map_err(|_| ShieldedPoolError::InvalidNullifierPda)?;
    if !pinocchio_system::check_id(nullifier_pda.owner()) || nullifier_pda.data_len() != 0 {
        return Err(ShieldedPoolError::NullifierAlreadyQueued.into());
    }
    Ok(bump)
}

#[inline(never)]
pub(crate) fn load_nullifier_pda(
    nullifier_pda: &AccountView,
    tree: &[u8; 32],
    nullifier: &[u8; 32],
) -> Result<NullifierPda, ProgramError> {
    if !nullifier_pda.is_writable()
        || !nullifier_pda.owned_by(&crate::ID)
        || nullifier_pda.data_len() != NULLIFIER_PDA_SIZE
    {
        return Err(ShieldedPoolError::InvalidNullifierPda.into());
    }
    let record = {
        let data = nullifier_pda
            .try_borrow()
            .map_err(|_| ShieldedPoolError::InvalidNullifierPda)?;
        NullifierPda::try_from_slice(&data).map_err(|_| ShieldedPoolError::InvalidNullifierPda)?
    };
    let expected = Address::derive_address(
        &[NULLIFIER_PDA_SEED, tree, nullifier],
        Some(record.bump),
        &crate::ID,
    );
    if !address_eq(nullifier_pda.address(), &expected) {
        return Err(ShieldedPoolError::InvalidNullifierPda.into());
    }
    Ok(record)
}
