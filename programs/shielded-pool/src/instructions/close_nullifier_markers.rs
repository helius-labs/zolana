use borsh::BorshDeserialize;
use pinocchio::{AccountView, ProgramResult};
use zolana_account_checks::AccountIterator;
use zolana_interface::{
    error::ShieldedPoolError, instruction::CloseNullifierMarkersData,
    state::discriminator::TREE_ACCOUNT_DISCRIMINATOR,
};
use zolana_tree::TreeAccount;

use crate::instructions::{nullifier_marker::close_nullifier_marker, shared::tree_error};

#[inline(never)]
pub fn process_close_nullifier_markers(accounts: &mut [AccountView], data: &[u8]) -> ProgramResult {
    let instruction = CloseNullifierMarkersData::try_from_slice(data)
        .map_err(|_| ShieldedPoolError::InvalidInstructionData)?;
    if instruction.nullifiers.is_empty() {
        return Err(ShieldedPoolError::InvalidInstructionData.into());
    }
    let mut iter = AccountIterator::new(accounts);
    let tree = iter.next_mut("tree")?;
    let close_before_index =
        TreeAccount::from_account_view_mut(&mut *tree, &crate::ID, TREE_ACCOUNT_DISCRIMINATOR)
            .map_err(tree_error)?
            .close_before_index();
    for nullifier in &instruction.nullifiers {
        let marker = iter.next_mut("nullifier_marker")?;
        close_nullifier_marker(tree, marker, nullifier, close_before_index)?;
    }
    if !iter.iterator_is_empty() {
        return Err(ShieldedPoolError::InvalidInstructionData.into());
    }
    Ok(())
}
