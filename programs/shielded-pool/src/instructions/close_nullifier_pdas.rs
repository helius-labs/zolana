use pinocchio::{AccountView, ProgramResult};
use zolana_account_checks::AccountIterator;
use zolana_interface::{
    error::ShieldedPoolError, state::discriminator::TREE_ACCOUNT_DISCRIMINATOR,
};
use zolana_tree::TreeAccount;

use crate::instructions::{nullifier_pda::NullifierPdaClose, shared::tree_error};

#[inline(never)]
pub fn process_close_nullifier_pdas(accounts: &mut [AccountView], data: &[u8]) -> ProgramResult {
    if !data.is_empty() {
        return Err(ShieldedPoolError::InvalidInstructionData.into());
    }
    let mut iter = AccountIterator::new(accounts);
    let tree = iter.next_mut("tree")?;
    let close = {
        let tree_account =
            TreeAccount::from_account_view_mut(&mut *tree, &crate::ID, TREE_ACCOUNT_DISCRIMINATOR)
                .map_err(tree_error)?;
        NullifierPdaClose {
            tree_id: tree_account.tree_id(),
            close_before_index: tree_account.close_before_index(),
        }
    };
    if iter.iterator_is_empty() {
        return Err(ShieldedPoolError::InvalidInstructionData.into());
    }
    while !iter.iterator_is_empty() {
        let nullifier_pda = iter.next_mut("nullifier_pda")?;
        close.close(tree, nullifier_pda)?;
    }
    Ok(())
}
