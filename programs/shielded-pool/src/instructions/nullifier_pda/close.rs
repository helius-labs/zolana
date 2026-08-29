use pinocchio::{error::ProgramError, AccountView, ProgramResult};
use zolana_interface::error::ShieldedPoolError;

use super::loader::load_nullifier_pda;

#[inline(never)]
pub(crate) fn close_nullifier_pda(
    tree: &mut AccountView,
    nullifier_pda: &mut AccountView,
    nullifier: &[u8; 32],
    close_before_index: u64,
) -> ProgramResult {
    let tree_address = *tree.address().as_array();
    let record = load_nullifier_pda(nullifier_pda, &tree_address, nullifier)?;
    if !record.is_closable(close_before_index) {
        return Err(ShieldedPoolError::NullifierPdaNotClosable.into());
    }
    let tree_balance = tree
        .lamports()
        .checked_add(nullifier_pda.lamports())
        .ok_or(ProgramError::ArithmeticOverflow)?;
    tree.set_lamports(tree_balance);
    nullifier_pda.set_lamports(0);
    nullifier_pda.close()
}
