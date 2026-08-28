use pinocchio::{error::ProgramError, AccountView, ProgramResult};
use zolana_interface::error::ShieldedPoolError;

use super::loader::load_nullifier_marker;

#[inline(never)]
pub(crate) fn close_nullifier_marker(
    tree: &mut AccountView,
    marker: &mut AccountView,
    nullifier: &[u8; 32],
    close_before_index: u64,
) -> ProgramResult {
    let tree_address = *tree.address().as_array();
    let record = load_nullifier_marker(marker, &tree_address, nullifier)?;
    if !record.is_closable(close_before_index) {
        return Err(ShieldedPoolError::NullifierMarkerNotClosable.into());
    }
    let tree_balance = tree
        .lamports()
        .checked_add(marker.lamports())
        .ok_or(ProgramError::ArithmeticOverflow)?;
    tree.set_lamports(tree_balance);
    marker.set_lamports(0);
    marker.close()
}
