use pinocchio::{AccountView, Address};
use zolana_interface::{
    state::discriminator::TREE_ACCOUNT_DISCRIMINATOR, SHIELDED_POOL_PROGRAM_ID,
};
use zolana_tree::TreeAccount;

use crate::error::CustomRingError;

pub struct TransactRoots {
    pub state: [u8; 32],
    pub nullifier: [u8; 32],
}

/// The borrow drops before the caller's SPP CPI, else SPP faults borrowing the
/// aliased money tree.
pub fn load_roots(
    tree_account: &mut AccountView,
    entries_tree: &Address,
    state_root_index: u16,
    nullifier_root_index: u16,
) -> Result<TransactRoots, CustomRingError> {
    if tree_account.address() != entries_tree {
        return Err(CustomRingError::InvalidEntriesTree);
    }
    let spp = Address::from(SHIELDED_POOL_PROGRAM_ID);
    if !tree_account.owned_by(&spp) {
        return Err(CustomRingError::InvalidEntriesTree);
    }
    let pubkey = tree_account.address().to_bytes();
    let mut data = tree_account
        .try_borrow_mut()
        .map_err(|_| CustomRingError::InvalidEntriesTree)?;
    if data.first() != Some(&TREE_ACCOUNT_DISCRIMINATOR) {
        return Err(CustomRingError::InvalidEntriesTree);
    }
    let tree = TreeAccount::from_bytes(&mut data, pubkey)
        .map_err(|_| CustomRingError::InvalidEntriesTree)?;
    if tree.is_paused() {
        return Err(CustomRingError::InvalidEntriesTree);
    }
    let state = tree
        .get_utxo_tree_root(state_root_index)
        .map_err(|_| CustomRingError::StalePolicyRoot)?;
    let nullifier = tree
        .get_nullifier_tree_root(nullifier_root_index)
        .map_err(|_| CustomRingError::StalePolicyRoot)?;
    Ok(TransactRoots { state, nullifier })
}
