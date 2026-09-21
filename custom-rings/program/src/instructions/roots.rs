use pinocchio::{AccountView, Address};
use zolana_interface::{
    state::{discriminator::TREE_ACCOUNT_DISCRIMINATOR, NULLIFIER_TREE_ROOT_HISTORY_CAPACITY},
    SHIELDED_POOL_PROGRAM_ID,
};
use zolana_tree::TreeAccount;

use crate::error::CustomRingError;

/// Absence proofs bind the current nullifier root.
pub const NULLIFIER_ROOT_WINDOW: u32 = 0;

pub struct TransactRoots {
    pub state: [u8; 32],
    pub nullifier: [u8; 32],
}

/// Historical nullifier roots invalidate absence proofs.
///
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
    let mut tree = TreeAccount::from_bytes(&mut data, pubkey)
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
    let cursor = tree.nullifier_tree().get_root_index();
    if !within_window(u32::from(nullifier_root_index), cursor) {
        return Err(CustomRingError::StalePolicyRoot);
    }
    Ok(TransactRoots { state, nullifier })
}

fn within_window(index: u32, cursor: u32) -> bool {
    let capacity = NULLIFIER_TREE_ROOT_HISTORY_CAPACITY;
    if index >= capacity || cursor >= capacity {
        return false;
    }
    index == cursor
}

#[cfg(test)]
mod tests {
    use super::*;

    const CAPACITY: u32 = NULLIFIER_TREE_ROOT_HISTORY_CAPACITY;

    #[test]
    fn only_the_current_root_is_admitted() {
        assert!(within_window(40, 40));
        assert!(!within_window(39, 40));
        assert!(!within_window(41, 40));
    }

    #[test]
    fn a_wrapped_history_index_is_stale() {
        assert!(!within_window(CAPACITY - 1, 2));
        assert!(!within_window(CAPACITY - 1, 1));
        assert!(!within_window(CAPACITY / 2, 1));
    }

    #[test]
    fn an_index_past_the_history_is_refused() {
        assert!(!within_window(CAPACITY, 0));
        assert!(!within_window(0, CAPACITY));
    }
}
