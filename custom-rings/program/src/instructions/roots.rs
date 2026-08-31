use pinocchio::{AccountView, Address};
use zolana_batched_merkle_tree::constants::DEFAULT_ADDRESS_BATCH_ROOT_HISTORY_LEN;
use zolana_interface::{
    state::discriminator::TREE_ACCOUNT_DISCRIMINATOR, SHIELDED_POOL_PROGRAM_ID,
};
use zolana_tree::TreeAccount;

use crate::error::CustomRingError;

/// Staleness bound on the nullifier root, an older root still proves a retired
/// entry current.
pub const NULLIFIER_ROOT_WINDOW: u32 = 8;

pub struct TransactRoots {
    pub state: [u8; 32],
    pub nullifier: [u8; 32],
}

/// Any live state root is admissible, inclusion is monotone, while a nullifier
/// root older than [`NULLIFIER_ROOT_WINDOW`] misses a retirement the absence
/// proof must see.
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
    let cursor = tree.nullifer_tree().get_root_index();
    if !within_window(u32::from(nullifier_root_index), cursor) {
        return Err(CustomRingError::StalePolicyRoot);
    }
    Ok(TransactRoots { state, nullifier })
}

fn within_window(index: u32, cursor: u32) -> bool {
    let capacity = DEFAULT_ADDRESS_BATCH_ROOT_HISTORY_LEN;
    if index >= capacity || cursor >= capacity {
        return false;
    }
    (cursor + capacity - index) % capacity <= NULLIFIER_ROOT_WINDOW
}

#[cfg(test)]
mod tests {
    use super::*;

    const CAPACITY: u32 = DEFAULT_ADDRESS_BATCH_ROOT_HISTORY_LEN;

    #[test]
    fn the_window_admits_the_cursor_and_the_last_entries() {
        assert!(within_window(40, 40));
        assert!(within_window(40 - NULLIFIER_ROOT_WINDOW, 40));
        assert!(!within_window(40 - NULLIFIER_ROOT_WINDOW - 1, 40));
    }

    #[test]
    fn the_window_wraps_with_the_buffer() {
        assert!(within_window(CAPACITY - 1, 2));
        assert!(within_window(CAPACITY - NULLIFIER_ROOT_WINDOW + 1, 1));
        assert!(!within_window(CAPACITY / 2, 1));
    }

    #[test]
    fn an_index_past_the_history_is_refused() {
        assert!(!within_window(CAPACITY, 0));
        assert!(!within_window(0, CAPACITY));
    }
}
