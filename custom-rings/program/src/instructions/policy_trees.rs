use pinocchio::{error::ProgramError, Address, ProgramResult};
use zolana_account_checks::AccountIterator;
use zolana_interface::{
    instruction::instruction_data::transact::TreeContext,
    state::NULLIFIER_TREE_ROOT_HISTORY_CAPACITY, tree_slot::TreeSlot, INPUT_TREES,
    NULLIFIER_PDA_SEED, SHIELDED_POOL_PROGRAM_ID,
};
use zolana_ring_policy::ANSWER_SLOTS;

use crate::{
    error::CustomRingError,
    instructions::{loader::load_policy_tree_slot, shared::PdaCheck},
};

/// Liveness bound only, the revocation target PDA check keeps older roots sound.
pub const NULLIFIER_ROOT_WINDOW: u32 = 8;
const _: () = assert!(NULLIFIER_ROOT_WINDOW < NULLIFIER_TREE_ROOT_HISTORY_CAPACITY);

/// Distinct SPP trees a policy statement reads list facts from, in slot order.
pub(crate) struct PolicyTrees {
    addresses: Vec<Address>,
    slots: Vec<TreeSlot>,
}

impl PolicyTrees {
    pub fn load(
        accounts: &mut AccountIterator<'_>,
        contexts: &[TreeContext],
    ) -> Result<Self, ProgramError> {
        if !(1..=INPUT_TREES).contains(&contexts.len()) {
            return Err(CustomRingError::InvalidPolicyTrees.into());
        }
        let mut trees = Self {
            addresses: Vec::with_capacity(contexts.len()),
            slots: Vec::with_capacity(contexts.len()),
        };
        for context in contexts {
            let account = accounts.next_account("policy_tree")?;
            if trees.addresses.contains(account.address()) {
                return Err(CustomRingError::InvalidPolicyTrees.into());
            }
            trees.slots.push(load_policy_tree_slot(account, context)?);
            trees.addresses.push(*account.address());
        }
        Ok(trees)
    }

    pub fn slots(&self) -> &[TreeSlot] {
        &self.slots
    }
}

pub(crate) struct RevocationTargets<'a> {
    pub targets: &'a [[u8; 32]; ANSWER_SLOTS],
    pub tree_indexes: &'a [u8; ANSWER_SLOTS],
}

impl RevocationTargets<'_> {
    /// Each nonzero target's nullifier PDA under its tree must still be empty.
    pub fn verify(self, trees: &PolicyTrees, accounts: &mut AccountIterator<'_>) -> ProgramResult {
        let spp = Address::from(SHIELDED_POOL_PROGRAM_ID);
        for (target, &index) in self.targets.iter().zip(self.tree_indexes) {
            if *target == [0u8; 32] {
                if index != 0 {
                    return Err(CustomRingError::InvalidRevocationTreeIndex.into());
                }
                continue;
            }
            let tree = trees
                .addresses
                .get(usize::from(index))
                .ok_or(CustomRingError::InvalidRevocationTreeIndex)?;
            let account = accounts.next_account("revocation_target")?;
            PdaCheck {
                program_id: &spp,
                address: account.address(),
                seeds: &[NULLIFIER_PDA_SEED, tree.as_array(), target],
                mismatch: CustomRingError::InvalidRevocationTarget,
            }
            .verify()?;
            if !pinocchio_system::check_id(account.owner()) || account.data_len() != 0 {
                return Err(CustomRingError::PolicyFactRevoked.into());
            }
        }
        Ok(())
    }

    /// An audit-only statement reads no facts.
    pub fn require_empty(self) -> ProgramResult {
        if self.targets.iter().any(|target| *target != [0u8; 32]) {
            return Err(CustomRingError::InvalidInstructionData.into());
        }
        if self.tree_indexes.iter().any(|index| *index != 0) {
            return Err(CustomRingError::InvalidRevocationTreeIndex.into());
        }
        Ok(())
    }
}

pub(crate) fn within_window(index: u32, cursor: u32) -> bool {
    let capacity = NULLIFIER_TREE_ROOT_HISTORY_CAPACITY;
    if index >= capacity || cursor >= capacity {
        return false;
    }
    (cursor + capacity - index) % capacity <= NULLIFIER_ROOT_WINDOW
}

#[cfg(test)]
mod tests {
    use super::*;

    const CAPACITY: u32 = NULLIFIER_TREE_ROOT_HISTORY_CAPACITY;

    #[test]
    fn the_window_admits_the_cursor_and_the_last_entries() {
        assert!(within_window(40, 40));
        assert!(within_window(40 - NULLIFIER_ROOT_WINDOW, 40));
        assert!(!within_window(40 - NULLIFIER_ROOT_WINDOW - 1, 40));
        assert!(!within_window(41, 40));
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
