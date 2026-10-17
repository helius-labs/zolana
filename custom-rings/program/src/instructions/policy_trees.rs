use custom_ring_interface::CustomRingError;
use pinocchio::{error::ProgramError, Address};
use zolana_account_checks::AccountIterator;
use zolana_interface::{
    instruction::instruction_data::transact::TreeContext, tree_slot::TreeSlot, INPUT_TREES,
};

use crate::instructions::loader::load_policy_tree_slot;

/// Distinct SPP trees a policy statement binds, in slot order.
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
