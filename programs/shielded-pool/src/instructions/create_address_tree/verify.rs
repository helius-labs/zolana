use pinocchio::{error::ProgramError, AccountView, Address};
use zolana_interface::instruction::CreateAddressTreeData;

use crate::{error::ShieldedPoolError, instructions::loader::MutableAddressTreeAccounts};

pub fn verify<'a>(
    program_id: &Address,
    accounts: &'a [AccountView],
    data: &CreateAddressTreeData,
) -> Result<MutableAddressTreeAccounts<'a>, ProgramError> {
    if data.height == 0 || data.queue_capacity == 0 {
        return Err(ShieldedPoolError::InvalidAddressTreeConfig.into());
    }
    // On create the tree must be writable + shielded-pool-owned; if the caller
    // pre-allocated it correctly via system_program, the owner is already set
    // to this program before our processor runs.
    crate::instructions::loader::load_mutable_address_tree_accounts(program_id, accounts, true)
}
