use pinocchio::{AccountView, Address, ProgramResult};
use zolana_interface::instruction::CreateAddressTreeData;

use super::{init::init_address_tree_account, verify::verify};
use crate::error::ShieldedPoolError;

pub fn process_create_address_tree(
    program_id: &Address,
    accounts: &[AccountView],
    data: CreateAddressTreeData,
) -> ProgramResult {
    let verified = verify(program_id, accounts, &data)?;
    let tree_pubkey = *verified.tree.address();
    // SAFETY: `MutableAddressTreeAccounts::tree` is the writable account passed
    // by the caller and not aliased with any other borrowed account.
    let bytes = unsafe { verified.tree.borrow_unchecked_mut() };
    init_address_tree_account(bytes, program_id, &tree_pubkey)
        .map_err(|_| ShieldedPoolError::InvalidAddressTreeAccounts)?;
    Ok(())
}
