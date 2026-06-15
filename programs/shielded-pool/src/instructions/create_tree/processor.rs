use pinocchio::{AccountView, Address, ProgramResult};

use super::{init::init_tree_account, verify::verify};
use crate::{error::ShieldedPoolError, instructions::loader};

pub fn process_create_tree(program_id: &Address, accounts: &mut [AccountView]) -> ProgramResult {
    let verified = verify(program_id, accounts)?;
    let tree_pubkey = *verified.tree.address();
    let bytes = loader::account_data_mut(verified.tree);
    init_tree_account(bytes, program_id, &tree_pubkey)
        .map_err(|_| ShieldedPoolError::InvalidTreeAccounts)?;
    Ok(())
}
