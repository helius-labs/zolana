use pinocchio::{error::ProgramError, AccountView, Address, ProgramResult};

use super::{init::init_tree_account, verify::verify};
use crate::{error::ShieldedPoolError, instructions::loader};

pub fn process_create_tree(program_id: &Address, accounts: &mut [AccountView]) -> ProgramResult {
    if accounts.len() < 3 {
        return Err(ProgramError::NotEnoughAccountKeys);
    }
    if !accounts[0].is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }
    let verified = verify(program_id, accounts)?;
    let tree_pubkey = *verified.tree.address();
    let bytes = loader::account_data_mut(verified.tree);
    init_tree_account(bytes, program_id, &tree_pubkey)
        .map_err(|_| ShieldedPoolError::InvalidTreeAccounts)?;
    Ok(())
}
