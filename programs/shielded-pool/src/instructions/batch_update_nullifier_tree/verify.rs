use pinocchio::{error::ProgramError, AccountView, Address};
use zolana_interface::{instruction::BatchUpdateNullifierTreeData, LIGHT_REGISTRY_CPI_AUTHORITY};

use crate::{error::ShieldedPoolError, instructions::loader::MutablePoolTreeAccounts};

pub fn verify<'a>(
    program_id: &Address,
    accounts: &'a mut [AccountView],
    data: &BatchUpdateNullifierTreeData,
) -> Result<MutablePoolTreeAccounts<'a>, ProgramError> {
    if data.address_new_root == [0u8; 32] || data.nullifier_new_root == [0u8; 32] {
        return Err(ShieldedPoolError::EmptyBatchUpdateRoot.into());
    }
    let loaded =
        crate::instructions::loader::load_mutable_pool_tree_accounts(program_id, accounts, true)?;

    if *loaded.signer.address() != Address::from(LIGHT_REGISTRY_CPI_AUTHORITY) {
        return Err(ShieldedPoolError::UnauthorizedCaller.into());
    }

    Ok(loaded)
}
