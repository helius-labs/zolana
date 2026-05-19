use light_batched_merkle_tree::merkle_tree::BatchedMerkleTreeAccount;
use pinocchio::{
    sysvars::{clock::Clock, Sysvar},
    AccountView, Address, ProgramResult,
};
use zolana_interface::instruction::InsertAddressesData;

use super::verify::verify;
use crate::{
    error::ShieldedPoolError, instructions::create_pool_tree::init::address_sub_tree_slice_mut,
};

pub fn process_insert_addresses(
    program_id: &Address,
    accounts: &[AccountView],
    data: InsertAddressesData,
) -> ProgramResult {
    let verified = verify(program_id, accounts, &data)?;
    let tree_pubkey = *verified.tree.address();
    let current_slot = Clock::get()?.slot;

    // SAFETY: tree is the writable account passed by the caller and not
    // aliased with any other borrowed account.
    let bytes = unsafe { verified.tree.borrow_unchecked_mut() };
    let address_slice = address_sub_tree_slice_mut(bytes)
        .map_err(|_| ShieldedPoolError::InvalidPoolTreeAccounts)?;
    let mut tree = BatchedMerkleTreeAccount::address_from_bytes(address_slice, &tree_pubkey)
        .map_err(|_| ShieldedPoolError::InvalidPoolTreeAccounts)?;

    for address in &data.addresses {
        tree.insert_address_into_queue(address, &current_slot)
            .map_err(|_| ShieldedPoolError::PoolTreeMutationFailed)?;
    }
    Ok(())
}
