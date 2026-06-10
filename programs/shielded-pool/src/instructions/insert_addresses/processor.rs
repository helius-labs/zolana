use light_batched_merkle_tree::merkle_tree::BatchedMerkleTreeAccount;
use pinocchio::{
    sysvars::{clock::Clock, Sysvar},
    AccountView, Address, ProgramResult,
};
use zolana_interface::instruction::InsertAddressesData;

use super::verify::verify;
use crate::{
    error::ShieldedPoolError,
    instructions::{create_pool_tree::init::address_sub_tree_slice_mut, loader},
    log::log,
};

pub fn process_insert_addresses(
    program_id: &Address,
    accounts: &mut [AccountView],
    data: InsertAddressesData,
) -> ProgramResult {
    let verified = verify(program_id, accounts, &data)?;
    let tree_pubkey = *verified.tree.address();
    let current_slot = Clock::get()?.slot;

    let bytes = loader::account_data_mut(verified.tree);
    let address_slice = address_sub_tree_slice_mut(bytes)
        .map_err(|_| ShieldedPoolError::InvalidPoolTreeAccounts)?;
    let mut tree = BatchedMerkleTreeAccount::address_from_bytes(address_slice, &tree_pubkey)
        .map_err(|_| ShieldedPoolError::InvalidPoolTreeAccounts)?;

    for address in &data.addresses {
        if tree
            .insert_address_into_queue(address, &current_slot)
            .is_err()
        {
            log("insert_addresses: queue/bloom-filter insert failed");
            return Err(ShieldedPoolError::AddressQueueInsertFailed.into());
        }
    }
    Ok(())
}
