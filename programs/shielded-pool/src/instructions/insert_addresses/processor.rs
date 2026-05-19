use light_batched_merkle_tree::merkle_tree::BatchedMerkleTreeAccount;
use pinocchio::{
    sysvars::{clock::Clock, Sysvar},
    AccountView, ProgramResult,
};
use zolana_interface::instruction::InsertAddressesData;

use super::verify::verify;
use crate::error::ShieldedPoolError;

pub fn process_insert_addresses(
    accounts: &[AccountView],
    data: InsertAddressesData,
) -> ProgramResult {
    let verified = verify(accounts, &data)?;
    let tree_pubkey = *verified.tree.address();
    let current_slot = Clock::get()?.slot;

    // SAFETY: `MutableAddressTreeAccounts::tree` is the writable account passed
    // by the caller and not aliased with any other borrowed account.
    let bytes = unsafe { verified.tree.borrow_unchecked_mut() };
    let mut tree = BatchedMerkleTreeAccount::address_from_bytes(bytes, &tree_pubkey)
        .map_err(|_| ShieldedPoolError::InvalidAddressTreeAccounts)?;

    for address in &data.addresses {
        tree.insert_address_into_queue(address, &current_slot)
            .map_err(|_| ShieldedPoolError::InvalidAddressTreeAccounts)?;
    }
    Ok(())
}
