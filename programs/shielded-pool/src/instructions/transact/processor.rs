use light_batched_merkle_tree::merkle_tree::BatchedMerkleTreeAccount;
use pinocchio::{
    sysvars::{clock::Clock, Sysvar},
    AccountView, Address, ProgramResult,
};
use zolana_interface::instruction::TransactData;

use super::proof::verify_transact_proof;
use super::settlement::settle_public_amounts;
use super::verify::verify;
use crate::{
    error::ShieldedPoolError,
    instructions::create_pool_tree::init::{
        address_sub_tree_slice_mut, append_state_leaves as append_to_pool,
    },
    log::log,
};

pub fn process_transact(
    program_id: &Address,
    accounts: &mut [AccountView],
    data: TransactData,
) -> ProgramResult {
    let verified = verify(program_id, accounts, &data)?;
    let tree_pubkey = *verified.tree.address();

    // SAFETY: this read-only borrow is scoped to proof verification and ends
    // before the later mutable borrow used for queue/state mutation.
    let bytes = unsafe { verified.tree.borrow_unchecked() };
    verify_transact_proof(bytes, &data, &verified.settlement)?;

    settle_public_amounts(program_id, &verified.settlement, &data)?;

    let mut queue_entries = Vec::with_capacity(data.nullifiers.len() + 1);
    for nullifier in &data.nullifiers {
        if !is_zero_32(nullifier) {
            queue_entries.push(*nullifier);
        }
    }
    queue_entries.push(data.sender_view_tag);

    let mut output_leaves = Vec::with_capacity(data.output_utxo_hashes.len());
    for output_hash in &data.output_utxo_hashes {
        if !is_zero_32(output_hash) {
            output_leaves.push(*output_hash);
        }
    }

    // SAFETY: `MutablePoolTreeAccounts::tree` is the writable account passed
    // by the caller and not aliased with any other borrowed account.
    let bytes = unsafe { verified.tree.borrow_unchecked_mut() };
    insert_queue_entries(bytes, tree_pubkey, &queue_entries)?;

    if !output_leaves.is_empty() && append_to_pool(bytes, &output_leaves).is_err() {
        log("transact: state sub-tree append failed");
        return Err(ShieldedPoolError::StateAppendFailed.into());
    }

    Ok(())
}

fn insert_queue_entries(
    bytes: &mut [u8],
    tree_pubkey: Address,
    entries: &[[u8; 32]],
) -> ProgramResult {
    let current_slot = Clock::get()?.slot;
    let address_slice = address_sub_tree_slice_mut(bytes)
        .map_err(|_| ShieldedPoolError::InvalidPoolTreeAccounts)?;
    let mut tree = BatchedMerkleTreeAccount::address_from_bytes(address_slice, &tree_pubkey)
        .map_err(|_| ShieldedPoolError::InvalidPoolTreeAccounts)?;

    for entry in entries {
        if tree
            .insert_address_into_queue(entry, &current_slot)
            .is_err()
        {
            log("transact: nullifier/view-tag queue insert failed");
            return Err(ShieldedPoolError::AddressQueueInsertFailed.into());
        }
    }
    Ok(())
}

fn is_zero_32(value: &[u8; 32]) -> bool {
    value.iter().all(|b| *b == 0)
}
