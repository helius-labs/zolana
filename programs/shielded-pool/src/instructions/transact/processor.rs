use light_batched_merkle_tree::merkle_tree::BatchedMerkleTreeAccount;
use pinocchio::{
    sysvars::{clock::Clock, Sysvar},
    AccountView, Address, ProgramResult,
};
use zolana_interface::instruction::TransactData;

use super::{proof::verify_transact_proof, settlement::settle_public_amounts, verify::verify};
use crate::{
    error::ShieldedPoolError,
    instructions::{
        create_pool_tree::init::{
            address_sub_tree_slice_mut, append_state_leaves as append_to_pool,
        },
        loader,
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

    // Scope the mutable account borrow to proof verification so it ends before
    // settlement and the later state mutation (no overlapping borrow). The
    // root-history loader currently needs a mutable byte slice even though
    // proof verification does not mutate it. (account_data_mut's own unsafe
    // contract is documented at its definition.)
    {
        let bytes = loader::account_data_mut(verified.tree);
        verify_transact_proof(bytes, &tree_pubkey, &data, &verified.settlement)?;
    }

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

    let bytes = loader::account_data_mut(verified.tree);
    insert_queue_entries(bytes, tree_pubkey, &queue_entries)?;

    if !output_leaves.is_empty() && append_to_pool(bytes, &output_leaves).is_err() {
        log("transact: state sub-tree append failed");
        return Err(ShieldedPoolError::StateAppendFailed.into());
    }

    Ok(())
}

pub(crate) fn insert_queue_entries(
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
        // Every queued value (nullifiers and the view tag) is later inserted
        // into the nullifier tree, which only admits 0 < value < 2^248 - 1
        // (the Light AddressV2 domain; see NULLIFIER_TREE_SENTINEL). A 0 or
        // >= 2^248 - 1 value can never be batch-proven, so it would permanently
        // wedge the forester's queue. The view tag is attacker-controlled
        // instruction data, so reject out-of-range values here rather than
        // queueing an unprovable entry.
        if !is_insertable_nullifier(entry) {
            log("transact: queued value out of nullifier-tree range (0, p-1)");
            return Err(ShieldedPoolError::AddressQueueInsertFailed.into());
        }
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

// The nullifier tree is a light-batched-merkle-tree (AddressV2): its indexed
// value domain is 0 < value < 2^248 - 1, where 0 is the seed leaf and
// 2^248 - 1 (Light's HIGHEST_ADDRESS_PLUS_ONE) is the init sentinel
// next-value. Nullifiers and view tags are derived 248-bit (spec
// truncate_248 / L=31), so honest values always fit; reject the rest here
// rather than queueing an entry the batch-append circuit could never prove.
const NULLIFIER_TREE_SENTINEL: [u8; 32] = [
    0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
];

fn is_insertable_nullifier(value: &[u8; 32]) -> bool {
    !is_zero_32(value) && is_be_less_than(value, &NULLIFIER_TREE_SENTINEL)
}

// Big-endian 32-byte strict less-than.
fn is_be_less_than(a: &[u8; 32], b: &[u8; 32]) -> bool {
    for (x, y) in a.iter().zip(b.iter()) {
        if x != y {
            return x < y;
        }
    }
    false
}
