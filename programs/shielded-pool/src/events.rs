//! Event emission via `sol_log_data`. Indexers consume these out of the
//! transaction logs to reconstruct tree state without reading the full
//! ~1.16 MB pool-tree account.

use light_event::{
    AddressQueuedEvent, AddressTreeBatchUpdatedEvent, PoolTreeCreatedEvent, ShieldedPoolEvent,
    StateLeavesAppendedEvent,
};
use pinocchio::Address;

use crate::instructions::create_pool_tree::init::STATE_HEIGHT;

#[inline]
fn emit(event: &ShieldedPoolEvent) {
    let bytes = match borsh::to_vec(event) {
        Ok(b) => b,
        // Logging is best-effort; never fail the instruction over a log.
        Err(_) => return,
    };
    log_data(&bytes);
}

#[inline]
fn log_data(bytes: &[u8]) {
    let parts: [&[u8]; 1] = [bytes];

    #[cfg(target_os = "solana")]
    unsafe {
        pinocchio::syscalls::sol_log_data(
            parts.as_ptr() as *const u8,
            parts.len() as u64,
        );
    }

    #[cfg(not(target_os = "solana"))]
    {
        let _ = parts;
    }
}

pub fn emit_pool_tree_created(tree: &Address, owner: &Address) {
    // Initial state root is the all-zero-leaves Poseidon root at STATE_HEIGHT
    // — known statically, no need to read the freshly-initialized buffer.
    use light_hasher::{Hasher, Poseidon};
    let initial_state_root = <Poseidon as Hasher>::zero_bytes()[STATE_HEIGHT];

    emit(&ShieldedPoolEvent::PoolTreeCreated(PoolTreeCreatedEvent {
        pool_tree: tree.to_bytes(),
        owner: owner.to_bytes(),
        initial_state_root,
    }));
}

pub fn emit_state_leaves_appended(
    tree: &Address,
    start_index: u64,
    new_root: [u8; 32],
    leaves: &[[u8; 32]],
) {
    emit(&ShieldedPoolEvent::StateLeavesAppended(
        StateLeavesAppendedEvent {
            pool_tree: tree.to_bytes(),
            start_index,
            new_root,
            leaves: leaves.to_vec(),
        },
    ));
}

pub fn emit_address_queued(tree: &Address, address: [u8; 32], slot: u64, queue_next_index: u64) {
    emit(&ShieldedPoolEvent::AddressQueued(AddressQueuedEvent {
        pool_tree: tree.to_bytes(),
        address,
        slot,
        queue_next_index,
    }));
}

pub fn emit_address_tree_batch_updated(
    tree: &Address,
    new_root: [u8; 32],
    root_index: u32,
    sequence_number: u64,
) {
    emit(&ShieldedPoolEvent::AddressTreeBatchUpdated(
        AddressTreeBatchUpdatedEvent {
            pool_tree: tree.to_bytes(),
            new_root,
            root_index,
            sequence_number,
        },
    ));
}
