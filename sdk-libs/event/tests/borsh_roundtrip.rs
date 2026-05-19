use borsh::{BorshDeserialize, BorshSerialize};
use light_event::{
    AddressQueuedEvent, AddressTreeBatchUpdatedEvent, PoolTreeCreatedEvent, ShieldedPoolEvent,
    StateLeavesAppendedEvent,
};

fn roundtrip<T: BorshSerialize + BorshDeserialize + Eq + std::fmt::Debug>(v: T) {
    let bytes = borsh::to_vec(&v).unwrap();
    let decoded = T::try_from_slice(&bytes).unwrap();
    assert_eq!(v, decoded);
}

#[test]
fn pool_tree_created_roundtrip() {
    roundtrip(PoolTreeCreatedEvent {
        pool_tree: [1u8; 32],
        owner: [2u8; 32],
        initial_state_root: [3u8; 32],
    });
}

#[test]
fn state_leaves_appended_roundtrip() {
    roundtrip(StateLeavesAppendedEvent {
        pool_tree: [4u8; 32],
        start_index: 7,
        new_root: [5u8; 32],
        leaves: vec![[6u8; 32], [7u8; 32]],
    });
}

#[test]
fn address_queued_roundtrip() {
    roundtrip(AddressQueuedEvent {
        pool_tree: [8u8; 32],
        address: [9u8; 32],
        slot: 42,
        queue_next_index: 3,
    });
}

#[test]
fn address_tree_batch_updated_roundtrip() {
    roundtrip(AddressTreeBatchUpdatedEvent {
        pool_tree: [10u8; 32],
        new_root: [11u8; 32],
        root_index: 5,
        sequence_number: 13,
    });
}

#[test]
fn enum_roundtrip() {
    let event = ShieldedPoolEvent::AddressQueued(AddressQueuedEvent {
        pool_tree: [1u8; 32],
        address: [2u8; 32],
        slot: 99,
        queue_next_index: 1,
    });
    roundtrip(event);
}
