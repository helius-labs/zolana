use aligned_sized::aligned_sized;

use crate::{queue_batch_metadata::QueueBatches, BorshDeserialize, BorshSerialize};

pub const ADDRESS_MERKLE_TREE_TYPE_V2: u64 = 4;

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[repr(u64)]
pub enum TreeType {
    AddressV2 = ADDRESS_MERKLE_TREE_TYPE_V2,
}

#[repr(C)]
#[derive(
    BorshSerialize,
    BorshDeserialize,
    Debug,
    PartialEq,
    Clone,
    Copy,
    bytemuck::Pod,
    bytemuck::Zeroable,
)]
#[aligned_sized(anchor)]
pub struct BatchedMerkleTreeMetadata {
    pub tree_type: u64,
    pub sequence_number: u64,
    pub next_index: u64,
    pub height: u32,
    /// Root-history capacity is the `ZKP` const generic (`batch_size /
    /// zkp_batch_size`), so it is not stored. `bytemuck::Pod` forbids implicit
    /// padding, so the four bytes it used to occupy are declared explicitly.
    pub _padding: [u8; 4],
    pub capacity: u64,
    pub queue_batches: QueueBatches,
    pub close_before_index: u64,
}
