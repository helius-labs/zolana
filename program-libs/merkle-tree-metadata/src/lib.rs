//! # light-merkle-tree-metadata
//!
//! Metadata structs for indexed and batched Merkle trees.
//!
//! | Module | Description |
//! |--------|-------------|
//! | [`merkle_tree`] | Tree metadata: height, next index, owner, delegate |
//! | [`queue`] | Queue metadata: type, capacity, sequence numbers |
//! | [`access`] | Owner and delegate access control checks |
//! | [`fee`] | Fee parameters for tree and queue operations |
//! | [`rollover`] | Rollover threshold and status tracking |
//! | [`events`] | Changelog events emitted on tree updates |
//! | [`errors`] | `MerkleTreeMetadataError` variants |

pub mod access;
pub mod errors;
pub mod events;
pub mod fee;
pub mod merkle_tree;
pub mod queue;
pub mod rollover;
pub mod utils;
#[cfg(feature = "anchor")]
use anchor_lang::{AnchorDeserialize, AnchorSerialize};
#[cfg(not(feature = "anchor"))]
pub(crate) use borsh::{BorshDeserialize as AnchorDeserialize, BorshSerialize as AnchorSerialize};

pub(crate) fn serialize_address<W: borsh::io::Write>(
    address: &solana_address::Address,
    writer: &mut W,
) -> borsh::io::Result<()> {
    borsh::BorshSerialize::serialize(&address.to_bytes(), writer)
}

pub(crate) fn deserialize_address<R: borsh::io::Read>(
    reader: &mut R,
) -> borsh::io::Result<solana_address::Address> {
    <[u8; 32] as borsh::BorshDeserialize>::deserialize_reader(reader)
        .map(solana_address::Address::from)
}

pub const INPUT_STATE_QUEUE_TYPE_V2: u64 = 3;
pub const ADDRESS_QUEUE_TYPE_V2: u64 = 4;
pub const OUTPUT_STATE_QUEUE_TYPE_V2: u64 = 5;

#[derive(Debug, PartialEq, Clone, Copy)]
#[repr(u64)]
pub enum QueueType {
    InputStateV2 = INPUT_STATE_QUEUE_TYPE_V2,
    AddressV2 = ADDRESS_QUEUE_TYPE_V2,
    OutputStateV2 = OUTPUT_STATE_QUEUE_TYPE_V2,
}

impl From<u64> for QueueType {
    fn from(value: u64) -> Self {
        match value {
            INPUT_STATE_QUEUE_TYPE_V2 => QueueType::InputStateV2,
            ADDRESS_QUEUE_TYPE_V2 => QueueType::AddressV2,
            OUTPUT_STATE_QUEUE_TYPE_V2 => QueueType::OutputStateV2,
            _ => panic!("Invalid queue type"),
        }
    }
}

pub const STATE_MERKLE_TREE_TYPE_V2: u64 = 3;
pub const ADDRESS_MERKLE_TREE_TYPE_V2: u64 = 4;

#[derive(Debug, Default, Ord, PartialEq, PartialOrd, Eq, Clone, Copy)]
#[repr(u64)]
pub enum TreeType {
    #[default]
    StateV2 = STATE_MERKLE_TREE_TYPE_V2,
    AddressV2 = ADDRESS_MERKLE_TREE_TYPE_V2,
    Unknown = 255,
}

impl From<u64> for TreeType {
    fn from(value: u64) -> Self {
        match value {
            STATE_MERKLE_TREE_TYPE_V2 => TreeType::StateV2,
            ADDRESS_MERKLE_TREE_TYPE_V2 => TreeType::AddressV2,
            255 => TreeType::Unknown,
            _ => panic!("Invalid TreeType"),
        }
    }
}
