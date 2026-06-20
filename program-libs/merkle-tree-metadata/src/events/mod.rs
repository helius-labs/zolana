#![allow(deprecated)]

pub mod batch;
pub mod concurrent;

use batch::BatchEvent;
use concurrent::*;

use crate::{AnchorDeserialize, AnchorSerialize};

#[derive(AnchorDeserialize, AnchorSerialize, Debug, PartialEq)]
#[repr(C)]
pub enum MerkleTreeEvent {
    /// Reserved for the removed v1 changelog event layout. Do not emit new
    /// events with this variant; it exists so Borsh enum tags for v2 and batch
    /// events remain stable.
    #[doc(hidden)]
    #[deprecated(note = "legacy event tag reserved for wire compatibility")]
    V1(ChangelogEvent),
    V2(NullifierEvent),
    V3(IndexedMerkleTreeEvent),
    BatchAppend(BatchEvent),
    BatchNullify(BatchEvent),
    BatchAddressAppend(BatchEvent),
}

#[cfg(test)]
#[allow(deprecated)]
mod tests {
    use super::*;

    fn serialized_tag(event: &MerkleTreeEvent) -> u8 {
        let mut bytes = Vec::new();
        AnchorSerialize::serialize(event, &mut bytes).unwrap();
        bytes[0]
    }

    fn batch_event() -> BatchEvent {
        BatchEvent {
            merkle_tree_pubkey: [0; 32],
            batch_index: 0,
            zkp_batch_index: 0,
            zkp_batch_size: 0,
            old_next_index: 0,
            new_next_index: 0,
            new_root: [0; 32],
            root_index: 0,
            sequence_number: 0,
            output_queue_pubkey: None,
        }
    }

    #[test]
    fn merkle_tree_event_tags_are_wire_stable() {
        assert_eq!(
            serialized_tag(&MerkleTreeEvent::V1(ChangelogEvent {
                id: [0; 32],
                paths: Vec::new(),
                seq: 0,
                index: 0,
            })),
            0
        );
        assert_eq!(
            serialized_tag(&MerkleTreeEvent::V2(NullifierEvent {
                id: [0; 32],
                nullified_leaves_indices: Vec::new(),
                seq: 0,
            })),
            1
        );
        assert_eq!(
            serialized_tag(&MerkleTreeEvent::V3(IndexedMerkleTreeEvent {
                id: [0; 32],
                updates: Vec::new(),
                seq: 0,
            })),
            2
        );
        assert_eq!(
            serialized_tag(&MerkleTreeEvent::BatchAppend(batch_event())),
            3
        );
        assert_eq!(
            serialized_tag(&MerkleTreeEvent::BatchNullify(batch_event())),
            4
        );
        assert_eq!(
            serialized_tag(&MerkleTreeEvent::BatchAddressAppend(batch_event())),
            5
        );
    }
}
