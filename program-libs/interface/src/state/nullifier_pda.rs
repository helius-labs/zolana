#[cfg(feature = "borsh")]
use borsh::{BorshDeserialize, BorshSerialize};

pub const NULLIFIER_PDA_SEED: &[u8] = b"nullifier";
pub const NULLIFIER_PDA_SIZE: usize = 10;

#[cfg_attr(feature = "borsh", derive(BorshDeserialize, BorshSerialize))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NullifierPda {
    /// Queue index the nullifier reserved, equal to the leaf it takes in the
    /// nullifier tree. Never zero: leaf 0 is the tree's init sentinel, so a
    /// zero record was not written by the program.
    pub queue_index: u64,
    pub tree_id: u16,
}

impl NullifierPda {
    pub fn is_closable(&self, close_before_index: u64) -> bool {
        self.queue_index < close_before_index
    }
}
