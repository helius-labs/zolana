#[cfg(feature = "borsh")]
use borsh::{BorshDeserialize, BorshSerialize};

pub const NULLIFIER_PDA_SEED: &[u8] = b"nullifier";
pub const NULLIFIER_PDA_SIZE: usize = 9;

#[cfg_attr(feature = "borsh", derive(BorshDeserialize, BorshSerialize))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NullifierPda {
    pub queue_index: u64,
    pub bump: u8,
}

impl NullifierPda {
    pub fn is_closable(&self, close_before_index: u64) -> bool {
        self.queue_index < close_before_index
    }
}
