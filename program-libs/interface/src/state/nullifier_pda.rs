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

    /// Write the record in its account layout: little-endian `queue_index`
    /// followed by little-endian `tree_id`, the same bytes as the borsh
    /// encoding. `data` must be exactly [`NULLIFIER_PDA_SIZE`] bytes.
    pub fn write_to(&self, data: &mut [u8]) -> Option<()> {
        let data: &mut [u8; NULLIFIER_PDA_SIZE] = data.try_into().ok()?;
        data[..8].copy_from_slice(&self.queue_index.to_le_bytes());
        data[8..].copy_from_slice(&self.tree_id.to_le_bytes());
        Some(())
    }

    pub fn read_from(data: &[u8]) -> Option<Self> {
        let data: &[u8; NULLIFIER_PDA_SIZE] = data.try_into().ok()?;
        Some(Self {
            queue_index: u64::from_le_bytes(data[..8].try_into().ok()?),
            tree_id: u16::from_le_bytes(data[8..].try_into().ok()?),
        })
    }
}
