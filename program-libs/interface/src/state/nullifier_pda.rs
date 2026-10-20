use super::discriminator::NULLIFIER_PDA;

pub const NULLIFIER_PDA_SEED: &[u8] = b"nullifier";
/// Account length: the discriminator byte, then the little-endian
/// `queue_index` and `tree_id`.
pub const NULLIFIER_PDA_SIZE: usize = 11;

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

    /// The record in its account layout: the [`NULLIFIER_PDA`] discriminator,
    /// then little-endian `queue_index` and little-endian `tree_id`. The
    /// discriminator types the account, so close never mistakes another
    /// program-owned account of the same length for a nullifier PDA.
    pub fn to_account_data(&self) -> [u8; NULLIFIER_PDA_SIZE] {
        let mut data = [0u8; NULLIFIER_PDA_SIZE];
        let (discriminator, rest) = data.split_at_mut(1);
        let (queue_index, tree_id) = rest.split_at_mut(8);
        discriminator.copy_from_slice(&[NULLIFIER_PDA]);
        queue_index.copy_from_slice(&self.queue_index.to_le_bytes());
        tree_id.copy_from_slice(&self.tree_id.to_le_bytes());
        data
    }

    /// Write [`Self::to_account_data`] into `data`, which must be exactly
    /// [`NULLIFIER_PDA_SIZE`] bytes.
    pub fn write_to(&self, data: &mut [u8]) -> Option<()> {
        let data: &mut [u8; NULLIFIER_PDA_SIZE] = data.try_into().ok()?;
        *data = self.to_account_data();
        Some(())
    }

    /// Read a record written by [`Self::write_to`]. `None` for a wrong length
    /// or a wrong discriminator.
    pub fn read_from(data: &[u8]) -> Option<Self> {
        let data: &[u8; NULLIFIER_PDA_SIZE] = data.try_into().ok()?;
        let (discriminator, rest) = data.split_first()?;
        if *discriminator != NULLIFIER_PDA {
            return None;
        }
        let (queue_index, tree_id) = rest.split_at(8);
        Some(Self {
            queue_index: u64::from_le_bytes(queue_index.try_into().ok()?),
            tree_id: u16::from_le_bytes(tree_id.try_into().ok()?),
        })
    }
}
