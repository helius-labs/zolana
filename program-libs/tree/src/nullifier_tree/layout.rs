use core::mem::{size_of, MaybeUninit};

use wincode::{
    config::{ConfigCore, ZeroCopy},
    io::Reader,
    ReadResult, SchemaRead, TypeMeta,
};

use zerocopy::{FromBytes, Immutable, KnownLayout};

use crate::nullifier_tree::{
    batch::{Batch, BatchState},
    constants::NUM_BATCHES,
    error::NullifierTreeError,
};

/// Cyclic root-history region: a write cursor followed by `N` root slots.
/// Capacity is the const generic `N`, so the only stored word is the cursor.
/// `[u8; 32]` is align-1, so there is no padding between the cursor and the
/// roots; the region is 8-byte aligned because the cursor is a `u64`.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, FromBytes, KnownLayout, Immutable)]
pub struct RootHistory<const N: usize> {
    pub current_index: u64,
    pub roots: [[u8; 32]; N],
}

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, FromBytes, KnownLayout, Immutable)]
pub struct NullifierTreeLayout<const ZKP_BATCHES: usize> {
    pub sequence_number: u64,
    pub next_index: u64,
    pub height: u32,
    /// Index of the batch accepting insertions. A `u32` so it fills the word
    /// `height` opens and the layout has no implicit padding.
    pub currently_processing_batch_index: u32,
    pub capacity: u64,
    pub batch_size: u64,
    pub zkp_batch_size: u64,
    /// Next batch to be inserted into the tree.
    pub pending_batch_index: u64,
    /// Queue index the next queued value takes. The queue is ahead of or equal
    /// to the tree: values are queued before they are applied to the tree.
    pub queue_next_index: u64,
    pub close_before_index: u64,
    pub root_history: RootHistory<ZKP_BATCHES>,
    pub batches: [Batch<ZKP_BATCHES>; NUM_BATCHES],
}

impl<const ZKP_BATCHES: usize> NullifierTreeLayout<ZKP_BATCHES> {
    pub fn get_num_zkp_batches(&self) -> u64 {
        self.batch_size / self.zkp_batch_size
    }

    pub fn get_current_batch(&self) -> Result<&Batch<ZKP_BATCHES>, NullifierTreeError> {
        self.batches
            .get(self.currently_processing_batch_index as usize)
            .ok_or(NullifierTreeError::InvalidBatchIndex)
    }

    pub fn get_current_batch_mut(&mut self) -> Result<&mut Batch<ZKP_BATCHES>, NullifierTreeError> {
        self.batches
            .get_mut(self.currently_processing_batch_index as usize)
            .ok_or(NullifierTreeError::InvalidBatchIndex)
    }

    pub fn get_pending_batch(&self) -> Result<&Batch<ZKP_BATCHES>, NullifierTreeError> {
        self.batches
            .get(self.pending_batch_index as usize)
            .ok_or(NullifierTreeError::InvalidBatchIndex)
    }

    pub fn get_pending_batch_mut(&mut self) -> Result<&mut Batch<ZKP_BATCHES>, NullifierTreeError> {
        self.batches
            .get_mut(self.pending_batch_index as usize)
            .ok_or(NullifierTreeError::InvalidBatchIndex)
    }

    /// Validates the queue, root-history, and cached-update capacities together.
    /// A root is appended for each ZKP batch, so one queue batch must contain
    /// exactly as many ZKP batches as both fixed-size account regions can hold.
    pub fn validate_configuration(
        batch_size: u64,
        zkp_batch_size: u64,
    ) -> Result<(), NullifierTreeError> {
        if batch_size == 0 || zkp_batch_size == 0 || !batch_size.is_multiple_of(zkp_batch_size) {
            return Err(NullifierTreeError::BatchSizeNotDivisibleByZkpBatchSize);
        }

        if batch_size / zkp_batch_size != ZKP_BATCHES as u64 {
            return Err(NullifierTreeError::InvalidRootHistoryCapacity);
        }
        Ok(())
    }

    pub fn increment_pending_batch_index_if_inserted(&mut self, state: BatchState) {
        if state == BatchState::Inserted {
            self.pending_batch_index = (self.pending_batch_index + 1) % NUM_BATCHES as u64;
        }
    }

    pub fn increment_currently_processing_batch_index_if_full(
        &mut self,
    ) -> Result<(), NullifierTreeError> {
        let state = self.get_current_batch()?.checked_state()?;
        if state == BatchState::Full {
            self.currently_processing_batch_index =
                (self.currently_processing_batch_index + 1) % NUM_BATCHES as u32;
        }
        Ok(())
    }
}

unsafe impl<C: ConfigCore, const ZKP_BATCHES: usize> ZeroCopy<C>
    for NullifierTreeLayout<ZKP_BATCHES>
{
}

unsafe impl<'de, C: ConfigCore, const ZKP_BATCHES: usize> SchemaRead<'de, C>
    for NullifierTreeLayout<ZKP_BATCHES>
{
    type Dst = Self;
    const TYPE_META: TypeMeta = TypeMeta::Static {
        size: size_of::<Self>(),
        zero_copy: true,
    };

    fn read(mut reader: impl Reader<'de>, dst: &mut MaybeUninit<Self>) -> ReadResult<()> {
        unsafe { Ok(reader.copy_into_t(dst)?) }
    }
}
