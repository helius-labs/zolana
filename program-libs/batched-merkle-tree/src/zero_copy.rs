use core::mem::size_of;

use solana_program_error::ProgramError;
use thiserror::Error;
use wincode::io::Reader;

#[derive(Debug, Error, PartialEq)]
pub enum ZeroCopyError {
    #[error("The vector is full, cannot push any new elements")]
    Full,
    #[error("Memory allocated {0}, Memory required {1}")]
    InsufficientMemoryAllocated(usize, usize),
    #[error("Invalid conversion")]
    InvalidConversion,
    #[error("Invalid size")]
    Size,
}

impl From<ZeroCopyError> for u32 {
    fn from(e: ZeroCopyError) -> u32 {
        match e {
            ZeroCopyError::Full => 15001,
            ZeroCopyError::InsufficientMemoryAllocated(_, _) => 15004,
            ZeroCopyError::InvalidConversion => 15008,
            ZeroCopyError::Size => 15010,
        }
    }
}

impl From<ZeroCopyError> for ProgramError {
    fn from(e: ZeroCopyError) -> Self {
        ProgramError::Custom(e.into())
    }
}

use core::mem::MaybeUninit;

use wincode::{
    config::{ConfigCore, ZeroCopy},
    ReadResult, SchemaRead, TypeMeta,
};
use zolana_bloom_filter::BloomFilter;

use crate::merkle_tree_metadata::BatchedMerkleTreeMetadata;

/// Cyclic ring buffer region with an upstream light-zero-copy `ZeroCopyCyclicVecU64`
/// header. `header = [current_index, length, capacity]` (24 bytes), followed by
/// `[[u8; 32]; N]` data. `T = [u8; 32]` is align-1 so there is no padding between
/// the header and the data; the whole region is 8-byte aligned because the header
/// is `[u64; 3]`.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct CyclicVec<const N: usize> {
    pub header: [u64; 3],
    pub data: [[u8; 32]; N],
}

/// Bounded vector region with an upstream light-zero-copy `ZeroCopyVecU64`
/// header. `header = [length, capacity]` (16 bytes), followed by
/// `[[u8; 32]; N]` data.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct BoundedVec<const N: usize> {
    pub header: [u64; 2],
    pub data: [[u8; 32]; N],
}

#[repr(C)]
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, bytemuck::Pod, bytemuck::Zeroable)]
pub struct CachedTreeUpdate {
    pub old_root: [u8; 32],
    pub new_root: [u8; 32],
    pub occupied: u8,
}

impl CachedTreeUpdate {
    pub fn is_occupied(&self) -> bool {
        self.occupied != 0
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct CachedTreeUpdateVec<const N: usize> {
    pub header: [u64; 2],
    pub data: [CachedTreeUpdate; N],
}

/// Upstream `ZeroCopyCyclicVecU64` header word indices.
pub(crate) const CYCLIC_CURRENT_INDEX: usize = 0;
pub(crate) const CYCLIC_LENGTH: usize = 1;
pub(crate) const CYCLIC_CAPACITY: usize = 2;

/// Upstream `ZeroCopyVecU64` header word indices.
pub(crate) const BOUNDED_LENGTH: usize = 0;
pub(crate) const BOUNDED_CAPACITY: usize = 1;

impl<const N: usize> BoundedVec<N> {
    /// Split a bounded region into a length-header reference and its data slice.
    /// The capacity word is fixed at init and is not exposed here.
    pub(crate) fn view(&mut self) -> BoundedVecView<'_> {
        BoundedVecView {
            length: &mut self.header[BOUNDED_LENGTH],
            data: &mut self.data,
        }
    }
}

/// A size-erased mutable view of a `BoundedVec`: the length header word plus
/// the data slice. Lets insertion helpers operate on regions of different
/// const capacities through one type while keeping the length header consistent.
pub(crate) struct BoundedVecView<'a> {
    pub(crate) length: &'a mut u64,
    pub(crate) data: &'a mut [[u8; 32]],
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct TreeAccountLayout<
    const ROOT_HISTORY: usize,
    const NUM_ITERS: usize,
    const BLOOM_BYTES: usize,
    const ZKP_BATCHES: usize,
> {
    pub discriminator: [u8; 8],
    pub metadata: BatchedMerkleTreeMetadata,
    pub root_history: CyclicVec<ROOT_HISTORY>,
    pub bloom_filters: [BloomFilter<NUM_ITERS, BLOOM_BYTES>; 2],
    pub hash_chains: [BoundedVec<ZKP_BATCHES>; 2],
    pub cached_tree_updates: [CachedTreeUpdateVec<ZKP_BATCHES>; 2],
}

unsafe impl<C: ConfigCore, const RH: usize, const NI: usize, const BLOOM: usize, const ZKP: usize>
    ZeroCopy<C> for TreeAccountLayout<RH, NI, BLOOM, ZKP>
{
}

unsafe impl<
        'de,
        C: ConfigCore,
        const RH: usize,
        const NI: usize,
        const BLOOM: usize,
        const ZKP: usize,
    > SchemaRead<'de, C> for TreeAccountLayout<RH, NI, BLOOM, ZKP>
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

#[cfg(test)]
mod layout_smoke {
    use super::*;

    #[test]
    fn tree_layout_round_trips() {
        let mut bytes = vec![0u8; size_of::<TreeAccountLayout<4, 3, 8, 2>>()];
        let layout: &mut TreeAccountLayout<4, 3, 8, 2> =
            wincode::deserialize_mut(&mut bytes).unwrap();
        layout.root_history.data[1] = [7u8; 32];
        layout.hash_chains[0].data[1] = [9u8; 32];
        layout.bloom_filters[0].insert(&[1u8; 32]).unwrap();
        layout.cached_tree_updates[1].data[1] = CachedTreeUpdate {
            old_root: [3u8; 32],
            new_root: [4u8; 32],
            occupied: 1,
        };
        let reloaded: &mut TreeAccountLayout<4, 3, 8, 2> =
            wincode::deserialize_mut(&mut bytes).unwrap();
        assert_eq!(reloaded.root_history.data[1], [7u8; 32]);
        assert_eq!(reloaded.hash_chains[0].data[1], [9u8; 32]);
        assert!(reloaded.bloom_filters[0].contains(&[1u8; 32]));
        assert_eq!(reloaded.cached_tree_updates[1].data[1].old_root, [3u8; 32]);
        assert_eq!(reloaded.cached_tree_updates[1].data[1].new_root, [4u8; 32]);
        assert_eq!(reloaded.cached_tree_updates[1].data[1].occupied, 1);
    }
}
