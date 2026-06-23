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

use light_bloom_filter::BloomFilter;

use crate::{merkle_tree_metadata::BatchedMerkleTreeMetadata, queue::BatchedQueueMetadata};

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
    pub root_history: [[u8; 32]; ROOT_HISTORY],
    pub bloom_filters: [BloomFilter<NUM_ITERS, BLOOM_BYTES>; 2],
    pub hash_chains: [[[u8; 32]; ZKP_BATCHES]; 2],
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct QueueAccountLayout<const BATCH: usize, const ZKP_BATCHES: usize> {
    pub discriminator: [u8; 8],
    pub metadata: BatchedQueueMetadata,
    pub value_vecs: [[[u8; 32]; BATCH]; 2],
    pub hash_chains: [[[u8; 32]; ZKP_BATCHES]; 2],
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

unsafe impl<C: ConfigCore, const BATCH: usize, const ZKP: usize> ZeroCopy<C>
    for QueueAccountLayout<BATCH, ZKP>
{
}

unsafe impl<'de, C: ConfigCore, const BATCH: usize, const ZKP: usize> SchemaRead<'de, C>
    for QueueAccountLayout<BATCH, ZKP>
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
        layout.root_history[1] = [7u8; 32];
        layout.hash_chains[0][1] = [9u8; 32];
        layout.bloom_filters[0].insert(&[1u8; 32]).unwrap();
        let reloaded: &mut TreeAccountLayout<4, 3, 8, 2> =
            wincode::deserialize_mut(&mut bytes).unwrap();
        assert_eq!(reloaded.root_history[1], [7u8; 32]);
        assert_eq!(reloaded.hash_chains[0][1], [9u8; 32]);
        assert!(reloaded.bloom_filters[0].contains(&[1u8; 32]));
    }

    #[test]
    fn queue_layout_round_trips() {
        let mut bytes = vec![0u8; size_of::<QueueAccountLayout<4, 2>>()];
        let layout: &mut QueueAccountLayout<4, 2> = wincode::deserialize_mut(&mut bytes).unwrap();
        layout.value_vecs[1][3] = [5u8; 32];
        let reloaded: &mut QueueAccountLayout<4, 2> = wincode::deserialize_mut(&mut bytes).unwrap();
        assert_eq!(reloaded.value_vecs[1][3], [5u8; 32]);
    }
}
