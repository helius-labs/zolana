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

use crate::{constants::NUM_BATCHES, merkle_tree_metadata::BatchedMerkleTreeMetadata};

/// Cyclic root-history region: a write cursor followed by `N` root slots.
/// Capacity is the const generic `N`, so the only stored word is the cursor.
/// `[u8; 32]` is align-1, so there is no padding between the cursor and the
/// roots; the region is 8-byte aligned because the cursor is a `u64`.
#[repr(C)]
#[derive(Clone, Copy, PartialEq)]
pub struct RootHistory<const N: usize> {
    pub current_index: u64,
    pub roots: [[u8; 32]; N],
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
#[derive(Clone, Copy, PartialEq)]
pub struct TreeAccountLayout<const ZKP_BATCHES: usize> {
    pub discriminator: [u8; 8],
    pub metadata: BatchedMerkleTreeMetadata,
    pub root_history: RootHistory<ZKP_BATCHES>,
    pub hash_chains: [[[u8; 32]; ZKP_BATCHES]; NUM_BATCHES],
    pub cached_tree_updates: [[CachedTreeUpdate; ZKP_BATCHES]; NUM_BATCHES],
}

unsafe impl<C: ConfigCore, const ZKP: usize> ZeroCopy<C> for TreeAccountLayout<ZKP> {}

unsafe impl<'de, C: ConfigCore, const ZKP: usize> SchemaRead<'de, C> for TreeAccountLayout<ZKP> {
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
        let mut bytes = vec![0u8; size_of::<TreeAccountLayout<2>>()];
        let layout: &mut TreeAccountLayout<2> = wincode::deserialize_mut(&mut bytes).unwrap();
        layout.root_history.roots[1] = [7u8; 32];
        layout.hash_chains[0][1] = [9u8; 32];
        layout.cached_tree_updates[1][1] = CachedTreeUpdate {
            old_root: [3u8; 32],
            new_root: [4u8; 32],
            occupied: 1,
        };
        let reloaded: &mut TreeAccountLayout<2> = wincode::deserialize_mut(&mut bytes).unwrap();
        assert_eq!(reloaded.root_history.roots[1], [7u8; 32]);
        assert_eq!(reloaded.hash_chains[0][1], [9u8; 32]);
        assert_eq!(reloaded.cached_tree_updates[1][1].old_root, [3u8; 32]);
        assert_eq!(reloaded.cached_tree_updates[1][1].new_root, [4u8; 32]);
        assert_eq!(reloaded.cached_tree_updates[1][1].occupied, 1);
    }
}
