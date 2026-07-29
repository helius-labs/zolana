use bytemuck::{Pod, Zeroable};

use super::discriminator::SPL_ASSET_COUNTER;
use crate::{error::InterfaceError, SPL_ASSET_COUNTER_PDA_SEED};

/// Typed view over the SPL asset counter: discriminator (1), reserved (7), and
/// the `next_id` (8) to assign on the next registration. The reserved bytes pad
/// the `u64` to its natural alignment so the struct has no implicit padding and
/// is a valid `Pod` for a single zero-copy `bytemuck` cast over the account
/// data.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Pod, Zeroable)]
#[repr(C)]
pub struct SplAssetCounter {
    pub discriminator: u8,
    pub reserved: [u8; 7],
    pub next_id: u64,
}

impl SplAssetCounter {
    pub const SIZE: usize = core::mem::size_of::<Self>();
    pub const SEED: &'static [u8] = SPL_ASSET_COUNTER_PDA_SEED;
    pub const FIRST_ASSET_ID: u64 = 2;

    pub fn check_discriminator(&self) -> Result<(), InterfaceError> {
        (self.discriminator == SPL_ASSET_COUNTER)
            .then_some(())
            .ok_or(InterfaceError::InvalidDiscriminator)
    }

    /// Initialize a freshly created (zeroed) counter: stamp the discriminator
    /// and seed `next_id` with [`Self::FIRST_ASSET_ID`].
    pub fn init(&mut self) {
        self.discriminator = SPL_ASSET_COUNTER;
        self.next_id = Self::FIRST_ASSET_ID;
    }

    /// Hand out the next asset id and advance the counter. Rejects a counter
    /// whose `next_id` dropped below [`Self::FIRST_ASSET_ID`] as corrupt, and a
    /// `next_id` at `u64::MAX` (no further ids available).
    pub fn allocate_id(&mut self) -> Result<u64, InterfaceError> {
        let id = self.next_id;
        if id < Self::FIRST_ASSET_ID {
            return Err(InterfaceError::InvalidDiscriminator);
        }
        self.next_id = id
            .checked_add(1)
            .ok_or(InterfaceError::InvalidDiscriminator)?;
        Ok(id)
    }
}

const _: () = assert!(SplAssetCounter::SIZE == 16);
const _: () = assert!(core::mem::align_of::<SplAssetCounter>() == 8);
