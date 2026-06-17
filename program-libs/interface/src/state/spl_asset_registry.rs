use bytemuck::{Pod, Zeroable};
use solana_address::Address;

use super::discriminator::SPL_ASSET_REGISTRY;
use crate::{error::InterfaceError, SPL_ASSET_REGISTRY_PDA_SEED};

/// Typed view over the SPL asset registry record: discriminator (1),
/// reserved (7), mint (32), asset_id (8). The reserved bytes pad the `u64` to
/// its natural alignment so the struct has no implicit padding and is a valid
/// `Pod` for a single zero-copy `bytemuck` cast over the account data.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Pod, Zeroable)]
#[repr(C)]
pub struct SplAssetRegistry {
    pub discriminator: u8,
    pub reserved: [u8; 7],
    pub mint: Address,
    pub asset_id: u64,
}

impl SplAssetRegistry {
    pub const SIZE: usize = core::mem::size_of::<Self>();
    pub const SEED: &'static [u8] = SPL_ASSET_REGISTRY_PDA_SEED;

    pub fn check_discriminator(&self) -> Result<(), InterfaceError> {
        (self.discriminator == SPL_ASSET_REGISTRY)
            .then_some(())
            .ok_or(InterfaceError::InvalidDiscriminator)
    }

    pub fn set(&mut self, mint: Address, asset_id: u64) {
        self.discriminator = SPL_ASSET_REGISTRY;
        self.mint = mint;
        self.asset_id = asset_id;
    }
}

const _: () = assert!(SplAssetRegistry::SIZE == 48);
const _: () = assert!(core::mem::align_of::<SplAssetRegistry>() == 8);
