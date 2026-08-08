use bytemuck::{Pod, Zeroable};

use super::discriminator::VK_REGISTRY_ACCOUNT;
use crate::{
    error::InterfaceError,
    verifying_keys::registry_spec::{VK_REGISTRY_BACKEND, VK_REGISTRY_LAYOUT_VERSION},
};

/// Fixed 8-byte header of a per-verifying-key registry account. The variable
/// tail (`g2_count` source-plus-blob entries, then the GT target) is
/// addressed with the `registry_spec` offset functions. The account has no
/// single Pod view.
///
/// In the trust model, the account address is a PDA over the keyset digest, so
/// the hot path authenticates by comparing the address against the codegen'd
/// spec const. The header exists to gate the multi-transaction init flow
/// (`finalized`) and to reject stale blobs after a validator backend bump
/// (`backend`), not to authenticate contents.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Pod, Zeroable)]
#[repr(C)]
pub struct VkRegistryHeader {
    pub discriminator: u8,
    pub layout_version: u8,
    pub backend: u8,
    pub g2_count: u8,
    pub finalized: u8,
    pub bump: u8,
    pub reserved: [u8; 2],
}

impl VkRegistryHeader {
    pub const SIZE: usize = core::mem::size_of::<Self>();

    pub fn check(&self, g2_count: u8) -> Result<(), InterfaceError> {
        (self.discriminator == VK_REGISTRY_ACCOUNT
            && self.layout_version == VK_REGISTRY_LAYOUT_VERSION
            && self.backend == VK_REGISTRY_BACKEND
            && self.g2_count == g2_count
            && self.reserved == [0u8; 2])
            .then_some(())
            .ok_or(InterfaceError::InvalidDiscriminator)
    }

    pub fn is_finalized(&self) -> bool {
        self.finalized == 1
    }

    pub fn init(&mut self, g2_count: u8, bump: u8) -> Result<(), InterfaceError> {
        if self.discriminator != 0 {
            return Err(InterfaceError::AlreadyInitialized);
        }
        self.discriminator = VK_REGISTRY_ACCOUNT;
        self.layout_version = VK_REGISTRY_LAYOUT_VERSION;
        self.backend = VK_REGISTRY_BACKEND;
        self.g2_count = g2_count;
        self.finalized = 0;
        self.bump = bump;
        Ok(())
    }
}

const _: () = assert!(VkRegistryHeader::SIZE == 8);
const _: () = assert!(core::mem::align_of::<VkRegistryHeader>() == 1);
const _: () = assert!(
    VkRegistryHeader::SIZE == crate::verifying_keys::registry_spec::VK_REGISTRY_HEADER_BYTES
);
