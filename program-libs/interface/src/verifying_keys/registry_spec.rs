//! Per-verifying-key registry account specification.
//!
//! A registry account caches, per VK, the prepared Miller line schedules of
//! its fixed G2 points and the `e(alpha, beta)` GT target, produced once by
//! the prepare syscalls from the compile-time VK constants. Its PDA
//! seeds include a keccak digest of those constants, so the address is a
//! commitment to the contents and hot-path authentication is one const
//! compare. The digest, address, and bump are emitted at codegen time into
//! `registry.rs` by `xtask vk-registry-consts`. [`derive_vk_registry_spec`]
//! is the single derivation the generator and the pin test share.

#[cfg(any(feature = "registry-derive", feature = "verifying-keys"))]
use groth16_solana::groth16::Groth16Verifyingkey;

pub const VK_REGISTRY_PDA_SEED: &[u8] = b"vk_registry";
#[cfg(feature = "registry-derive")]
const VK_REGISTRY_DIGEST_DOMAIN: &[u8] = b"zolana:vk-registry:v1";
pub const VK_REGISTRY_LAYOUT_VERSION: u8 = 1;
/// Prepared-blob backend byte. It must match the blob headers the prepare
/// syscall emits. A validator backend change bumps this and every account
/// re-initializes from its stored sources.
pub const VK_REGISTRY_BACKEND: u8 = 5;

pub const VK_REGISTRY_HEADER_BYTES: usize = 8;
pub const VK_REGISTRY_SOURCE_BYTES: usize = 128;
/// Prepared wire-blob size. It must equal the fork's
/// `vk_registry::PREPARED_G2_WIRE_BYTES`. Duplicated because the layout must
/// compile without the `vk-registry` syscall feature. The equality is pinned
/// where that feature is on.
pub const VK_REGISTRY_BLOB_BYTES: usize = 16_712;
pub const VK_REGISTRY_ENTRY_BYTES: usize = VK_REGISTRY_SOURCE_BYTES + VK_REGISTRY_BLOB_BYTES;
pub const VK_REGISTRY_GT_BYTES: usize = 384;

/// header, then g2_count x (canonical source, prepared blob), then the GT
/// target. Sources are kept so a backend bump can re-prepare in place.
pub const fn vk_registry_account_len(g2_count: usize) -> usize {
    VK_REGISTRY_HEADER_BYTES + g2_count * VK_REGISTRY_ENTRY_BYTES + VK_REGISTRY_GT_BYTES
}

pub const fn vk_registry_source_offset(index: usize) -> usize {
    VK_REGISTRY_HEADER_BYTES + index * VK_REGISTRY_ENTRY_BYTES
}

pub const fn vk_registry_blob_offset(index: usize) -> usize {
    vk_registry_source_offset(index) + VK_REGISTRY_SOURCE_BYTES
}

pub const fn vk_registry_gt_offset(g2_count: usize) -> usize {
    VK_REGISTRY_HEADER_BYTES + g2_count * VK_REGISTRY_ENTRY_BYTES
}

/// Codegen-emitted commitment to one VK's registry account.
///
/// `address` is `find_program_address([VK_REGISTRY_PDA_SEED, digest],
/// consumer)`. Comparing a passed account's address against it is the entire
/// hot-path trust decision.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VkRegistrySpec {
    pub g2_count: u8,
    pub digest: [u8; 32],
    pub address: [u8; 32],
    pub bump: u8,
}

/// G2 sources of a VK in the canonical registry order. The order is beta,
/// gamma, delta, then for BSB22 keys commitment.g2 and
/// commitment.g_sigma_neg_g2. The digest and the account entries use this
/// order. Changing it changes every address.
#[cfg(feature = "registry-derive")]
pub fn vk_registry_g2_sources(vk: &Groth16Verifyingkey) -> ([[u8; 128]; 5], usize) {
    let mut sources = [[0u8; 128]; 5];
    sources[0] = vk.vk_beta_g2;
    sources[1] = vk.vk_gamma_g2;
    sources[2] = vk.vk_delta_g2;
    match vk.vk_commitment {
        Some(commitment) => {
            sources[3] = commitment.g2;
            sources[4] = commitment.g_sigma_neg_g2;
            (sources, 5)
        }
        None => (sources, 3),
    }
}

/// Registry spec for a catalog verifying key.
///
/// Generated verifying keys are `const` values, so separate references to the
/// same constant are not guaranteed to have the same address. Compare the key
/// contents instead of relying on constant-promotion pointer identity. Covers
/// every generated key, the recursive outer keys included. A non-catalog key
/// resolves to `None` and the caller fails closed.
#[cfg(feature = "verifying-keys")]
pub fn vk_registry_spec_for(vk: &Groth16Verifyingkey<'_>) -> Option<&'static VkRegistrySpec> {
    let index = super::catalog::VK_CATALOG
        .iter()
        .position(|(_, entry)| *entry == vk)?;
    super::catalog::vk_catalog_entry(index).map(|(_, _, spec)| spec)
}

/// Derive the spec for one VK under a consumer program id. Used by the
/// codegen and re-run by the pin test. The program never derives at runtime.
#[cfg(feature = "registry-derive")]
pub fn derive_vk_registry_spec(vk: &Groth16Verifyingkey, consumer: &[u8; 32]) -> VkRegistrySpec {
    use sha3::{Digest, Keccak256};

    let (sources, g2_count) = vk_registry_g2_sources(vk);
    let mut hasher = Keccak256::new();
    hasher.update(VK_REGISTRY_DIGEST_DOMAIN);
    hasher.update([
        VK_REGISTRY_LAYOUT_VERSION,
        VK_REGISTRY_BACKEND,
        g2_count as u8,
    ]);
    for source in sources.iter().take(g2_count) {
        hasher.update(source);
    }
    hasher.update(vk.vk_alpha_g1);
    hasher.update(vk.vk_beta_g2);
    let digest: [u8; 32] = hasher.finalize().into();

    let (address, bump) = solana_pubkey::Pubkey::find_program_address(
        &[VK_REGISTRY_PDA_SEED, &digest],
        &solana_pubkey::Pubkey::new_from_array(*consumer),
    );
    VkRegistrySpec {
        g2_count: g2_count as u8,
        digest,
        address: address.to_bytes(),
        bump,
    }
}
