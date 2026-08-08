//! The full verifying-key catalog, one entry per generated module, sorted by
//! module name (the `mod.rs` order). Registry codegen, the fingerprint pin,
//! and the registry-spec table all index this array, so a new VK is added
//! here exactly once.

use groth16_solana::groth16::Groth16Verifyingkey;

use super::{registry::VK_REGISTRY_SPECS, registry_spec::VkRegistrySpec, *};

/// The two generated tables are indexed by the same position, and the spec's
/// digest is a commitment to the key it sits beside. A length drift would pair
/// a key with another key's registry address.
const _: () = assert!(VK_CATALOG.len() == VK_REGISTRY_SPECS.len());

/// One catalogue key with the registry spec its digest commits to.
///
/// The only way to resolve an index into both tables. Fallible, because the
/// index reaches this from instruction data.
pub fn vk_catalog_entry(
    index: usize,
) -> Option<(
    &'static str,
    &'static Groth16Verifyingkey<'static>,
    &'static VkRegistrySpec,
)> {
    let (name, vk) = VK_CATALOG.get(index)?;
    Some((name, vk, VK_REGISTRY_SPECS.get(index)?))
}

macro_rules! catalog {
    ($(($name:literal, $vk:expr),)*) => {
        pub static VK_CATALOG: [(&str, &Groth16Verifyingkey<'static>); 38] = [
            $(($name, $vk),)*
        ];
    };
}

catalog!(
    (
        "batch_address_append_40_10",
        &zolana_batched_merkle_tree::verify::verifying_keys::batch_address_append_40_10::VERIFYINGKEY
    ),
    (
        "batch_address_append_40_250",
        &zolana_batched_merkle_tree::verify::verifying_keys::batch_address_append_40_250::VERIFYINGKEY
    ),
    ("merge_8_1", &merge_8_1::VERIFYINGKEY),
    ("merge_ring_8_1", &merge_ring_8_1::VERIFYINGKEY),
    ("transfer_confidential_1_1", &transfer_confidential_1_1::VERIFYINGKEY),
    ("transfer_confidential_1_2", &transfer_confidential_1_2::VERIFYINGKEY),
    ("transfer_confidential_1_8", &transfer_confidential_1_8::VERIFYINGKEY),
    ("transfer_confidential_2_2", &transfer_confidential_2_2::VERIFYINGKEY),
    ("transfer_confidential_2_3", &transfer_confidential_2_3::VERIFYINGKEY),
    ("transfer_confidential_3_3", &transfer_confidential_3_3::VERIFYINGKEY),
    ("transfer_confidential_4_3", &transfer_confidential_4_3::VERIFYINGKEY),
    ("transfer_confidential_4_4", &transfer_confidential_4_4::VERIFYINGKEY),
    ("transfer_confidential_5_3", &transfer_confidential_5_3::VERIFYINGKEY),
    ("transfer_confidential_5_4", &transfer_confidential_5_4::VERIFYINGKEY),
    ("transfer_p256_ring_1_1", &transfer_p256_ring_1_1::VERIFYINGKEY),
    ("transfer_p256_ring_1_2", &transfer_p256_ring_1_2::VERIFYINGKEY),
    ("transfer_p256_ring_1_8", &transfer_p256_ring_1_8::VERIFYINGKEY),
    ("transfer_p256_ring_2_2", &transfer_p256_ring_2_2::VERIFYINGKEY),
    ("transfer_p256_ring_2_3", &transfer_p256_ring_2_3::VERIFYINGKEY),
    ("transfer_p256_ring_3_3", &transfer_p256_ring_3_3::VERIFYINGKEY),
    ("transfer_p256_ring_4_3", &transfer_p256_ring_4_3::VERIFYINGKEY),
    ("transfer_p256_ring_4_4", &transfer_p256_ring_4_4::VERIFYINGKEY),
    ("transfer_p256_ring_5_3", &transfer_p256_ring_5_3::VERIFYINGKEY),
    ("transfer_p256_ring_5_4", &transfer_p256_ring_5_4::VERIFYINGKEY),
    ("transfer_ring_1_1", &transfer_ring_1_1::VERIFYINGKEY),
    ("transfer_ring_1_2", &transfer_ring_1_2::VERIFYINGKEY),
    ("transfer_ring_1_8", &transfer_ring_1_8::VERIFYINGKEY),
    ("transfer_ring_2_2", &transfer_ring_2_2::VERIFYINGKEY),
    ("transfer_ring_2_3", &transfer_ring_2_3::VERIFYINGKEY),
    ("transfer_ring_3_3", &transfer_ring_3_3::VERIFYINGKEY),
    ("transfer_ring_4_3", &transfer_ring_4_3::VERIFYINGKEY),
    ("transfer_ring_4_4", &transfer_ring_4_4::VERIFYINGKEY),
    ("transfer_ring_5_3", &transfer_ring_5_3::VERIFYINGKEY),
    ("transfer_ring_5_4", &transfer_ring_5_4::VERIFYINGKEY),
    ("transfer_ring_authority_1_1", &transfer_ring_authority_1_1::VERIFYINGKEY),
    ("transfer_ring_authority_2_2", &transfer_ring_authority_2_2::VERIFYINGKEY),
    ("transfer_ring_authority_3_3", &transfer_ring_authority_3_3::VERIFYINGKEY),
    ("transfer_ring_authority_4_4", &transfer_ring_authority_4_4::VERIFYINGKEY),
);
