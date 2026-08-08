//! Pins the committed registry specs to a re-derivation under this
//! program's own id. A VK or derivation change forces `cargo xtask
//! vk-registry-consts` to run in the same change.

use zolana_interface::verifying_keys::registry_spec::{derive_vk_registry_spec, VkRegistrySpec};

fn check(name: &str, vk: &groth16_solana::groth16::Groth16Verifyingkey, spec: &VkRegistrySpec) {
    assert_eq!(
        &derive_vk_registry_spec(vk, swap_program::ID.as_array()),
        spec,
        "stale registry spec for {name}"
    );
    assert_eq!(
        spec.g2_count,
        if vk.vk_commitment.is_some() { 5 } else { 3 },
        "wrong source count for {name}"
    );
}

#[test]
fn registry_specs_match_rederivation() {
    check(
        "cancel",
        &swap_program::verifying_keys::cancel::VERIFYINGKEY,
        &swap_program::vk_registry_specs::CANCEL_REGISTRY,
    );
    check(
        "make",
        &swap_program::verifying_keys::make::VERIFYINGKEY,
        &swap_program::vk_registry_specs::MAKE_REGISTRY,
    );
    check(
        "take",
        &swap_program::verifying_keys::take::VERIFYINGKEY,
        &swap_program::vk_registry_specs::TAKE_REGISTRY,
    );
    check(
        "take_verifiable_encryption",
        &swap_program::verifying_keys::take_verifiable_encryption::VERIFYINGKEY,
        &swap_program::vk_registry_specs::TAKE_VERIFIABLE_ENCRYPTION_REGISTRY,
    );
}
