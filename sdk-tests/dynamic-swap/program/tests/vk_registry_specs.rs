//! Pins the committed registry specs to a re-derivation under this
//! program's own id. A VK or derivation change forces `cargo xtask
//! vk-registry-consts` to run in the same change.

use zolana_interface::verifying_keys::registry_spec::{derive_vk_registry_spec, VkRegistrySpec};

fn check(name: &str, vk: &groth16_solana::groth16::Groth16Verifyingkey, spec: &VkRegistrySpec) {
    assert_eq!(
        &derive_vk_registry_spec(vk, dynamic_swap_program::ID.as_array()),
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
        "escrow_open",
        &dynamic_swap_program::verifying_keys::escrow_open::VERIFYINGKEY,
        &dynamic_swap_program::vk_registry_specs::ESCROW_OPEN_REGISTRY,
    );
    check(
        "escrow_settle",
        &dynamic_swap_program::verifying_keys::escrow_settle::VERIFYINGKEY,
        &dynamic_swap_program::vk_registry_specs::ESCROW_SETTLE_REGISTRY,
    );
}
