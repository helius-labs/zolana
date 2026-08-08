//! Pins the committed generated registry specs to a re-derivation from the
//! committed verifying keys, the analogue of `vk_fingerprint.rs`. A change
//! to a VK, the digest domain, the seed, the source order, or the consumer
//! id regenerates different specs, and this test forces `cargo xtask
//! vk-registry-consts` to run in the same change.
//!
//! The crate's own dev-dependency turns `registry-derive` on, so a missing
//! feature is a build failure here rather than a silently skipped file.

use zolana_interface::{
    verifying_keys::{
        catalog::VK_CATALOG,
        registry::VK_REGISTRY_SPECS,
        registry_spec::{
            derive_vk_registry_spec, vk_registry_account_len, vk_registry_blob_offset,
            vk_registry_gt_offset, VK_REGISTRY_BLOB_BYTES, VK_REGISTRY_ENTRY_BYTES,
        },
    },
    SHIELDED_POOL_PROGRAM_ID,
};

/// Generated keys are `const`, so two references to one key need not share an
/// address. Resolution must read the contents.
#[test]
fn registry_lookup_uses_key_contents_not_constant_address() {
    use groth16_solana::groth16::Groth16Verifyingkey;
    use zolana_interface::verifying_keys::registry_spec::vk_registry_spec_for;

    let original = VK_CATALOG[0].1;
    let copied = Groth16Verifyingkey {
        nr_pubinputs: original.nr_pubinputs,
        vk_alpha_g1: original.vk_alpha_g1,
        vk_beta_g2: original.vk_beta_g2,
        vk_gamma_g2: original.vk_gamma_g2,
        vk_delta_g2: original.vk_delta_g2,
        vk_ic: original.vk_ic,
        vk_commitment: original.vk_commitment,
    };

    assert!(!core::ptr::eq(original, &copied));
    assert_eq!(
        vk_registry_spec_for(original),
        vk_registry_spec_for(&copied)
    );
}

#[test]
fn committed_registry_specs_match_rederivation() {
    assert_eq!(VK_CATALOG.len(), VK_REGISTRY_SPECS.len());
    for ((name, vk), spec) in VK_CATALOG.iter().zip(VK_REGISTRY_SPECS.iter()) {
        let derived = derive_vk_registry_spec(vk, &SHIELDED_POOL_PROGRAM_ID);
        assert_eq!(&derived, spec, "stale registry spec for {name}");
        assert_eq!(
            spec.g2_count,
            if vk.vk_commitment.is_some() { 5 } else { 3 },
            "wrong source count for {name}"
        );
    }
}

#[test]
fn registry_account_layout_is_pinned() {
    assert_eq!(VK_REGISTRY_BLOB_BYTES, 16_712);
    assert_eq!(VK_REGISTRY_ENTRY_BYTES, 16_840);
    assert_eq!(vk_registry_account_len(3), 50_912);
    assert_eq!(vk_registry_account_len(5), 84_592);
    assert_eq!(vk_registry_blob_offset(0), 8 + 128);
    assert_eq!(vk_registry_gt_offset(3), 8 + 3 * 16_840);
}
