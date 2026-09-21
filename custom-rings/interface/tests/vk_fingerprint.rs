//! Pins a SHA-256 fingerprint over the committed custom-ring verifying key. The key
//! is a generated artifact (`prover/server/scripts/generate_keys_custom_ring.sh`),
//! a regeneration rewrites an opaque constant file that is effectively
//! unreviewable by diff. This test turns any VK change into an explicit
//! one-line re-pin: if it fails, confirm the rotation was intentional and
//! update the pinned fingerprint below.
#![cfg(feature = "verifying-keys")]

use groth16_solana::groth16::Groth16Verifyingkey;
use zolana_hasher::{sha256::Sha256BE, Hasher};

fn absorb(preimage: &mut Vec<u8>, name: &str, vk: &Groth16Verifyingkey) {
    preimage.extend_from_slice(name.as_bytes());
    preimage.extend_from_slice(&(vk.nr_pubinputs as u64).to_be_bytes());
    preimage.extend_from_slice(&vk.vk_alpha_g1);
    preimage.extend_from_slice(&vk.vk_beta_g2);
    preimage.extend_from_slice(&vk.vk_gamma_g2);
    preimage.extend_from_slice(&vk.vk_delta_g2);
    preimage.extend_from_slice(&(vk.vk_ic.len() as u64).to_be_bytes());
    for ic in vk.vk_ic {
        preimage.extend_from_slice(ic);
    }
    match &vk.vk_commitment {
        None => preimage.push(0),
        Some(commitment) => {
            preimage.push(1);
            preimage.extend_from_slice(&commitment.g2);
            preimage.extend_from_slice(&commitment.g_sigma_neg_g2);
        }
    }
}

#[test]
fn policy_verifying_key_fingerprint_is_pinned() {
    let mut preimage = Vec::new();
    absorb(
        &mut preimage,
        "policy_verifying_key",
        &custom_ring_interface::policy_verifying_key::VERIFYINGKEY,
    );
    let digest = Sha256BE::hash(&preimage).expect("fingerprint digest");
    let fingerprint: String = digest.iter().map(|byte| format!("{byte:02x}")).collect();

    // `Sha256BE` zeroes the leading byte (field-element convention), so the
    // fingerprint always starts with `00`.
    assert_eq!(
        fingerprint, "0028d9fdd1e0c86a6dce78f92ed5ee57304498952914c05a17d520abb2ea0fbc",
        "policy verifying key changed; if this rotation is intentional, re-pin the fingerprint"
    );
}

#[test]
fn base_verifying_key_fingerprint_is_pinned() {
    let mut preimage = Vec::new();
    absorb(
        &mut preimage,
        "base_verifying_key",
        &custom_ring_interface::base_verifying_key::VERIFYINGKEY,
    );
    let digest = Sha256BE::hash(&preimage).expect("fingerprint digest");
    let fingerprint: String = digest.iter().map(|byte| format!("{byte:02x}")).collect();

    assert_eq!(
        fingerprint, "004ca139a7638090b03c481d86f4720cd73bd425196fd5cbce4b003639b31e75",
        "base verifying key changed; if this rotation is intentional, re-pin the fingerprint"
    );
}

fn assert_rail_fingerprint(name: &str, vk: &Groth16Verifyingkey, expected: &str) {
    let mut preimage = Vec::new();
    absorb(&mut preimage, name, vk);
    let digest = Sha256BE::hash(&preimage).expect("fingerprint digest");
    let fingerprint: String = digest.iter().map(|byte| format!("{byte:02x}")).collect();
    assert_eq!(
        fingerprint, expected,
        "{name} changed; confirm the rotation before re-pinning"
    );
}

#[test]
fn compressed_policy_verifying_key_fingerprint_is_pinned() {
    assert_rail_fingerprint(
        "compressed_policy_verifying_key",
        &custom_ring_interface::compressed_policy_verifying_key::VERIFYINGKEY,
        "008418fed5ae58fec62aa34b9802b341c4b1530d707c8b86c33f2f5515227d3d",
    );
}

#[test]
fn compressed_register_verifying_key_fingerprint_is_pinned() {
    assert_rail_fingerprint(
        "compressed_register_verifying_key",
        &custom_ring_interface::compressed_register_verifying_key::VERIFYINGKEY,
        "00b806b5ca0ad7e48f519769b378ab0ddd22561507a8f8771c408f4042103f0d",
    );
}

#[test]
fn delegate_policy_verifying_key_fingerprint_is_pinned() {
    assert_rail_fingerprint(
        "delegate_policy_verifying_key",
        &custom_ring_interface::delegate_policy_verifying_key::VERIFYINGKEY,
        "002da50adf5b64a5a85a25f8604bf7355644e94398b115a3d3802402879bc064",
    );
}

#[test]
fn register_key_verifying_key_fingerprint_is_pinned() {
    assert_rail_fingerprint(
        "register_key_verifying_key",
        &custom_ring_interface::register_key_verifying_key::VERIFYINGKEY,
        "00d19fa87f5ef162037f4cccc69d6fbcd969d964a2bb9e06761624a94750bdf0",
    );
}

#[test]
fn deposit_verifying_key_fingerprint_is_pinned() {
    assert_rail_fingerprint(
        "deposit_verifying_key",
        &custom_ring_interface::deposit_verifying_key::VERIFYINGKEY,
        "0019d6f09a8c5574eadace234cee8e906ae3b7bd1dd7deb4bc8b3791213bf466",
    );
}
