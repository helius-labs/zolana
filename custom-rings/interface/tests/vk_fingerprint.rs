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
        fingerprint, "00aef74b58e79520aa53e765488b4800a1e1bfa772dfc52da69f4ec69ef9adb1",
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
        fingerprint, "00c166b7d0effb48846babf65b6db4c7ed39402c048d6e540ceb9a46625ac1c6",
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
        "00ec3c3b992070ade0a2351b9e2a46b232af33a89e02d9018fc9417e77176927",
    );
}

#[test]
fn delegate_policy_verifying_key_fingerprint_is_pinned() {
    assert_rail_fingerprint(
        "delegate_policy_verifying_key",
        &custom_ring_interface::delegate_policy_verifying_key::VERIFYINGKEY,
        "001314d8e03bda9f6d0ace3966267c6b497d1fe5c4c23dfe5233b2ead0800585",
    );
}

#[test]
fn register_key_verifying_key_fingerprint_is_pinned() {
    assert_rail_fingerprint(
        "register_key_verifying_key",
        &custom_ring_interface::register_key_verifying_key::VERIFYINGKEY,
        "00198c3d52a19d7006adc899e9e1eeee0c4fed80e19fdd2d73640dc3ed84a3c8",
    );
}

#[test]
fn deposit_verifying_key_fingerprint_is_pinned() {
    assert_rail_fingerprint(
        "deposit_verifying_key",
        &custom_ring_interface::deposit_verifying_key::VERIFYINGKEY,
        "00402a5ef77e62e470830853dc57b7c937e4604f7d139df709221efa752e24d4",
    );
}
