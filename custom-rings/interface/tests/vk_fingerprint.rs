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
        fingerprint, "002dba044c1423c2257756d2e455b8c445f2af6ee917fce2e1b9d6b61096be3d",
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
        "003a7dd718feeb06aaf61087d2c26ae0f327cc49c0349f5e8a92493d11a0b915",
    );
}

#[test]
fn delegate_policy_verifying_key_fingerprint_is_pinned() {
    assert_rail_fingerprint(
        "delegate_policy_verifying_key",
        &custom_ring_interface::delegate_policy_verifying_key::VERIFYINGKEY,
        "009396c4721cee463dd30fdf9bdcbaf1b74c58a3bd8ca81a7011bcc156e4c3fc",
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
        "002a3b32374aaec7b10dcb5eef8f8457cf48d18f587e3a7a878abfd5557782a9",
    );
}
