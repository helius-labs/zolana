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
        fingerprint, "00ea83fbcf8264dcbf6ee378f4d06707166d643524cd44d3881c7f50e73037ff",
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
        fingerprint, "00a638d9fa9214907ed586a25d32cc1dfaa6f43e36088c63e410aa56b2439125",
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
fn confidential_base_verifying_key_fingerprint_is_pinned() {
    assert_rail_fingerprint(
        "base_confidential_verifying_key",
        &custom_ring_interface::base_confidential_verifying_key::VERIFYINGKEY,
        "00e3d232a1bb9206080e7a37671f949081e6215c1dddcdd737d6f81a9e1b80db",
    );
}

#[test]
fn delegate_policy_verifying_key_fingerprint_is_pinned() {
    assert_rail_fingerprint(
        "delegate_policy_verifying_key",
        &custom_ring_interface::delegate_policy_verifying_key::VERIFYINGKEY,
        "0000a442b4ea66ddd63d139590f1787a6fe04255c3136d3a096e234858766e70",
    );
}

#[test]
fn register_key_verifying_key_fingerprint_is_pinned() {
    assert_rail_fingerprint(
        "register_key_verifying_key",
        &custom_ring_interface::register_key_verifying_key::VERIFYINGKEY,
        "00cc659410e9fb2bff6fa3761867c88f2d23be231b9c85b9f341e3acb3ecd44e",
    );
}

#[test]
fn deposit_verifying_key_fingerprint_is_pinned() {
    assert_rail_fingerprint(
        "deposit_verifying_key",
        &custom_ring_interface::deposit_verifying_key::VERIFYINGKEY,
        "00f7e46b1b7fcd535547f2d902bf77eacc3ca4bc8b2ab1bcc10778d2ae9c6705",
    );
}

#[test]
fn update_members_verifying_key_fingerprint_is_pinned() {
    assert_rail_fingerprint(
        "update_members_verifying_key",
        &custom_ring_interface::update_members_verifying_key::VERIFYINGKEY,
        "00d2a0857f2d81b7e86400af8a18b5427cca6e735df5fd0c0c9f44b1ba5fb924",
    );
}

#[test]
fn policy_2x3_verifying_key_fingerprint_is_pinned() {
    assert_rail_fingerprint(
        "policy_2x3_verifying_key",
        &custom_ring_interface::policy_2x3_verifying_key::VERIFYINGKEY,
        "004e5ba7881f0811d11b7fe71aee6b62a5da33ffaf95aca6af123dc0f3a407b1",
    )
}

#[test]
fn policy_2x3_anonymous_verifying_key_fingerprint_is_pinned() {
    assert_rail_fingerprint(
        "policy_2x3_anonymous_verifying_key",
        &custom_ring_interface::policy_2x3_anonymous_verifying_key::VERIFYINGKEY,
        "002fc742e008811a85f831bc82e93d6834d1feba3f38551ac3a5c98d9d687d9b",
    )
}

#[test]
fn delegate_policy_2x3_verifying_key_fingerprint_is_pinned() {
    assert_rail_fingerprint(
        "delegate_policy_2x3_verifying_key",
        &custom_ring_interface::delegate_policy_2x3_verifying_key::VERIFYINGKEY,
        "00717a5f396de81b02478813c2b1005bcb7fd91bdc800c495897ac358ddc951d",
    )
}
