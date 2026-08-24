//! Pins a SHA-256 fingerprint over the committed audit verifying key. The key
//! is a generated artifact (`prover/server/scripts/regenerate_all_vkeys.sh`);
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
fn verifying_key_fingerprint_is_pinned() {
    let mut preimage = Vec::new();
    absorb(
        &mut preimage,
        "audit_vk",
        &custom_ring_interface::audit_vk::VERIFYINGKEY,
    );
    let digest = Sha256BE::hash(&preimage).expect("fingerprint digest");
    let fingerprint: String = digest.iter().map(|byte| format!("{byte:02x}")).collect();

    // `Sha256BE` zeroes the leading byte (field-element convention), so the
    // fingerprint always starts with `00`.
    assert_eq!(
        fingerprint, "00fcd040ec258abfc3cabdceefdf24eb4c7a3b47d29b5aafd87b7b7b4f598148",
        "verifying key changed; if this rotation is intentional, re-pin the fingerprint"
    );
}
