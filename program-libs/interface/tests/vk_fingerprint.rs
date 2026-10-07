//! Pins a single SHA-256 fingerprint over every committed Groth16 verifying
//! key the shielded-pool program embeds. The keys are generated artifacts
//! (`prover/server/scripts/regenerate_all_vkeys.sh`); a regeneration rewrites
//! opaque constant files that are effectively unreviewable by diff. This
//! test turns any VK change into an explicit one-line re-pin: if it fails,
//! confirm the rotation was intentional (new proving keys uploaded, lockfile
//! updated in the same commit) and update the pinned fingerprint below.

use groth16_solana::groth16::Groth16Verifyingkey;
use zolana_hasher::{sha256::Sha256BE, Hasher};

macro_rules! vks {
    ($($module:ident),* $(,)?) => {
        [$((stringify!($module), &zolana_interface::verifying_keys::$module::VERIFYINGKEY)),*]
    };
}

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
    let keys: [(&str, &Groth16Verifyingkey); 122] = vks![
        merge_8_1,
        merge_24_1,
        merge_54_1,
        merge_ring_8_1,
        merge_ring_24_1,
        merge_ring_54_1,
        transfer_p256_ring_1_2,
        transfer_p256_ring_1_4,
        transfer_p256_ring_1_8,
        transfer_p256_ring_2_2,
        transfer_p256_ring_2_4,
        transfer_p256_ring_1_16,
        transfer_p256_ring_2_8,
        transfer_p256_ring_3_2,
        transfer_p256_ring_3_4,
        transfer_p256_ring_2_16,
        transfer_p256_ring_3_8,
        transfer_p256_ring_4_2,
        transfer_p256_ring_4_4,
        transfer_p256_ring_4_8,
        transfer_p256_ring_5_2,
        transfer_p256_ring_5_4,
        transfer_p256_ring_4_16,
        transfer_p256_ring_5_8,
        transfer_p256_ring_6_2,
        transfer_p256_ring_6_4,
        transfer_p256_ring_5_16,
        transfer_p256_ring_6_8,
        transfer_p256_ring_8_2,
        transfer_p256_ring_8_4,
        transfer_p256_ring_8_8,
        transfer_p256_ring_8_16,
        transfer_p256_ring_12_2,
        transfer_p256_ring_12_4,
        transfer_p256_ring_12_8,
        transfer_p256_ring_16_2,
        transfer_p256_ring_16_4,
        transfer_p256_ring_16_8,
        transfer_p256_ring_24_2,
        transfer_p256_ring_24_4,
        transfer_p256_ring_32_2,
        transfer_p256_ring_40_2,
        transfer_p256_ring_48_2,
        transfer_p256_ring_49_2,
        transfer_confidential_1_2,
        transfer_confidential_1_4,
        transfer_confidential_1_8,
        transfer_confidential_2_2,
        transfer_confidential_2_4,
        transfer_confidential_1_16,
        transfer_confidential_2_8,
        transfer_confidential_3_2,
        transfer_confidential_3_4,
        transfer_confidential_2_16,
        transfer_confidential_3_8,
        transfer_confidential_4_2,
        transfer_confidential_4_4,
        transfer_confidential_4_8,
        transfer_confidential_5_2,
        transfer_confidential_5_4,
        transfer_confidential_4_16,
        transfer_confidential_5_8,
        transfer_confidential_6_2,
        transfer_confidential_6_4,
        transfer_confidential_5_16,
        transfer_confidential_6_8,
        transfer_confidential_8_2,
        transfer_confidential_8_4,
        transfer_confidential_8_8,
        transfer_confidential_8_16,
        transfer_confidential_12_2,
        transfer_confidential_12_4,
        transfer_confidential_12_8,
        transfer_confidential_16_2,
        transfer_confidential_16_4,
        transfer_confidential_16_8,
        transfer_confidential_24_2,
        transfer_confidential_24_4,
        transfer_confidential_32_2,
        transfer_confidential_40_2,
        transfer_confidential_48_2,
        transfer_confidential_49_2,
        transfer_ring_1_2,
        transfer_ring_1_4,
        transfer_ring_1_8,
        transfer_ring_2_2,
        transfer_ring_2_4,
        transfer_ring_1_16,
        transfer_ring_2_8,
        transfer_ring_3_2,
        transfer_ring_3_4,
        transfer_ring_2_16,
        transfer_ring_3_8,
        transfer_ring_4_2,
        transfer_ring_4_4,
        transfer_ring_4_8,
        transfer_ring_5_2,
        transfer_ring_5_4,
        transfer_ring_4_16,
        transfer_ring_5_8,
        transfer_ring_6_2,
        transfer_ring_6_4,
        transfer_ring_5_16,
        transfer_ring_6_8,
        transfer_ring_8_2,
        transfer_ring_8_4,
        transfer_ring_8_8,
        transfer_ring_8_16,
        transfer_ring_12_2,
        transfer_ring_12_4,
        transfer_ring_12_8,
        transfer_ring_16_2,
        transfer_ring_16_4,
        transfer_ring_16_8,
        transfer_ring_24_2,
        transfer_ring_24_4,
        transfer_ring_32_2,
        transfer_ring_40_2,
        transfer_ring_48_2,
        transfer_ring_49_2,
        transfer_ring_authority_2_2,
        transfer_ring_authority_4_4,
    ];

    let mut preimage = Vec::new();
    for (name, vk) in keys {
        absorb(&mut preimage, name, vk);
    }
    let digest = Sha256BE::hash(&preimage).expect("fingerprint digest");
    let fingerprint: String = digest.iter().map(|byte| format!("{byte:02x}")).collect();

    // `Sha256BE` zeroes the leading byte (field-element convention), so the
    // fingerprint always starts with `00`.
    assert_eq!(
        fingerprint, "0030e0255e106fd7aed236e8da2274f98b3923da3c57cd0cfa3b19aa4d1dd08c",
        "verifying keys changed; if this rotation is intentional, re-pin the fingerprint"
    );
}
