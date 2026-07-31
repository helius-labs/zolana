//! Pins a single SHA-256 fingerprint over every committed Groth16 verifying
//! key the shielded-pool program embeds. The keys are generated artifacts
//! (`prover/server/scripts/regenerate_all_vkeys.sh`); a regeneration rewrites
//! 26 opaque constant files that are effectively unreviewable by diff. This
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
    let keys: [(&str, &Groth16Verifyingkey); 36] = vks![
        merge_8_1,
        merge_zone_8_1,
        transfer_p256_zone_1_1,
        transfer_p256_zone_1_2,
        transfer_p256_zone_1_8,
        transfer_p256_zone_2_2,
        transfer_p256_zone_2_3,
        transfer_p256_zone_3_3,
        transfer_p256_zone_4_3,
        transfer_p256_zone_4_4,
        transfer_p256_zone_5_3,
        transfer_p256_zone_5_4,
        transfer_confidential_1_1,
        transfer_confidential_1_2,
        transfer_confidential_1_8,
        transfer_confidential_2_2,
        transfer_confidential_2_3,
        transfer_confidential_3_3,
        transfer_confidential_4_3,
        transfer_confidential_4_4,
        transfer_confidential_5_3,
        transfer_confidential_5_4,
        transfer_zone_1_1,
        transfer_zone_1_2,
        transfer_zone_1_8,
        transfer_zone_2_2,
        transfer_zone_2_3,
        transfer_zone_3_3,
        transfer_zone_4_3,
        transfer_zone_4_4,
        transfer_zone_5_3,
        transfer_zone_5_4,
        transfer_zone_authority_1_1,
        transfer_zone_authority_2_2,
        transfer_zone_authority_3_3,
        transfer_zone_authority_4_4,
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
        fingerprint, "00e8b2716ed4bee43814992e86cdf94582d316c8757525ec25f4a7b01b802542",
        "verifying keys changed; if this rotation is intentional, re-pin the fingerprint"
    );
}
