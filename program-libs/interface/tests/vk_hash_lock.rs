//! Pin canonical VK hashes to both the linked constants and the key-file lock.
#![cfg(feature = "verifying-keys")]
use groth16_solana::vk::setup::vk_sha256;
use spr_interface::verifying_keys;

macro_rules! vks {
    ($($module:ident),* $(,)?) => {
        [$(
            (
                concat!(stringify!($module), ".key"),
                &verifying_keys::$module::VERIFYINGKEY,
                verifying_keys::$module::VERIFYINGKEY_VK_SHA256,
            ),
        )*]
    };
}

#[test]
fn verifying_key_sha256s_match_lockfile_and_key_points() {
    let lock: serde_json::Value = serde_json::from_str(include_str!(
        "../../../prover/server/prover/provingkeys/proving-keys.lock"
    ))
    .expect("lock JSON");
    let entries = vks![
        merge_24_1,
        merge_52_1,
        merge_8_1,
        merge_ring_24_1,
        merge_ring_52_1,
        merge_ring_8_1,
        transfer_confidential_12_2,
        transfer_confidential_12_4,
        transfer_confidential_12_8,
        transfer_confidential_16_2,
        transfer_confidential_16_4,
        transfer_confidential_16_8,
        transfer_confidential_1_16,
        transfer_confidential_1_2,
        transfer_confidential_1_4,
        transfer_confidential_1_8,
        transfer_confidential_24_2,
        transfer_confidential_24_4,
        transfer_confidential_2_16,
        transfer_confidential_2_2,
        transfer_confidential_2_4,
        transfer_confidential_2_8,
        transfer_confidential_32_2,
        transfer_confidential_3_2,
        transfer_confidential_3_4,
        transfer_confidential_3_8,
        transfer_confidential_40_2,
        transfer_confidential_48_2,
        transfer_confidential_49_2,
        transfer_confidential_4_16,
        transfer_confidential_4_2,
        transfer_confidential_4_4,
        transfer_confidential_4_8,
        transfer_confidential_5_16,
        transfer_confidential_5_2,
        transfer_confidential_5_4,
        transfer_confidential_5_8,
        transfer_confidential_6_2,
        transfer_confidential_6_4,
        transfer_confidential_6_8,
        transfer_confidential_8_16,
        transfer_confidential_8_2,
        transfer_confidential_8_4,
        transfer_confidential_8_8,
        transfer_confidential_eddsa_16_16,
        transfer_confidential_eddsa_16_8,
        transfer_confidential_eddsa_24_16,
        transfer_confidential_eddsa_24_8,
        transfer_confidential_eddsa_2_16,
        transfer_confidential_eddsa_2_8,
        transfer_confidential_eddsa_48_16,
        transfer_confidential_eddsa_48_8,
        transfer_confidential_eddsa_4_16,
        transfer_confidential_eddsa_4_8,
        transfer_confidential_eddsa_8_16,
        transfer_confidential_eddsa_8_8,
        transfer_eddsa_ring_12_2,
        transfer_eddsa_ring_12_4,
        transfer_eddsa_ring_12_8,
        transfer_eddsa_ring_16_2,
        transfer_eddsa_ring_16_4,
        transfer_eddsa_ring_16_8,
        transfer_eddsa_ring_1_16,
        transfer_eddsa_ring_1_2,
        transfer_eddsa_ring_1_4,
        transfer_eddsa_ring_1_8,
        transfer_eddsa_ring_24_2,
        transfer_eddsa_ring_24_4,
        transfer_eddsa_ring_2_16,
        transfer_eddsa_ring_2_2,
        transfer_eddsa_ring_2_4,
        transfer_eddsa_ring_2_8,
        transfer_eddsa_ring_32_2,
        transfer_eddsa_ring_3_2,
        transfer_eddsa_ring_3_4,
        transfer_eddsa_ring_3_8,
        transfer_eddsa_ring_40_2,
        transfer_eddsa_ring_48_2,
        transfer_eddsa_ring_49_2,
        transfer_eddsa_ring_4_16,
        transfer_eddsa_ring_4_2,
        transfer_eddsa_ring_4_4,
        transfer_eddsa_ring_4_8,
        transfer_eddsa_ring_5_16,
        transfer_eddsa_ring_5_2,
        transfer_eddsa_ring_5_4,
        transfer_eddsa_ring_5_8,
        transfer_eddsa_ring_6_2,
        transfer_eddsa_ring_6_4,
        transfer_eddsa_ring_6_8,
        transfer_eddsa_ring_8_16,
        transfer_eddsa_ring_8_2,
        transfer_eddsa_ring_8_4,
        transfer_eddsa_ring_8_8,
        transfer_ring_12_2,
        transfer_ring_12_4,
        transfer_ring_12_8,
        transfer_ring_16_2,
        transfer_ring_16_4,
        transfer_ring_16_8,
        transfer_ring_1_16,
        transfer_ring_1_2,
        transfer_ring_1_4,
        transfer_ring_1_8,
        transfer_ring_24_2,
        transfer_ring_24_4,
        transfer_ring_2_16,
        transfer_ring_2_2,
        transfer_ring_2_4,
        transfer_ring_2_8,
        transfer_ring_32_2,
        transfer_ring_3_2,
        transfer_ring_3_4,
        transfer_ring_3_8,
        transfer_ring_40_2,
        transfer_ring_48_2,
        transfer_ring_49_2,
        transfer_ring_4_16,
        transfer_ring_4_2,
        transfer_ring_4_4,
        transfer_ring_4_8,
        transfer_ring_5_16,
        transfer_ring_5_2,
        transfer_ring_5_4,
        transfer_ring_5_8,
        transfer_ring_6_2,
        transfer_ring_6_4,
        transfer_ring_6_8,
        transfer_ring_8_16,
        transfer_ring_8_2,
        transfer_ring_8_4,
        transfer_ring_8_8,
        transfer_ring_authority_2_2,
        transfer_ring_authority_4_4,
    ];
    for (name, vk, generated) in entries {
        let listed = verifying_keys::VK_SHA256S
            .iter()
            .find_map(|(file, digest)| (*file == name).then_some(*digest))
            .expect("VK hash is listed");
        let pinned = lock
            .get("keys")
            .and_then(|keys| keys.get(name))
            .and_then(|entry| entry.get("vk_sha256"))
            .and_then(serde_json::Value::as_str)
            .expect("locked VK hash");
        let recomputed = vk_sha256(vk);
        let hex = recomputed
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>();
        assert_eq!(
            (generated, listed, hex.as_str()),
            (recomputed, recomputed, pinned),
            "{name}"
        );
    }
    assert_eq!(entries.len(), verifying_keys::VK_SHA256S.len());
}
