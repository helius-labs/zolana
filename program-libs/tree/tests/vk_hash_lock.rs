//! Pin canonical VK hashes to both the linked constants and the key-file lock.
#![cfg(feature = "verify")]
use groth16_solana::vk::setup::vk_sha256;
use spr_tree::nullifier_tree::verify::verifying_keys;

#[test]
fn verifying_key_sha256s_match_lockfile_and_key_points() {
    let lock: serde_json::Value = serde_json::from_str(include_str!(
        "../../../prover/server/prover/provingkeys/proving-keys.lock"
    ))
    .expect("lock JSON");
    let entries = [
        (
            "batch_address-append_40_10.key",
            &verifying_keys::batch_address_append_40_10::VERIFYINGKEY,
            verifying_keys::batch_address_append_40_10::VERIFYINGKEY_VK_SHA256,
        ),
        (
            "batch_address-append_40_4999.key",
            &verifying_keys::batch_address_append_40_4999::VERIFYINGKEY,
            verifying_keys::batch_address_append_40_4999::VERIFYINGKEY_VK_SHA256,
        ),
    ];
    for (name, vk, generated) in entries {
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
        assert_eq!((generated, hex.as_str()), (recomputed, pinned), "{name}");
    }
}
