//! Pins the proving-key sha256 each committed address-append verifying key
//! carries to `proving-keys.lock`, the file the prover verifies every key it
//! loads against, so a vk regenerated from a stale key fails here instead of
//! on-chain.
#![cfg(feature = "verify")]

use std::collections::BTreeMap;

use zolana_tree::nullifier_tree::verify::verifying_keys::PROVING_KEY_SHA256S;

const LOCK: &str = include_str!("../../../prover/server/prover/provingkeys/proving-keys.lock");

fn locked_sha256s() -> BTreeMap<String, String> {
    let lock: serde_json::Value = serde_json::from_str(LOCK).expect("proving-keys.lock is JSON");
    lock["keys"]
        .as_object()
        .expect("proving-keys.lock has a keys object")
        .iter()
        .map(|(name, entry)| {
            let sha256 = entry["sha256"].as_str().expect("lock entry has a sha256");
            (name.clone(), sha256.to_string())
        })
        .collect()
}

fn hex(bytes: &[u8; 32]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[test]
fn proving_key_sha256s_match_lockfile() {
    let locked = locked_sha256s();
    for (name, sha256) in PROVING_KEY_SHA256S {
        let pinned = locked
            .get(*name)
            .unwrap_or_else(|| panic!("{name} is not in proving-keys.lock"));
        assert_eq!(&hex(sha256), pinned, "{name}");
    }
}

#[test]
fn every_locked_address_append_key_has_a_verifying_key() {
    let locked: Vec<String> = locked_sha256s()
        .into_keys()
        .filter(|name| name.starts_with("batch_address-append_"))
        .collect();
    let committed: Vec<String> = PROVING_KEY_SHA256S
        .iter()
        .map(|(name, _)| name.to_string())
        .collect();
    assert_eq!(committed, locked);
}
