//! Pins the proving-key sha256 each committed custom-ring verifying key
//! carries to `proving-keys.lock`, the file the prover verifies every key it
//! loads against, so a vk regenerated from a stale key fails here instead of
//! on-chain.
#![cfg(feature = "verifying-keys")]

use std::collections::BTreeMap;

use custom_ring_interface::{
    shaped_verifying_keys::SHAPED_PROVING_KEY_SHA256S, PROVING_KEY_SHA256S,
};

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
    for (name, sha256) in PROVING_KEY_SHA256S.iter().chain(SHAPED_PROVING_KEY_SHA256S) {
        let pinned = locked
            .get(*name)
            .unwrap_or_else(|| panic!("{name} is not in proving-keys.lock"));
        assert_eq!(&hex(sha256), pinned, "{name}");
    }
}

#[test]
fn every_locked_custom_ring_key_has_a_verifying_key() {
    let locked: Vec<String> = locked_sha256s()
        .into_keys()
        .filter(|name| name.starts_with("custom_ring_"))
        .collect();
    let mut committed: Vec<String> = PROVING_KEY_SHA256S
        .iter()
        .chain(SHAPED_PROVING_KEY_SHA256S)
        .map(|(name, _)| name.to_string())
        .collect();
    committed.sort();
    assert_eq!(committed, locked);
}

#[test]
fn every_shipped_shape_has_exactly_one_verifier_per_registry_strategy() {
    let manifest: serde_json::Value =
        serde_json::from_str(include_str!("../../policy-shapes.json")).unwrap();
    let mut names = std::collections::BTreeSet::new();
    for entry in manifest.as_array().unwrap() {
        let key = custom_ring_interface::shaped_verifying_keys::policy_shape_key(
            entry["inputs"].as_u64().unwrap() as usize,
            entry["outputs"].as_u64().unwrap() as usize,
            entry["anonymous"].as_bool().unwrap(),
            entry["delegate"].as_bool().unwrap(),
            entry["subtree"].as_bool().unwrap(),
        )
        .expect("shipped shape has a verifier");
        assert_eq!(key.nr_pubinputs, 78);
        assert_eq!(key.vk_ic.len(), 80);
        let name = format!(
            "{}.key",
            entry["circuit"].as_str().unwrap().replace('-', "_")
        );
        assert!(names.insert(name.clone()));
        assert!(SHAPED_PROVING_KEY_SHA256S
            .iter()
            .any(|(pinned, _)| *pinned == name));
    }
    assert_eq!(names.len(), SHAPED_PROVING_KEY_SHA256S.len());
}
