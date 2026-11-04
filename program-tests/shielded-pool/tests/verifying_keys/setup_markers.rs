//! groth16-solana exports a setup marker next to every generated verifying key,
//! and `zolana vks check` reads those markers back from a deployed program. The
//! markers sit in dependency crates (`spr-interface`, `spr-tree`), so this
//! reads the built `.so` (run `just build-programs` first) and expects exactly
//! one production marker per committed verifying key, each carrying the
//! canonical VK sha256 mapped to its proving-key file by the lockfile.

use groth16_solana::vk::setup::find_setup_txts;

fn program_path() -> String {
    std::env::var("SHIELDED_POOL_PROGRAM_PATH").unwrap_or_else(|_| {
        concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../target/deploy/shielded_pool_program.so"
        )
        .to_string()
    })
}

#[test]
fn every_verifying_key_marker_is_in_the_program_binary() {
    let path = program_path();
    let binary = std::fs::read(&path)
        .unwrap_or_else(|e| panic!("read {path} (run just build-programs): {e}"));
    let mut found: Vec<(String, bool)> = find_setup_txts(&binary)
        .expect("vk setup markers parse")
        .into_iter()
        .map(|marker| (hex::encode(marker.vk_sha256), marker.insecure_test_setup))
        .collect();
    found.sort();
    let lock: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../prover/server/prover/provingkeys/proving-keys.lock"
    ))
    .expect("proving-key lock JSON");
    let mut expected: Vec<(String, bool)> = spr_interface::verifying_keys::PROVING_KEY_SHA256S
        .iter()
        .chain(spr_tree::nullifier_tree::verify::verifying_keys::PROVING_KEY_SHA256S)
        .map(|(name, _)| {
            let digest = lock
                .get("keys")
                .and_then(|keys| keys.get(name))
                .and_then(|entry| entry.get("vk_sha256"))
                .and_then(serde_json::Value::as_str)
                .expect("locked VK hash");
            (digest.to_string(), false)
        })
        .collect();
    expected.sort();
    assert_eq!(found, expected);
    for (name, digest) in spr_interface::verifying_keys::PROVING_KEY_SHA256S
        .iter()
        .chain(spr_tree::nullifier_tree::verify::verifying_keys::PROVING_KEY_SHA256S)
    {
        assert!(
            !binary.windows(digest.len()).any(|bytes| bytes == digest),
            "{name}: the program must not embed a proving-key file hash"
        );
    }
}

#[test]
fn the_test_program_explicitly_enables_the_confidential_eddsa_keys() {
    let path = program_path();
    let binary = std::fs::read(&path)
        .unwrap_or_else(|error| panic!("read {path} (run just build-test-programs): {error}"));
    let feature = shielded_pool_program::circuit_features::CONFIDENTIAL_EDDSA;
    assert!(
        feature.enabled,
        "the host tests must enable confidential-eddsa"
    );
    assert_eq!(
        feature_gate::find_features(&binary).expect("feature markers parse"),
        vec![feature_gate::FeatureInfo {
            name: feature.name.into(),
            enabled: true,
            vk_sha256s: feature.vk_sha256s.to_vec(),
        }],
        "the SBF test binary must be built with confidential-eddsa"
    );
}
