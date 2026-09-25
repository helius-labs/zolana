//! groth16-solana exports a setup marker next to every generated verifying key,
//! and `zolana vks check` reads those markers back from a deployed program. The
//! markers sit in dependency crates (`zolana-interface`, `zolana-tree`), so this
//! reads the built `.so` (run `just build-programs` first) and expects exactly
//! one production marker per committed verifying key, each carrying the
//! proving-key sha256 its generated file pins.

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
    let mut found: Vec<([u8; 32], bool)> = find_setup_txts(&binary)
        .expect("vk setup markers parse")
        .into_iter()
        .map(|marker| (marker.proving_key_sha256, marker.insecure_test_setup))
        .collect();
    found.sort();
    let mut expected: Vec<([u8; 32], bool)> = zolana_interface::verifying_keys::PROVING_KEY_SHA256S
        .iter()
        .chain(zolana_tree::nullifier_tree::verify::verifying_keys::PROVING_KEY_SHA256S)
        .map(|(_, sha256)| (*sha256, false))
        .collect();
    expected.sort();
    assert_eq!(found, expected);
}
