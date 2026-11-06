use std::{fs, ptr};

use dynamic_swap_program::verifier::pool_deposit::VERIFYINGKEY_PROVING_KEY_SHA256;

use super::{artifacts, load_circuit, CachedCircuit};

/// A copy of the built pool deposit circuit without its proving key, and the
/// key's bytes. `build-zk-program` writes the originals.
fn circuit_without_key() -> (tempfile::TempDir, Vec<u8>) {
    let built = artifacts("pool_deposit");
    let directory = tempfile::tempdir().unwrap();
    fs::copy(
        built.join("circuit.xbc"),
        directory.path().join("circuit.xbc"),
    )
    .expect("run `just ensure-dynamic-swap-keys` first");
    let key = fs::read(built.join("pk.bin")).expect("run `just ensure-dynamic-swap-keys` first");
    (directory, key)
}

#[test]
fn missing_proving_key_can_be_created_and_retried() {
    let (directory, key) = circuit_without_key();
    let cache = CachedCircuit::new();
    let checksum = &VERIFYINGKEY_PROVING_KEY_SHA256;

    assert!(load_circuit(&cache, directory.path(), checksum).is_err());
    fs::write(directory.path().join("pk.bin"), &key).unwrap();
    let loaded = load_circuit(&cache, directory.path(), checksum)
        .expect("creating the missing key must let the same cache retry");
    let reused = load_circuit(&cache, directory.path(), checksum).unwrap();
    assert!(ptr::eq(loaded, reused), "reuse the parsed circuit");
}

#[test]
fn mismatched_proving_key_is_refused_even_after_a_successful_load() {
    let (directory, key) = circuit_without_key();
    let cache = CachedCircuit::new();
    let checksum = &VERIFYINGKEY_PROVING_KEY_SHA256;
    let path = directory.path().join("pk.bin");

    fs::write(&path, b"an incomplete proving key").unwrap();
    assert!(load_circuit(&cache, directory.path(), checksum).is_err());
    fs::write(&path, &key).unwrap();
    load_circuit(&cache, directory.path(), checksum)
        .expect("repairing the key must let the same cache retry");

    fs::write(&path, b"a key swapped after loading").unwrap();
    assert!(
        load_circuit(&cache, directory.path(), checksum).is_err(),
        "each proof reads the key again, so each load checks it"
    );
}
