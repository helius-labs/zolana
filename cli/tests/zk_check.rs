#[path = "support/zk_fixture.rs"]
mod fixture;

use fixture::{Circuit, assert_success};
use std::{fs, path::Path};

const CLI: &str = env!("CARGO_BIN_EXE_zolana");

#[test]
fn check_rejects_missing_modules_without_writing() {
    let circuit = Circuit::new(
        Path::new(env!("CARGO_TARGET_TMPDIR")),
        "check_rejects_missing_modules_without_writing",
    );
    let output = circuit.check(CLI, false);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !output.status.success(),
        "check must reject missing committed verifiers"
    );
    assert!(stderr.contains("escrow.vk.rs"), "{stderr}");
    assert_eq!(
        circuit.verifier_dir().exists(),
        false,
        "check must not create committed modules"
    );
}

#[test]
fn check_rejects_changed_modules_without_modifying_files() {
    let circuit = Circuit::new(
        Path::new(env!("CARGO_TARGET_TMPDIR")),
        "check_rejects_changed_modules_without_modifying_files",
    );
    assert_success(&circuit.export(CLI));
    fs::write(circuit.committed("escrow.vk.rs"), "stale key\n").unwrap();
    fs::write(circuit.committed("unrelated.rs"), "user module\n").unwrap();
    let before = ["escrow.vk.rs", "escrow.rs", "unrelated.rs"]
        .map(|name| fs::read(circuit.committed(name)).unwrap());
    let output = circuit.check(CLI, false);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!output.status.success(), "check must reject a changed key");
    assert!(stderr.contains("escrow.vk.rs"), "{stderr}");
    let after = ["escrow.vk.rs", "escrow.rs", "unrelated.rs"]
        .map(|name| fs::read(circuit.committed(name)).unwrap());
    assert_eq!(
        after, before,
        "failed check must preserve every verifier file"
    );
}

#[test]
fn build_check_passes_without_wasm_or_sbf_and_preserves_keys() {
    let circuit = Circuit::new(
        Path::new(env!("CARGO_TARGET_TMPDIR")),
        "build_check_passes_without_wasm_or_sbf_and_preserves_keys",
    );
    assert_success(&circuit.export(CLI));
    let files = [
        circuit.committed("escrow.vk.rs"),
        circuit.committed("escrow.rs"),
        circuit.artifact().join("pk.bin"),
        circuit.artifact().join("vk.bin"),
        circuit.artifact().join("metadata.json"),
    ];
    let before = files.each_ref().map(|path| fs::read(path).unwrap());
    // There is no wasm feature; the SBF-only feature fails compilation if built.
    assert_success(&circuit.check(CLI, true));
    let after = files.each_ref().map(|path| fs::read(path).unwrap());
    assert_eq!(
        after, before,
        "successful check must preserve verifier and setup bytes"
    );
    assert_eq!(
        circuit.build_dir().join("wasm").exists(),
        false,
        "check must skip wasm"
    );
}
