#[path = "support/zk_fixture.rs"]
mod fixture;

use fixture::{Circuit, assert_success};
use sha2::{Digest, Sha256};
use std::{fs, path::Path, process::Command};

const CLI: &str = env!("CARGO_BIN_EXE_zolana");

#[test]
fn export_requires_a_trusted_verifying_key_manifest() {
    let output = Command::new(CLI)
        .args(["zk", "export-verifier"])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("--checksums"));
}

#[test]
fn export_checks_the_verifying_key_pin_before_parsing_or_writing() {
    let circuit = Circuit::new(
        Path::new(env!("CARGO_TARGET_TMPDIR")),
        "export_checks_the_verifying_key_pin_before_parsing_or_writing",
    );
    fs::write(circuit.artifact().join("vk.bin"), b"corrupt verifying key").unwrap();
    let output = circuit.export(CLI);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!output.status.success());
    assert!(
        stderr.contains("verifying key is not in the trusted checksum manifest"),
        "{stderr}"
    );
    assert_eq!(
        circuit.verifier_dir().exists(),
        false,
        "failed pin must not write any verifier"
    );
}

#[test]
fn export_rejects_unpinned_keys_and_mismatched_setup_metadata() {
    let circuit = Circuit::new(
        Path::new(env!("CARGO_TARGET_TMPDIR")),
        "export_rejects_unpinned_keys_and_mismatched_setup_metadata",
    );
    for contents in [
        String::new(),
        format!("{}  escrow/pk.bin\n", "00".repeat(32)),
    ] {
        circuit.write_checksums(&contents);
        let output = circuit.export(CLI);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(!output.status.success());
        assert!(
            stderr.contains("verifying key is not in the trusted checksum manifest"),
            "{stderr}"
        );
        assert_eq!(circuit.verifier_dir().exists(), false);
    }
    let bytes = fs::read(circuit.artifact().join("vk.bin")).unwrap();
    fs::write(circuit.artifact().join("vk.bin"), &bytes[..bytes.len() - 1]).unwrap();
    circuit.write_checksums(&format!("{}  escrow/vk.bin\n", circuit.vk_digest()));
    let output = circuit.export(CLI);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!output.status.success());
    assert!(
        stderr.contains("verifying key differs from its setup metadata"),
        "{stderr}"
    );
    assert_eq!(circuit.verifier_dir().exists(), false);
}

#[test]
fn export_derives_standard_setup_metadata_and_pins_exact_proving_key_bytes() {
    let circuit = Circuit::new(
        Path::new(env!("CARGO_TARGET_TMPDIR")),
        "export_derives_standard_setup_metadata_and_pins_exact_proving_key_bytes",
    );
    // sha256sum binary-mode records are accepted for the actual vk.bin artifact.
    circuit.write_checksums(&format!("{} *escrow/vk.bin\n", circuit.vk_digest()));
    assert_success(&circuit.export(CLI));
    let source = fs::read_to_string(circuit.committed("escrow.vk.rs")).unwrap();
    let pk_digest = format!(
        "{:x}",
        Sha256::digest(fs::read(circuit.artifact().join("pk.bin")).unwrap())
    );
    assert!(source.contains("pub const VERIFYINGKEY_INSECURE_TEST_SETUP: bool = true;"));
    assert!(source.contains("pub const VERIFYINGKEY_PROVING_KEY_SHA256: [u8; 32]"));
    assert!(source.contains(&format!("proving_key_sha256\\x00{pk_digest}\\x00")));
    assert!(source.contains("#[unsafe(export_name = \"groth16_solana_vk_setup_"));
    assert!(source.contains("#[cfg(not(feature = \"insecure-test-setup\"))]"));
    assert!(source.contains(&format!(
        "pub const ZOLANA_VK_SHA256: &str = \"{}\";",
        circuit.vk_digest()
    )));
    assert!(circuit.committed("escrow.rs").is_file());
}

#[test]
fn export_rejects_a_production_flag_on_real_dev_setup_keys() {
    let circuit = Circuit::new(
        Path::new(env!("CARGO_TARGET_TMPDIR")),
        "export_rejects_a_production_flag_on_real_dev_setup_keys",
    );
    let path = circuit.artifact().join("metadata.json");
    let mut metadata: serde_json::Value =
        serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    metadata["production_safe"] = serde_json::json!(true);
    fs::write(&path, serde_json::to_vec(&metadata).unwrap()).unwrap();
    let files = [
        path,
        circuit.artifact().join("pk.bin"),
        circuit.artifact().join("vk.bin"),
    ];
    let before = files.each_ref().map(|path| fs::read(path).unwrap());
    let output = circuit.export(CLI);
    assert!(
        !output.status.success(),
        "a sidecar flag must not relabel dev keys as production"
    );
    let after = files.each_ref().map(|path| fs::read(path).unwrap());
    assert_eq!(
        after, before,
        "rejected export must preserve every setup artifact"
    );
    assert_eq!(
        circuit.verifier_dir().exists(),
        false,
        "rejected setup classification must not write a verifier"
    );
}
