#[path = "support/zk_fixture.rs"]
mod fixture;

use fixture::{assert_success, key_bytes, Circuit, PINNED_FILES};
use serde_json::json;
use std::{fs, path::Path, process::Command};

const CLI: &str = env!("CARGO_BIN_EXE_zolana");

fn circuit(name: &str) -> Circuit {
    Circuit::new(Path::new(env!("CARGO_TARGET_TMPDIR")), name)
}

/// Exports, expecting a failure that names `expected` and writes no verifier.
fn assert_export_fails(circuit: &Circuit, expected: &str) {
    let output = circuit.export(CLI);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!output.status.success(), "export must fail: {expected}");
    assert!(
        stderr.contains(expected),
        "expected {expected:?} in {stderr}"
    );
    assert!(
        !circuit.verifier_dir().exists(),
        "a failed export must not write any verifier"
    );
}

fn not_pinned(circuit: &Circuit, label: &str, file: &str) -> String {
    format!(
        "escrow {label} {} is not pinned by the trusted checksum manifest",
        circuit.artifact().join(file).display()
    )
}

fn mismatched(circuit: &Circuit, label: &str, file: &str) -> String {
    format!(
        "escrow {label} {} does not match its entry in the trusted checksum manifest",
        circuit.artifact().join(file).display()
    )
}

fn edit_metadata(circuit: &Circuit, edit: impl FnOnce(&mut serde_json::Value)) {
    let path = circuit.artifact().join("metadata.json");
    let mut metadata: serde_json::Value =
        serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    edit(&mut metadata);
    fs::write(&path, serde_json::to_vec(&metadata).unwrap()).unwrap();
}

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
    let circuit = circuit("export_checks_the_verifying_key_pin_before_parsing_or_writing");
    fs::write(circuit.artifact().join("vk.bin"), b"corrupt verifying key").unwrap();
    assert_export_fails(&circuit, &mismatched(&circuit, "verifying key", "vk.bin"));
}

#[test]
fn every_key_file_must_be_pinned_under_its_own_path() {
    let circuit = circuit("every_key_file_must_be_pinned_under_its_own_path");
    let line =
        |digest_of: &str, file: &str| format!("{}  escrow/{file}\n", circuit.digest(digest_of));
    let cases = [
        (
            String::new(),
            not_pinned(&circuit, "verifying key", "vk.bin"),
        ),
        // The verifying key's digest listed under another file pins nothing.
        (
            line("vk.bin", "pk.bin") + &line("metadata.json", "metadata.json"),
            not_pinned(&circuit, "verifying key", "vk.bin"),
        ),
        (
            line("vk.bin", "vk.bin") + &line("pk.bin", "pk.bin"),
            not_pinned(&circuit, "setup metadata", "metadata.json"),
        ),
        (
            line("vk.bin", "vk.bin") + &line("metadata.json", "metadata.json"),
            not_pinned(&circuit, "proving key", "pk.bin"),
        ),
        (
            line("vk.bin", "vk.bin")
                + &line("metadata.json", "metadata.json")
                + &format!("{}  escrow/pk.bin\n", "00".repeat(32)),
            mismatched(&circuit, "proving key", "pk.bin"),
        ),
    ];
    for (manifest, expected) in cases {
        circuit.write_checksums(&manifest);
        assert_export_fails(&circuit, &expected);
    }
}

#[test]
fn export_rejects_setup_metadata_that_does_not_describe_the_key() {
    let circuit = circuit("export_rejects_setup_metadata_that_does_not_describe_the_key");
    edit_metadata(&circuit, |metadata| {
        metadata["verifying_key_sha256"] = json!("00".repeat(32));
    });
    circuit.write_checksums(&circuit.pins(" "));
    assert_export_fails(&circuit, "verifying key differs from its setup metadata");
}

#[test]
fn export_derives_standard_setup_metadata_and_pins_exact_proving_key_bytes() {
    let circuit =
        circuit("export_derives_standard_setup_metadata_and_pins_exact_proving_key_bytes");
    // sha256sum binary-mode records are accepted for the actual artifacts.
    circuit.write_checksums(&circuit.pins("*"));
    assert_success(&circuit.export(CLI));
    let source = fs::read_to_string(circuit.committed("escrow.vk.rs")).unwrap();
    let pk_digest = circuit.digest("pk.bin");
    assert!(source.contains("pub const VERIFYINGKEY_INSECURE_TEST_SETUP: bool = true;"));
    assert!(source.contains("pub const VERIFYINGKEY_PROVING_KEY_SHA256: [u8; 32]"));
    assert!(source.contains(&format!("proving_key_sha256\\x00{pk_digest}\\x00")));
    assert!(source.contains("#[unsafe(export_name = \"groth16_solana_vk_setup_"));
    assert!(source.contains("#[cfg(not(feature = \"insecure-test-setup\"))]"));
    assert!(source.contains(&format!(
        "pub const ZOLANA_VK_SHA256: &str = \"{}\";",
        circuit.digest("vk.bin")
    )));
    assert!(circuit.committed("escrow.rs").is_file());
}

#[test]
fn a_sidecar_must_not_relabel_dev_keys_as_production() {
    let circuit = circuit("a_sidecar_must_not_relabel_dev_keys_as_production");
    // Every field that decides the setup kind, consistently relabelled.
    edit_metadata(&circuit, |metadata| {
        metadata["production_safe"] = json!(true);
        metadata["setup_mode"] = json!("phase2-from-ptau");
        metadata["deterministic_rng_seed"] = serde_json::Value::Null;
    });
    let files = PINNED_FILES.map(|file| circuit.artifact().join(file));
    let before = files.each_ref().map(|path| fs::read(path).unwrap());
    assert_export_fails(
        &circuit,
        &mismatched(&circuit, "setup metadata", "metadata.json"),
    );
    let after = files.each_ref().map(|path| fs::read(path).unwrap());
    assert_eq!(
        after, before,
        "rejected export must preserve every setup artifact"
    );
}

#[test]
fn a_swapped_proving_key_is_rejected() {
    let circuit = circuit("a_swapped_proving_key_is_rejected");
    let (other_pk, _) = key_bytes(1);
    fs::write(circuit.artifact().join("pk.bin"), other_pk).unwrap();
    assert_export_fails(&circuit, &mismatched(&circuit, "proving key", "pk.bin"));
    // A manifest that pins the swapped key still pins a pair that does not
    // belong together.
    circuit.write_checksums(&circuit.pins(" "));
    assert_export_fails(
        &circuit,
        &format!(
            "escrow proving key {} does not belong to its verifying key",
            circuit.artifact().join("pk.bin").display()
        ),
    );
}

#[test]
fn export_writes_nothing_unless_every_program_is_pinned() {
    let circuit = circuit("export_writes_nothing_unless_every_program_is_pinned");
    let withdraw = circuit.build_dir().join("withdraw");
    fs::create_dir(&withdraw).unwrap();
    for file in PINNED_FILES.iter().chain(&["digest"]) {
        fs::copy(circuit.artifact().join(file), withdraw.join(file)).unwrap();
    }
    fs::write(
        circuit.build_dir().join("programs.json"),
        serde_json::to_vec(&json!([
            {"name": "escrow", "rust_type": "Escrow", "fields": []},
            {"name": "withdraw", "rust_type": "Withdraw", "fields": []},
        ]))
        .unwrap(),
    )
    .unwrap();
    assert_export_fails(
        &circuit,
        &format!(
            "withdraw verifying key {} is not pinned by the trusted checksum manifest",
            withdraw.join("vk.bin").display()
        ),
    );
}

#[test]
fn program_names_must_be_plain_identifiers() {
    let circuit = circuit("program_names_must_be_plain_identifiers");
    fs::write(
        circuit.build_dir().join("programs.json"),
        serde_json::to_vec(&json!([
            {"name": "../escrow", "rust_type": "Escrow", "fields": []},
        ]))
        .unwrap(),
    )
    .unwrap();
    assert_export_fails(
        &circuit,
        "program name \"../escrow\" is not a plain Rust identifier",
    );
}

#[test]
fn export_names_a_directory_without_compiled_circuits() {
    let circuit = circuit("export_names_a_directory_without_compiled_circuits");
    fs::remove_file(circuit.build_dir().join("programs.json")).unwrap();
    assert_export_fails(
        &circuit,
        &format!(
            "{} holds no compiled circuits",
            circuit.build_dir().display()
        ),
    );
}
