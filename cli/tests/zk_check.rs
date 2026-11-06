#[path = "support/zk_fixture.rs"]
mod fixture;

use fixture::{assert_success, Circuit};
use std::{fs, path::Path, process::Output};

const CLI: &str = env!("CARGO_BIN_EXE_zolana");

/// Runs `--check` without `--skip-wasm`, so check mode itself must skip the
/// wasm build (the fixture has no wasm feature for wasm-pack to build).
fn check(circuit: &Circuit, build_program: bool) -> Output {
    let mut command = circuit.command(CLI);
    if build_program {
        command.args(["build-zk-program", "--sbf-features", "sbf-must-not-run"]);
    } else {
        command.args(["zk", "compile"]);
    }
    command
        .args([
            "--check",
            "--test",
            "--skip-r1cs",
            "--skip-keys",
            "--manifest-path",
        ])
        .arg(circuit.dir.join("Cargo.toml"))
        .output()
        .unwrap()
}

#[test]
fn check_rejects_missing_modules_without_writing() {
    let circuit = Circuit::new(
        Path::new(env!("CARGO_TARGET_TMPDIR")),
        "check_rejects_missing_modules_without_writing",
    );
    // A crate opts into verifiers with `src/verifier`; an empty one lists none.
    fs::create_dir_all(circuit.verifier_dir()).unwrap();
    let output = check(&circuit, false);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !output.status.success(),
        "check must reject missing committed verifiers"
    );
    assert!(
        stderr.contains(&format!(
            "missing: {}",
            circuit.committed("escrow.vk.rs").display()
        )) && stderr.contains(&format!(
            "missing: {}",
            circuit.committed("escrow.rs").display()
        )),
        "{stderr}"
    );
    assert_eq!(
        fs::read_dir(circuit.verifier_dir()).unwrap().count(),
        0,
        "check must not create committed modules"
    );
}

#[test]
fn check_skips_verifiers_for_a_crate_without_a_verifier_directory() {
    let circuit = Circuit::new(
        Path::new(env!("CARGO_TARGET_TMPDIR")),
        "check_skips_verifiers_for_a_crate_without_a_verifier_directory",
    );
    let output = check(&circuit, false);
    assert_success(&output);
    assert!(
        !circuit.verifier_dir().exists(),
        "check must not create a verifier directory"
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
    fs::write(circuit.committed("removed.vk.rs"), "old key\n").unwrap();
    let before = ["escrow.vk.rs", "escrow.rs", "unrelated.rs", "removed.vk.rs"]
        .map(|name| fs::read(circuit.committed(name)).unwrap());
    let output = check(&circuit, false);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!output.status.success(), "check must reject a changed key");
    assert!(
        stderr.contains(&format!(
            "stale: {}",
            circuit.committed("escrow.vk.rs").display()
        )) && stderr.contains(&format!(
            "orphan: {}",
            circuit.committed("removed.vk.rs").display()
        )) && !stderr.contains("unrelated.rs"),
        "{stderr}"
    );
    let after = ["escrow.vk.rs", "escrow.rs", "unrelated.rs", "removed.vk.rs"]
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
    assert_success(&check(&circuit, true));
    let after = files.each_ref().map(|path| fs::read(path).unwrap());
    assert_eq!(
        after, before,
        "successful check must preserve verifier and setup bytes"
    );
    assert!(
        !circuit.build_dir().join("wasm").exists(),
        "check must skip wasm"
    );
}
