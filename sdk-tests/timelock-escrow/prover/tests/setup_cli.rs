use std::{fs, path::Path, process::Command};

#[derive(Debug, PartialEq, Eq)]
struct EmittedKey {
    insecure_test_setup: bool,
    compile_error: bool,
    warning_header: bool,
}

fn emitted_key(dir: &Path, insecure_test_keys: bool) -> EmittedKey {
    let rust_vk = dir.join("withdraw.rs");
    let mut setup = Command::new(env!("CARGO_BIN_EXE_timelock-escrow-prover-setup"));
    setup
        .arg("withdraw")
        .arg(dir)
        .arg("--rust-vk")
        .arg(&rust_vk);
    if insecure_test_keys {
        setup.arg("--insecure-test-keys");
    }
    let status = setup.status().expect("run the setup binary");
    assert!(status.success(), "setup failed: {status}");
    let source = fs::read_to_string(&rust_vk).expect("read the emitted verifying key");
    EmittedKey {
        insecure_test_setup: source
            .contains("pub const VERIFYINGKEY_INSECURE_TEST_SETUP: bool = true;"),
        compile_error: source.contains("compile_error!"),
        warning_header: source.starts_with("// INSECURE TEST KEY"),
    }
}

#[test]
fn only_a_fixed_seed_setup_emits_an_insecure_test_key() {
    let root = Path::new(env!("CARGO_TARGET_TMPDIR")).join("setup_cli");

    assert_eq!(
        [
            emitted_key(&root.join("system"), false),
            emitted_key(&root.join("fixed_seed"), true),
        ],
        [
            EmittedKey {
                insecure_test_setup: false,
                compile_error: false,
                warning_header: false,
            },
            EmittedKey {
                insecure_test_setup: true,
                compile_error: true,
                warning_header: true,
            },
        ]
    );
}
