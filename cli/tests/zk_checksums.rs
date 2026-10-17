use std::{fs, path::PathBuf, process::Command};

use sha2::{Digest, Sha256};
use zolana_program::{Groth16Keys, ProvingKey, VerifyingKey};

#[test]
fn export_checks_the_pinned_image_before_writing_a_verifier() {
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("zk_checksums");
    if dir.exists() {
        fs::remove_dir_all(&dir).unwrap();
    }
    fs::create_dir_all(dir.join("src")).unwrap();
    fs::write(
        dir.join("Cargo.toml"),
        "[package]\nname = \"checksum-fixture\"\nversion = \"0.1.0\"\nedition = \"2021\"\n[workspace]\n",
    )
    .unwrap();
    fs::write(dir.join("src/lib.rs"), "").unwrap();
    let build = dir.join("target/zk/checksum-fixture");
    fs::create_dir_all(&build).unwrap();
    fs::write(
        build.join("test.verifier.rs"),
        "include!(\"test.vk.rs\");\n",
    )
    .unwrap();
    let key = build.join("test.pk");
    let proving_key = ProvingKey {
        vk: VerifyingKey {
            alpha_g1: Default::default(),
            beta_g2: Default::default(),
            gamma_g2: Default::default(),
            delta_g2: Default::default(),
            gamma_abc_g1: vec![Default::default(); 2],
        },
        beta_g1: Default::default(),
        delta_g1: Default::default(),
        a_query: Vec::new(),
        b_g1_query: Vec::new(),
        b_g2_query: Vec::new(),
        h_query: Vec::new(),
        l_query: Vec::new(),
    };
    let bytes = Groth16Keys::from(proving_key).to_image_bytes();
    let digest = hex::encode(Sha256::digest(&bytes));
    let manifest = build.join("keys.sha256");
    let pinned = format!("{digest}  test.pk\n");
    fs::write(&key, &bytes).unwrap();
    fs::write(&manifest, &pinned).unwrap();
    let export = |setup: &str| {
        Command::new(env!("CARGO_BIN_EXE_zolana"))
            .args(["zk", "export-verifier", "--setup", setup, "--manifest-path"])
            .arg(dir.join("Cargo.toml"))
            .arg("--checksums")
            .arg(&manifest)
            .arg(&key)
            .env("CARGO_TARGET_DIR", dir.join("target"))
            .output()
            .unwrap()
    };

    let missing = Command::new(env!("CARGO_BIN_EXE_zolana"))
        .args(["zk", "export-verifier", "--setup", "test"])
        .output()
        .unwrap();
    assert!(!missing.status.success());
    assert!(String::from_utf8_lossy(&missing.stderr).contains("--checksums"));

    // A corrupt image must fail at the checksum, before parsing or exporting it.
    fs::write(&key, b"corrupt key image").unwrap();
    let output = export("test");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!output.status.success(), "{stderr}");
    assert!(
        stderr.contains("does not match its sha256 checksum"),
        "{stderr}"
    );
    assert!(!dir.join("src/verifier").exists());
    assert!(!build.join("test.vk.rs").exists());

    fs::write(&key, &bytes).unwrap();
    fs::write(build.join("other.pk"), &bytes).unwrap();
    for (contents, expected) in [
        (String::new(), "contains no key checksums"),
        (format!("{digest}  other.pk\n"), "has no checksum in"),
        ("invalid  test.pk\n".into(), "invalid SHA-256"),
        (format!("{pinned}{pinned}"), "duplicate checksum"),
    ] {
        fs::write(&manifest, contents).unwrap();
        let output = export("test");
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(!output.status.success(), "{stderr}");
        assert!(stderr.contains(expected), "{stderr}");
        assert!(!dir.join("src/verifier").exists());
    }

    fs::write(&manifest, &pinned).unwrap();
    let output = export("production");
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr)
        .contains("production export requires an imported ceremony zkey"));
    assert!(!dir.join("src/verifier").exists());

    // Binary-mode sha256sum manifests are accepted, relative to the manifest.
    fs::write(&manifest, format!("{digest} *test.pk\n")).unwrap();
    let output = export("test");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let verifier = fs::read_to_string(dir.join("src/verifier/test.vk.rs")).unwrap();
    assert!(verifier.contains(&digest));
}
