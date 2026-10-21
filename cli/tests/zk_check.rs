use std::{
    fs,
    path::{Path, PathBuf},
    process::{Command, Output},
};

const PACKAGE: &str = "zk-check-fixture";
const GLUE: &str = "include!(\"escrow.vk.rs\");\n";
const TEST_KEY: &str = "pub const VERIFYINGKEY_INSECURE_TEST_SETUP: bool = true;\n";
const PRODUCTION_KEY: &str = "pub const VERIFYINGKEY_INSECURE_TEST_SETUP: bool = false;\n";
const LISTING: &str = "pub mod escrow;\n";

struct Circuit {
    dir: PathBuf,
}

impl Circuit {
    fn new(name: &str) -> Self {
        let dir = Path::new(env!("CARGO_TARGET_TMPDIR"))
            .join("zk_check")
            .join(name);
        if dir.exists() {
            fs::remove_dir_all(&dir).expect("clear the fixture");
        }
        fs::create_dir_all(dir.join("src")).expect("create the fixture");
        fs::write(
            dir.join("Cargo.toml"),
            format!(
                "[package]\nname = \"{PACKAGE}\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n[workspace]\n"
            ),
        )
        .expect("write the fixture manifest");
        fs::write(dir.join("src").join("lib.rs"), "").expect("write the fixture lib");
        let circuit = Self { dir };
        fs::create_dir_all(circuit.build_dir()).expect("create the build directory");
        circuit.build("escrow.verifier.rs", GLUE);
        circuit.build("escrow.vk.rs", TEST_KEY);
        circuit
    }

    fn build_dir(&self) -> PathBuf {
        self.dir.join("target").join("zk").join(PACKAGE)
    }

    fn verifier_dir(&self) -> PathBuf {
        self.dir.join("src").join("verifier")
    }

    fn committed(&self, file: &str) -> PathBuf {
        self.verifier_dir().join(file)
    }

    fn build(&self, file: &str, contents: &str) {
        fs::write(self.build_dir().join(file), contents).expect("write a build output");
    }

    fn commit(&self, file: &str, contents: &str) {
        fs::create_dir_all(self.verifier_dir()).expect("create the verifier directory");
        fs::write(self.committed(file), contents).expect("write a committed module");
    }

    fn check(&self) -> Output {
        Command::new(env!("CARGO_BIN_EXE_zolana"))
            .args([
                "zk",
                "compile",
                "--check",
                "--skip-r1cs",
                "--skip-keys",
                "--manifest-path",
            ])
            .arg(self.dir.join("Cargo.toml"))
            .env("CARGO_TARGET_DIR", self.dir.join("target"))
            .output()
            .expect("run zolana")
    }
}

#[test]
fn check_lists_missing_modules_without_writing() {
    let circuit = Circuit::new("check_lists_missing_modules_without_writing");
    let output = circuit.check();
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!output.status.success(), "{stderr}");
    for file in ["escrow.rs", "escrow.vk.rs", "mod.rs"] {
        let expected = format!("{}: missing", circuit.committed(file).display());
        assert!(stderr.contains(&expected), "{stderr}");
    }
    assert!(!circuit.verifier_dir().exists());
}

#[test]
fn check_lists_differing_and_ungenerated_modules() {
    let circuit = Circuit::new("check_lists_differing_and_ungenerated_modules");
    circuit.commit("escrow.rs", GLUE);
    circuit.commit("escrow.vk.rs", "stale");
    circuit.commit("mod.rs", LISTING);
    circuit.commit("withdraw.rs", GLUE);
    let output = circuit.check();
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!output.status.success(), "{stderr}");
    let differs = format!(
        "{}: differs from the generated module",
        circuit.committed("escrow.vk.rs").display()
    );
    let ungenerated = format!(
        "{}: not generated",
        circuit.committed("withdraw.rs").display()
    );
    assert!(stderr.contains(&differs), "{stderr}");
    assert!(stderr.contains(&ungenerated), "{stderr}");
    for file in ["escrow.rs", "mod.rs"] {
        let listed = format!("{}:", circuit.committed(file).display());
        assert!(!stderr.contains(&listed), "{stderr}");
    }
    assert_eq!(
        fs::read_to_string(circuit.committed("escrow.vk.rs")).expect("read the committed key"),
        "stale"
    );
}

#[test]
fn check_passes_on_committed_modules_and_keeps_a_production_key() {
    let circuit = Circuit::new("check_passes_on_committed_modules_and_keeps_a_production_key");
    circuit.commit("escrow.rs", GLUE);
    circuit.commit("escrow.vk.rs", PRODUCTION_KEY);
    circuit.commit("mod.rs", LISTING);
    let output = circuit.check();
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(output.status.success(), "{stdout}\n{stderr}");
    let kept = format!(
        "{}: production key kept",
        circuit.committed("escrow.vk.rs").display()
    );
    assert!(stdout.contains(&kept), "{stdout}");
}
