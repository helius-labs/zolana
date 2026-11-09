#[path = "../../src/zk/build/xark_source.rs"]
mod xark_source;
#[path = "zk_keys.rs"]
mod zk_keys;

pub use zk_keys::key_bytes;

use serde_json::json;
use sha2::{Digest, Sha256};
use std::{
    ffi::OsStr,
    fs,
    path::{Path, PathBuf},
    process::{Command, Output},
    sync::OnceLock,
};

const PACKAGE: &str = "zk-cli-fixture";
const CIRCUIT_DIGEST: &str = "cli-fixture-digest";
pub const PINNED_FILES: [&str; 3] = ["vk.bin", "pk.bin", "metadata.json"];

/// The workspace's Xark dependency, parsed by the same rules as the CLI.
fn xark_dependency() -> &'static str {
    static DEPENDENCY: OnceLock<String> = OnceLock::new();
    DEPENDENCY.get_or_init(|| {
        let manifest = Path::new(env!("CARGO_MANIFEST_DIR")).join("../Cargo.toml");
        let output = Command::new("cargo")
            .args([
                "metadata",
                "--no-deps",
                "--format-version",
                "1",
                "--manifest-path",
            ])
            .arg(manifest)
            .output()
            .expect("inspect workspace Xark dependency");
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let metadata: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        let source = metadata["packages"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|package| package["dependencies"].as_array())
            .flatten()
            .find(|dependency| dependency["name"] == "xark")
            .and_then(|dependency| dependency["source"].as_str())
            .expect("workspace declares a Git Xark dependency");
        xark_source::pinned_git_dependency(source).unwrap()
    })
}

pub struct Circuit {
    pub dir: PathBuf,
}

impl Circuit {
    pub fn new(root: &Path, name: &str) -> Self {
        let dir = root.join("zk_cli").join(name);
        if dir.exists() {
            fs::remove_dir_all(&dir).unwrap();
        }
        fs::create_dir_all(dir.join("src")).unwrap();
        fs::write(
            dir.join("Cargo.toml"),
            format!(
                "[package]\nname = \"{PACKAGE}\"\nversion = \"0.1.0\"\nedition = \"2024\"\n\
             [workspace]\n\
             [features]\ncircuits = []\nbuild-circuits = []\nsbf-must-not-run = []\n\
             [dependencies]\nxark = {{ {}, optional = true }}\n",
                xark_dependency(),
            ),
        )
        .unwrap();
        // Discovery is a native test, independently of compiling the cached circuit.
        fs::write(
            dir.join("src/lib.rs"),
            r##"
#[cfg(feature = "sbf-must-not-run")]
compile_error!("check mode must skip the SBF build");

#[test]
fn __zk_export() {
    let directory = std::env::var_os("ZOLANA_PROGRAM_EXPORT_DIR").unwrap();
    std::fs::write(std::path::Path::new(&directory).join("escrow.json"),
        r#"{"name":"escrow","rust_type":"Escrow","fields":[]}"#).unwrap();
}
"##,
        )
        .unwrap();
        fs::copy(
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../Cargo.lock"),
            dir.join("Cargo.lock"),
        )
        .unwrap();
        let circuit = Self { dir };
        fs::create_dir_all(circuit.artifact()).unwrap();
        fs::write(
            circuit.build_dir().join("programs.json"),
            serde_json::to_vec(&json!([{"name":"escrow", "rust_type":"Escrow", "fields":[]}]))
                .unwrap(),
        )
        .unwrap();
        // --skip-r1cs must reuse this output rather than invoking the compiler.
        fs::write(
            circuit.artifact().join("circuit.xbc"),
            b"cached compiler output",
        )
        .unwrap();
        fs::write(circuit.artifact().join("digest"), CIRCUIT_DIGEST).unwrap();
        let (pk, vk) = key_bytes(0);
        fs::write(circuit.artifact().join("pk.bin"), pk).unwrap();
        fs::write(circuit.artifact().join("vk.bin"), &vk).unwrap();
        fs::write(
            circuit.artifact().join("metadata.json"),
            serde_json::to_vec(&json!({
                "protocol": "groth16", "curve": "bn254", "setup_mode": "single-party",
                "production_safe": false, "digest": CIRCUIT_DIGEST,
                "verifying_key_sha256": format!("{:x}", Sha256::digest(&vk)),
                "deterministic_rng_seed": 0, "r1cs_form": "reduced", "qap_domain_size": 4,
                "backend_version": "0.3.0"
            }))
            .unwrap(),
        )
        .unwrap();
        circuit.write_checksums(&circuit.pins(" "));
        circuit
    }

    pub fn build_dir(&self) -> PathBuf {
        self.dir.join("target/zk").join(PACKAGE)
    }
    pub fn artifact(&self) -> PathBuf {
        self.build_dir().join("escrow")
    }
    pub fn verifier_dir(&self) -> PathBuf {
        self.dir.join("src/verifier")
    }
    pub fn committed(&self, file: &str) -> PathBuf {
        self.verifier_dir().join(file)
    }
    pub fn checksums(&self) -> PathBuf {
        self.build_dir().join("keys.sha256")
    }
    /// The sha256 of an artifact file, as a manifest lists it.
    pub fn digest(&self, file: &str) -> String {
        format!(
            "{:x}",
            Sha256::digest(fs::read(self.artifact().join(file)).unwrap())
        )
    }
    /// Manifest lines pinning every key file the export reads; `mode` is
    /// sha256sum's text (` `) or binary (`*`) marker.
    pub fn pins(&self, mode: &str) -> String {
        PINNED_FILES
            .iter()
            .map(|file| format!("{} {mode}escrow/{file}\n", self.digest(file)))
            .collect()
    }
    pub fn write_checksums(&self, contents: &str) {
        fs::write(self.checksums(), contents).unwrap();
    }

    pub fn command(&self, executable: impl AsRef<OsStr>) -> Command {
        let mut command = Command::new(executable);
        command.env("CARGO_TARGET_DIR", self.dir.join("target"));
        command
    }

    pub fn export(&self, executable: impl AsRef<OsStr>) -> Output {
        self.command(executable)
            .args(["zk", "export-verifier", "--manifest-path"])
            .arg(self.dir.join("Cargo.toml"))
            .arg("--out")
            .arg(self.build_dir())
            .arg("--checksums")
            .arg(self.checksums())
            .output()
            .unwrap()
    }
}

impl Drop for Circuit {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.dir);
    }
}

pub fn assert_success(output: &Output) {
    assert!(
        output.status.success(),
        "stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}
