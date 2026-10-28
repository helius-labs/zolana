#![allow(dead_code)]

use ark_bn254::Fr;
use ark_serialize::{CanonicalSerialize, Compress};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use serde_json::json;
use sha2::{Digest, Sha256};
use std::{
    ffi::OsStr,
    fs,
    path::{Path, PathBuf},
    process::{Command, Output},
    sync::OnceLock,
};
use xark_groth16::{
    DomainKind,
    r1cs::{ConstraintSource, RowChunk, VarLayout, Window},
};

const PACKAGE: &str = "zk-cli-fixture";
const CIRCUIT_DIGEST: &str = "cli-fixture-digest";

struct EqualityCircuit(VarLayout);

impl ConstraintSource for EqualityCircuit {
    fn layout(&self) -> &VarLayout {
        &self.0
    }
    fn num_constraints(&self) -> usize {
        1
    }
    fn windows(&self, _: usize) -> Vec<Window> {
        vec![Window {
            rows: 0..1,
            handle: 0..1,
        }]
    }
    fn expand(&self, window: &Window, out: &mut RowChunk) {
        out.clear(window.rows.start);
        // public * 1 = private
        for column in [1, 0, 2] {
            out.push_lc([(column, Fr::from(1u64))]);
        }
    }
}

/// Real current-format test keys for a one-row equality constraint.
pub fn key_bytes() -> (Vec<u8>, Vec<u8>) {
    let source = EqualityCircuit(VarLayout::new([(0, true), (1, false)]));
    let mut pk = Vec::new();
    let vk = xark_groth16::setup::dev_setup(
        &source,
        &mut ChaCha20Rng::seed_from_u64(0),
        &mut pk,
        Compress::Yes,
        DomainKind::Radix2,
    )
    .unwrap();
    let mut bytes = Vec::new();
    vk.serialize_compressed(&mut bytes).unwrap();
    (pk, bytes)
}

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
        let dependency = metadata["packages"]
            .as_array()
            .unwrap()
            .iter()
            .flat_map(|package| package["dependencies"].as_array().unwrap())
            .find(|dependency| dependency["name"] == "xark")
            .expect("workspace declares Xark");
        if let Some(path) = dependency["path"].as_str() {
            return format!("path = {}", serde_json::to_string(path).unwrap());
        }
        let source = dependency["source"]
            .as_str()
            .and_then(|source| source.strip_prefix("git+"))
            .expect("workspace uses a path or pinned Git Xark dependency");
        let (url, query) = source
            .split_once('?')
            .expect("Xark Git dependency has a revision");
        let revision = query
            .split('#')
            .next()
            .unwrap()
            .split('&')
            .find_map(|parameter| parameter.strip_prefix("rev="))
            .filter(|revision| !revision.is_empty())
            .expect("Xark Git dependency pins a revision");
        format!(
            "git = {}, rev = {}",
            serde_json::to_string(url).unwrap(),
            serde_json::to_string(revision).unwrap()
        )
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
             [features]\ncircuits = []\nr1cs-export = []\nsbf-must-not-run = []\n\
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
        let (pk, vk) = key_bytes();
        fs::write(circuit.artifact().join("pk.bin"), pk).unwrap();
        fs::write(circuit.artifact().join("vk.bin"), &vk).unwrap();
        fs::write(
            circuit.artifact().join("metadata.json"),
            serde_json::to_vec(&json!({
                "protocol": "groth16", "curve": "bn254", "setup_mode": "insecure-dev-mode",
                "production_safe": false, "digest": CIRCUIT_DIGEST,
                "verifying_key_sha256": format!("{:x}", Sha256::digest(&vk)),
                "deterministic_rng_seed": 0, "r1cs_form": "reduced", "qap_domain_size": 4,
                "backend_version": "0.3.0"
            }))
            .unwrap(),
        )
        .unwrap();
        circuit.write_checksums(&format!("{}  escrow/vk.bin\n", circuit.vk_digest()));
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
    pub fn vk_digest(&self) -> String {
        format!(
            "{:x}",
            Sha256::digest(fs::read(self.artifact().join("vk.bin")).unwrap())
        )
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

    pub fn check(&self, executable: impl AsRef<OsStr>, build_program: bool) -> Output {
        let mut command = self.command(executable);
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
                "--skip-wasm",
                "--manifest-path",
            ])
            .arg(self.dir.join("Cargo.toml"))
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
