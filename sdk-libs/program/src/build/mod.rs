//! Builds the existing program crate through generated Xark entrypoints.

mod metadata;
mod options;
mod verifier;

pub use metadata::{export_program, ProgramMetadata, PublicField, PublicFieldKind, PublicInputLayout};
pub use options::*;

use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{fmt, fs, path::{Path, PathBuf}, process::Command};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SetupKind { InsecureTest, SingleParty, Production }

#[derive(Debug)]
pub enum BuildError { NoCircuits(PathBuf), NothingToCompile, Message(String) }
impl fmt::Display for BuildError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoCircuits(path) => write!(f, "no program entries in {}", path.display()),
            Self::NothingToCompile => f.write_str("no build step selected"),
            Self::Message(message) => f.write_str(message),
        }
    }
}
impl std::error::Error for BuildError {}
impl From<std::io::Error> for BuildError { fn from(e: std::io::Error) -> Self { error(e) } }
impl From<serde_json::Error> for BuildError { fn from(e: serde_json::Error) -> Self { error(e) } }
type Result<T> = std::result::Result<T, BuildError>;
fn error(e: impl fmt::Display) -> BuildError { BuildError::Message(e.to_string()) }

struct Package { name: String, manifest: PathBuf, root: PathBuf, target: PathBuf }

fn run(command: &mut Command) -> Result<()> {
    let display = format!("{command:?}");
    let status = command.status().map_err(|e| error(format!("{display}: {e}")))?;
    if status.success() { Ok(()) } else { Err(error(format!("{display} failed: {status}"))) }
}

fn package(selection: &PackageSelection) -> Result<Package> {
    let mut command = Command::new("cargo");
    command.args(["metadata", "--no-deps", "--format-version", "1"]);
    if let Some(path) = &selection.manifest_path { command.arg("--manifest-path").arg(path); }
    let output = command.output()?;
    if !output.status.success() { return Err(error(String::from_utf8_lossy(&output.stderr))); }
    let data: Value = serde_json::from_slice(&output.stdout)?;
    let packages = data["packages"].as_array().ok_or_else(|| error("cargo returned no packages"))?;
    let manifest = selection.manifest_path.as_ref().map(fs::canonicalize).transpose()?;
    let selected = if let Some(name) = &selection.package {
        packages.iter().find(|p| p["name"].as_str() == Some(name))
    } else if let Some(manifest) = &manifest {
        packages.iter().find(|p| p["manifest_path"].as_str().is_some_and(|p| Path::new(p) == manifest))
    } else {
        let current = std::env::current_dir()?;
        packages.iter().filter(|p| p["manifest_path"].as_str().is_some_and(|p| current.starts_with(Path::new(p).parent().unwrap())))
            .max_by_key(|p| p["manifest_path"].as_str().unwrap().len())
    }.ok_or_else(|| error("select a circuit package with -p or --manifest-path"))?;
    Ok(Package { name: selected["name"].as_str().unwrap().into(), manifest: selected["manifest_path"].as_str().unwrap().into(),
        root: data["workspace_root"].as_str().unwrap().into(), target: data["target_directory"].as_str().unwrap().into() })
}

fn output_dir(package: &Package, out: &Option<PathBuf>) -> PathBuf {
    out.clone().unwrap_or_else(|| package.target.join("zk").join(&package.name))
}

fn compiler(package: &Package) -> Result<PathBuf> {
    let path = std::env::var_os("XARK").map(PathBuf::from).unwrap_or_else(|| {
        let local = package.root.join(".tools/xark/target/release/xark");
        if local.is_file() { local } else { PathBuf::from("xark") }
    });
    let version = Command::new(&path).arg("--version").output()
        .map_err(|e| error(format!("Xark is required: run tools/xark/build.sh or set XARK ({e})")))?;
    let text = String::from_utf8_lossy(&version.stdout);
    if !version.status.success() || !text.contains("0.3.0") || !text.contains("b443d83") {
        return Err(error(format!("expected Xark 0.3.0 at b443d83, got {text}")));
    }
    Ok(path)
}

fn discover(package: &Package, out: &Path, features: &str) -> Result<Vec<ProgramMetadata>> {
    let metadata = out.join(".metadata");
    fs::create_dir_all(&metadata)?;
    for file in fs::read_dir(&metadata)? {
        let file = file?.path();
        if file.extension().is_some_and(|extension| extension == "json") { fs::remove_file(file)?; }
    }
    let features = format!("{features},r1cs-export");
    run(Command::new("cargo").args(["test", "--release", "--lib", "--manifest-path"]).arg(&package.manifest)
        .args(["--features", &features, "__zk_export", "--", "--nocapture"])
        .env("ZOLANA_PROGRAM_EXPORT_DIR", fs::canonicalize(&metadata)?))?;
    let mut programs = Vec::new();
    for file in fs::read_dir(&metadata)? {
        let path = file?.path();
        if path.extension().is_some_and(|extension| extension == "json") {
            programs.push(serde_json::from_slice::<ProgramMetadata>(&fs::read(path)?)?);
        }
    }
    programs.sort_by(|a, b| a.name.cmp(&b.name));
    if programs.is_empty() { return Err(BuildError::NoCircuits(package.manifest.clone())); }
    fs::write(out.join("programs.json"), serde_json::to_vec_pretty(&programs)?)?;
    Ok(programs)
}

fn entries(out: &Path) -> Result<Vec<ProgramMetadata>> {
    Ok(serde_json::from_slice(&fs::read(out.join("programs.json"))?)?)
}

fn write_if_changed(path: &Path, bytes: impl AsRef<[u8]>) -> Result<()> {
    let bytes = bytes.as_ref();
    if fs::read(path).ok().as_deref() != Some(bytes) { fs::write(path, bytes)?; }
    Ok(())
}

fn entry(package: &Package, out: &Path, program: &ProgramMetadata, features: &str) -> Result<PathBuf> {
    let dir = out.join(".entries").join(&program.name);
    fs::create_dir_all(dir.join("src"))?;
    let path = serde_json::to_string(package.manifest.parent().unwrap().to_str().ok_or_else(|| error("non UTF-8 crate path"))?)?;
    let features = features.split(',').filter(|feature| !feature.is_empty())
        .map(serde_json::to_string).collect::<std::result::Result<Vec<_>, _>>()?.join(", ");
    let manifest = format!("[package]\nname = \"zolana-generated-{}-{}\"\nversion = \"0.1.0\"\nedition = \"2024\"\npublish = false\n\n[workspace]\n\n[lib]\ncrate-type = [\"cdylib\", \"rlib\"]\n\n[dependencies]\nprogram = {{ package = \"{}\", path = {path}, features = [{features}] }}\nxark = {{ git = \"https://github.com/blueshift-gg/xark\", rev = \"b443d83ea8ec7f2253610887e9690623ad048aef\" }}\n\n[lints.rust]\nunexpected_cfgs = {{ level = \"warn\", check-cfg = [\"cfg(xark)\", \"cfg(xark_client)\"] }}\n", package.name, program.name, package.name);
    write_if_changed(&dir.join("Cargo.toml"), manifest)?;
    let source = format!("use xark::prelude::*;\n\n#[circuit]\npub fn r#{}(program: Private<program::{}>, public_hash: Public<Field>) {{\n    let checked = program.execute().expect(\"valid program transaction\");\n    require_eq(*checked.public_hash(), public_hash);\n}}\n", program.name, program.rust_type);
    write_if_changed(&dir.join("src/lib.rs"), source)?;
    let lock = package.root.join("Cargo.lock");
    if lock.is_file() && !dir.join("Cargo.lock").is_file() { fs::copy(lock, dir.join("Cargo.lock"))?; }
    Ok(dir)
}

pub fn compile(options: &CompileOptions) -> Result<()> {
    if options.skip_r1cs && options.skip_keys && options.skip_wasm { return Err(BuildError::NothingToCompile); }
    let package = package(&options.package)?;
    let out = output_dir(&package, &options.r1cs_out);
    fs::create_dir_all(&out)?;
    let out = fs::canonicalize(out)?;
    let programs = match discover(&package, &out, &options.r1cs_features) {
        Ok(programs) => programs,
        Err(BuildError::NoCircuits(_)) => return compile_plain(&package, &out, options),
        Err(error) => return Err(error),
    };
    let xark = compiler(&package)?;
    for program in &programs {
        let artifact = out.join(&program.name);
        let entry = entry(&package, &out, program, &options.r1cs_features)?;
        if !options.skip_r1cs || !artifact.join("circuit.xbc").is_file() {
            run(Command::new(&xark).arg("build").arg(&entry).arg("--out").arg(&artifact))?;
        }
        if !options.skip_keys { setup_one(&xark, &artifact, options.test)?; }
        if !options.skip_wasm && !options.check {
            let client_out = options.wasm_out.clone().unwrap_or_else(|| out.join("client")).join(&program.name);
            fs::create_dir_all(&client_out)?;
            run(Command::new(&xark).arg("client").arg(&artifact).arg("--out").arg(client_out))?;
        }
        if !options.skip_keys && package.manifest.parent().unwrap().join("src/verifier").is_dir() {
            verifier::export(&package, &artifact, program, options.check)?;
        }
    }
    if !options.skip_wasm && !options.check { bridge(&package, &out, options)?; }
    Ok(())
}

fn bridge(package: &Package, out: &Path, options: &CompileOptions) -> Result<()> {
    let directory = options.wasm_out.clone().unwrap_or_else(|| out.join("wasm"));
    let directory = std::path::absolute(directory)?;
    let target = match options.wasm_target { WasmTarget::Web => "web", WasmTarget::Nodejs => "nodejs" };
    let mut command = Command::new("wasm-pack");
    command.arg("build").arg(package.manifest.parent().unwrap())
        .args(["--release", "--target", target, "--no-pack", "--out-dir"]).arg(directory);
    if !options.wasm_opt { command.arg("--no-opt"); }
    command.arg("--features").arg(&options.wasm_features);
    run(&mut command)
}

fn setup_one(xark: &Path, artifact: &Path, test: bool) -> Result<()> {
    let digest = fs::read_to_string(artifact.join("digest"))?;
    if let Ok(bytes) = fs::read(artifact.join("metadata.json")) {
        let old: Value = serde_json::from_slice(&bytes)?;
        if old["digest"].as_str().is_some_and(|old| old == digest.trim()) && artifact.join("pk.bin").is_file() {
            return Ok(());
        }
        if old["production_safe"].as_bool() == Some(true) { return Err(error("the production key belongs to a different circuit; run a new ceremony")); }
    }
    let mut cmd = Command::new(xark);
    cmd.arg("setup").arg(artifact);
    if test { cmd.args(["--insecure-dev-mode", "--deterministic-rng", "0", "--domain", "radix2"]); }
    run(&mut cmd)
}

pub fn setup(options: &SetupOptions) -> Result<()> {
    let package = package(&options.package)?;
    let out = output_dir(&package, &options.out);
    let xark = compiler(&package)?;
    if !options.r1cs.is_empty() { return Err(error("Xark setup takes compiled circuit directories; select the program package")); }
    for program in entries(&out)? { setup_one(&xark, &out.join(program.name), options.test)?; }
    Ok(())
}

pub fn import(options: &ImportOptions) -> Result<()> {
    let _ = options;
    Err(error("snarkjs zkeys are not Xark keys; use the Xark ceremony output for the compiled circuit"))
}

pub fn export_verifier(options: &ExportVerifierOptions) -> Result<()> {
    let package = package(&options.package)?;
    let out = output_dir(&package, &None);
    if !options.pk.is_empty() { return Err(error("export uses the Xark verifying keys alongside each compiled circuit")); }
    let sums = fs::read_to_string(&options.checksums)?;
    for program in entries(&out)? {
        let artifact = out.join(&program.name);
        let key = fs::read(artifact.join("vk.bin"))?;
        let digest = format!("{:x}", Sha256::digest(&key));
        if !sums.lines().any(|line| line.split_whitespace().next() == Some(&digest)) { return Err(error(format!("{} verifying key is not in the trusted checksum manifest", program.name))); }
        verifier::export(&package, &artifact, &program, false)?;
    }
    Ok(())
}

pub fn build(options: &BuildOptions) -> Result<()> {
    compile(&options.compile)?;
    if !options.sbf.skip_sbf {
        let package = package(&options.compile.package)?;
        let mut command = Command::new("cargo");
        command.arg("build-sbf").arg("--manifest-path").arg(package.manifest);
        if let Some(out) = &options.sbf.sbf_out_dir { command.arg("--sbf-out-dir").arg(out); }
        if let Some(features) = &options.sbf.sbf_features { command.args(["--", "--features", features]); }
        run(&mut command)?;
    }
    Ok(())
}

fn compile_plain(package: &Package, out: &Path, options: &CompileOptions) -> Result<()> {
    let xark = compiler(package)?;
    if !options.skip_r1cs || !out.join("circuit.xbc").is_file() {
        run(Command::new(&xark).arg("build").arg(package.manifest.parent().unwrap()).arg("--out").arg(out))?;
    }
    let schema: Value = serde_json::from_slice(&fs::read(out.join("schema.json"))?)?;
    let name = schema["circuit"].as_str().ok_or_else(|| error("Xark schema has no circuit name"))?;
    if !options.skip_keys {
        setup_one(&xark, out, options.test)?;
        verifier::export_plain(package, out, name, options.check)?;
    }
    if !options.skip_wasm && !options.check {
        run(Command::new(&xark).arg("client").arg(out).arg("--out").arg(options.wasm_out.clone().unwrap_or_else(|| out.join("client"))))?;
    }
    Ok(())
}
