//! Builds the existing program crate through generated Xark entrypoints.

mod key_cache;
mod options;
mod verifier;
mod wasm_cache;
mod xark_source;

pub use options::*;
use spr_program::build::{ProgramMetadata, PublicFieldKind};

use serde_json::Value;
use std::{
    fmt, fs,
    path::{Path, PathBuf},
    process::Command,
};

#[derive(Debug)]
pub enum BuildError {
    NoCircuits(PathBuf),
    NothingToCompile,
    Io {
        path: PathBuf,
        source: std::io::Error,
    },
    Message(String),
}
impl fmt::Display for BuildError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoCircuits(path) => write!(f, "no program entries in {}", path.display()),
            Self::NothingToCompile => f.write_str("no build step selected"),
            Self::Io { path, source } => write!(f, "{}: {source}", path.display()),
            Self::Message(message) => f.write_str(message),
        }
    }
}
impl std::error::Error for BuildError {}
impl From<std::io::Error> for BuildError {
    fn from(e: std::io::Error) -> Self {
        error(e)
    }
}
impl From<serde_json::Error> for BuildError {
    fn from(e: serde_json::Error) -> Self {
        error(e)
    }
}
type Result<T> = std::result::Result<T, BuildError>;
fn error(e: impl fmt::Display) -> BuildError {
    BuildError::Message(e.to_string())
}

fn read(path: &Path) -> Result<Vec<u8>> {
    fs::read(path).map_err(|source| BuildError::Io {
        path: path.to_path_buf(),
        source,
    })
}

fn json_str<'a>(value: &'a Value, key: &str) -> Result<&'a str> {
    value[key]
        .as_str()
        .ok_or_else(|| error(format!("cargo metadata has no {key}")))
}

struct Package {
    name: String,
    manifest: PathBuf,
    root: PathBuf,
    target: PathBuf,
    xark_source: PathBuf,
    xark_dependency: String,
    /// The `cargo metadata` output, which resolves every manifest and the
    /// lockfile.
    metadata: Vec<u8>,
    /// The library target's crate name, whose dep-info lists the sources a
    /// wasm build read.
    lib_name: Option<String>,
}

impl Package {
    fn crate_dir(&self) -> Result<&Path> {
        self.manifest.parent().ok_or_else(|| {
            error(format!(
                "{} has no parent directory",
                self.manifest.display()
            ))
        })
    }

    fn verifier_dir(&self) -> Result<PathBuf> {
        Ok(self.crate_dir()?.join("src/verifier"))
    }
}

fn run(command: &mut Command) -> Result<()> {
    let display = format!("{command:?}");
    let status = command
        .status()
        .map_err(|e| error(format!("{display}: {e}")))?;
    if status.success() {
        Ok(())
    } else {
        Err(error(format!("{display} failed: {status}")))
    }
}

fn package(selection: &PackageSelection) -> Result<Package> {
    let mut command = Command::new("cargo");
    command.args(["metadata", "--all-features", "--format-version", "1"]);
    if let Some(path) = &selection.manifest_path {
        command.arg("--manifest-path").arg(path);
    }
    let output = command.output()?;
    if !output.status.success() {
        return Err(error(String::from_utf8_lossy(&output.stderr)));
    }
    let data: Value = serde_json::from_slice(&output.stdout)?;
    let packages = data["packages"]
        .as_array()
        .ok_or_else(|| error("cargo returned no packages"))?;
    let manifest = selection
        .manifest_path
        .as_ref()
        .map(fs::canonicalize)
        .transpose()?;
    let selected = if let Some(name) = &selection.package {
        packages.iter().find(|p| p["name"].as_str() == Some(name))
    } else if let Some(manifest) = &manifest {
        packages.iter().find(|p| {
            p["manifest_path"]
                .as_str()
                .is_some_and(|p| Path::new(p) == manifest)
        })
    } else {
        let current = std::env::current_dir()?;
        packages
            .iter()
            .filter(|p| {
                p["manifest_path"]
                    .as_str()
                    .and_then(|p| Path::new(p).parent())
                    .is_some_and(|dir| current.starts_with(dir))
            })
            .max_by_key(|p| p["manifest_path"].as_str().map_or(0, str::len))
    }
    .ok_or_else(|| error("select a circuit package with -p or --manifest-path"))?;
    let mut languages = packages.iter().filter(|package| package["name"] == "xark");
    let language = languages
        .next()
        .ok_or_else(|| error("the program must declare a Xark dependency"))?;
    if languages.next().is_some() {
        return Err(error(
            "all workspace packages must use the same Xark dependency",
        ));
    }
    let language_manifest = Path::new(
        language["manifest_path"]
            .as_str()
            .ok_or_else(|| error("Xark has no manifest path"))?,
    );
    let language_path = language_manifest
        .parent()
        .ok_or_else(|| error("invalid Xark manifest path"))?;
    let xark_source = language_path
        .parent()
        .and_then(Path::parent)
        .ok_or_else(|| error("invalid Xark source layout"))?
        .to_path_buf();
    let source = language["source"]
        .as_str()
        .ok_or_else(|| error("Xark must use a pinned Git dependency"))?;
    let xark_dependency = xark_source::pinned_git_dependency(source).map_err(error)?;
    let lib_name = selected["targets"].as_array().and_then(|targets| {
        targets
            .iter()
            .find(|target| {
                target["kind"]
                    .as_array()
                    .is_some_and(|kinds| kinds.iter().any(|kind| kind == "cdylib"))
            })
            .and_then(|target| target["name"].as_str())
            .map(|name| name.replace('-', "_"))
    });
    Ok(Package {
        name: json_str(selected, "name")?.into(),
        manifest: json_str(selected, "manifest_path")?.into(),
        root: json_str(&data, "workspace_root")?.into(),
        target: json_str(&data, "target_directory")?.into(),
        xark_source,
        xark_dependency,
        metadata: output.stdout,
        lib_name,
    })
}

fn output_dir(package: &Package, out: &Option<PathBuf>) -> PathBuf {
    out.clone()
        .unwrap_or_else(|| package.target.join("zk").join(&package.name))
}

fn wasm_features(options: &CompileOptions) -> String {
    let mut features = options
        .wasm_features
        .as_deref()
        .unwrap_or(DEFAULT_WASM_FEATURES)
        .split(',')
        .filter(|feature| !feature.is_empty())
        .map(str::to_owned)
        .collect::<Vec<_>>();
    if !options.no_prover {
        features.push("spr-program/wasm-prover".into());
    }
    if options.verifier {
        features.push("spr-program/wasm-verify".into());
    }
    features.sort();
    features.dedup();
    features.join(",")
}

fn check_input_only(package: &Package, features: &str) -> Result<()> {
    let mut command = Command::new("cargo");
    command
        .args(["tree", "--manifest-path"])
        .arg(&package.manifest)
        .args([
            "--package",
            &package.name,
            "--target",
            "wasm32-unknown-unknown",
            "--edges",
            "normal,no-proc-macro",
            "--prefix",
            "none",
            "--format",
            "{p}",
            "--color",
            "never",
        ])
        .current_dir(package.crate_dir()?);
    if !features.is_empty() {
        command.args(["--features", features]);
    }
    let output = command.output()?;
    if !output.status.success() {
        return Err(error(String::from_utf8_lossy(&output.stderr)));
    }
    if String::from_utf8_lossy(&output.stdout)
        .lines()
        .any(|package| package.split_whitespace().next() == Some("xark-wasm"))
    {
        return Err(error(
            "--no-prover conflicts with a resolved WASM dependency on xark-wasm; disable the feature or dependency that enables it",
        ));
    }
    Ok(())
}

#[cfg(test)]
#[path = "../../../tests/unit/input_only.rs"]
mod input_only_tests;

fn discover(package: &Package, out: &Path, features: &str) -> Result<Vec<ProgramMetadata>> {
    let metadata = out.join(".metadata");
    fs::create_dir_all(&metadata)?;
    for file in fs::read_dir(&metadata)? {
        let file = file?.path();
        if file
            .extension()
            .is_some_and(|extension| extension == "json")
        {
            fs::remove_file(file)?;
        }
    }
    let features = format!("{features},build-circuits");
    run(Command::new("cargo")
        .args(["test", "--release", "--lib", "--manifest-path"])
        .arg(&package.manifest)
        .args(["--features", &features, "__zk_export", "--", "--nocapture"])
        .env("ZOLANA_PROGRAM_EXPORT_DIR", fs::canonicalize(&metadata)?))?;
    let mut programs = Vec::new();
    for file in fs::read_dir(&metadata)? {
        let path = file?.path();
        if path
            .extension()
            .is_some_and(|extension| extension == "json")
        {
            programs.push(serde_json::from_slice::<ProgramMetadata>(&fs::read(path)?)?);
        }
    }
    programs.sort_by(|a, b| a.name.cmp(&b.name));
    let index = out.join("programs.json");
    if programs.is_empty() {
        if index.exists() {
            fs::remove_file(index)?;
        }
        return Err(BuildError::NoCircuits(package.manifest.clone()));
    }
    validate_programs(&programs)?;
    fs::write(index, serde_json::to_vec_pretty(&programs)?)?;
    Ok(programs)
}

/// Program names become file names, crate names and generated identifiers,
/// and their layouts become on-chain verifiers.
fn validate_programs(programs: &[ProgramMetadata]) -> Result<()> {
    programs
        .iter()
        .try_for_each(|program| program.validate().map_err(error))
}

/// What a circuit artifact directory holds: the ZK programs of a crate, or
/// one plain Xark circuit.
enum Compiled {
    Programs(Vec<ProgramMetadata>),
    Plain(String),
}

fn compiled(out: &Path) -> Result<Compiled> {
    let index = out.join("programs.json");
    if index.is_file() {
        let programs: Vec<ProgramMetadata> = serde_json::from_slice(&read(&index)?)?;
        validate_programs(&programs)?;
        return Ok(Compiled::Programs(programs));
    }
    if out.join("schema.json").is_file() {
        return plain_circuit_name(out).map(Compiled::Plain);
    }
    Err(error(format!(
        "{} holds no compiled circuits (no programs.json or schema.json); run `zolana zk compile` first",
        out.display()
    )))
}

fn plain_circuit_name(out: &Path) -> Result<String> {
    let schema: Value = serde_json::from_slice(&read(&out.join("schema.json"))?)?;
    let name = schema["circuit"]
        .as_str()
        .ok_or_else(|| error("Xark schema has no circuit name"))?;
    // The name becomes a module file name, like a program name.
    ProgramMetadata {
        name: name.into(),
        rust_type: name.into(),
        fields: Vec::new(),
    }
    .validate()
    .map_err(error)?;
    Ok(name.into())
}

fn write_if_changed(path: &Path, bytes: impl AsRef<[u8]>) -> Result<()> {
    let bytes = bytes.as_ref();
    if fs::read(path).ok().as_deref() != Some(bytes) {
        fs::write(path, bytes)?;
    }
    Ok(())
}

fn entry(
    package: &Package,
    out: &Path,
    program: &ProgramMetadata,
    features: &str,
) -> Result<PathBuf> {
    let dir = out.join(".entries").join(&program.name);
    fs::create_dir_all(dir.join("src"))?;
    let path = serde_json::to_string(
        package
            .crate_dir()?
            .to_str()
            .ok_or_else(|| error("non UTF-8 crate path"))?,
    )?;
    let features = features
        .split(',')
        .filter(|feature| !feature.is_empty())
        .map(serde_json::to_string)
        .collect::<std::result::Result<Vec<_>, _>>()?
        .join(", ");
    let xark_dependency = &package.xark_dependency;
    let manifest = format!(
        "[package]\nname = \"spr-generated-{}-{}\"\nversion = \"0.1.0\"\nedition = \"2024\"\npublish = false\n\n[workspace]\n\n[lib]\ncrate-type = [\"cdylib\", \"rlib\"]\n\n[dependencies]\nprogram = {{ package = \"{}\", path = {path}, features = [{features}] }}\nxark = {{ {xark_dependency} }}\n\n[lints.rust]\nunexpected_cfgs = {{ level = \"warn\", check-cfg = [\"cfg(xark)\", \"cfg(xark_client)\"] }}\n",
        package.name, program.name, package.name
    );
    write_if_changed(&dir.join("Cargo.toml"), manifest)?;
    let source = format!(
        "use xark::prelude::*;\n\n#[circuit]\npub fn r#{}(program: Private<program::{}>, public_hash: Public<Field>) {{\n    let checked = program.execute().expect(\"valid program transaction\");\n    require_eq(*checked.public_hash(), public_hash);\n}}\n",
        program.name, program.rust_type
    );
    write_if_changed(&dir.join("src/lib.rs"), source)?;
    let lock = package.root.join("Cargo.lock");
    if lock.is_file() && !dir.join("Cargo.lock").is_file() {
        fs::copy(lock, dir.join("Cargo.lock"))?;
    }
    Ok(dir)
}

pub fn compile(options: &CompileOptions) -> Result<()> {
    if !options.check && options.skip_r1cs && options.skip_keys && options.skip_wasm {
        return Err(BuildError::NothingToCompile);
    }
    let package = package(&options.package)?;
    let features = wasm_features(options);
    if options.no_prover && !options.skip_wasm && !options.check {
        check_input_only(&package, &features)?;
    }
    let out = output_dir(&package, &options.r1cs_out);
    fs::create_dir_all(&out)?;
    let out = fs::canonicalize(out)?;
    let programs = match discover(&package, &out, &options.r1cs_features) {
        Ok(programs) => programs,
        Err(BuildError::NoCircuits(_)) => return compile_plain(&package, &out, options),
        Err(error) => return Err(error),
    };
    let wasm_out = if options.skip_wasm || options.check {
        None
    } else {
        Some(wasm_output(&package, &out, options)?)
    };
    // A crate opts into on-chain verifiers by having `src/verifier`.
    let verifier_dir = package.verifier_dir()?;
    let export = verifier_dir.is_dir() && (options.check || !options.skip_keys);
    let mut files = Vec::new();
    for program in &programs {
        let artifact = out.join(&program.name);
        let entry = entry(&package, &out, program, &options.r1cs_features)?;
        if !options.skip_r1cs || !artifact.join("circuit.xbc").is_file() {
            xark_cli::build(&entry, &artifact).map_err(error)?;
        }
        if options.check {
            require_cached_setup(&artifact)?;
        } else if !options.skip_keys {
            setup_one(&artifact, options.test)?;
        }
        if export {
            let keys = verifier::KeyArtifacts::read(&artifact)?;
            files.extend(verifier::program_files(program, &keys)?);
        }
    }
    if export {
        verifier::sync(&verifier_dir, &files, options.check)?;
    }
    if let Some(wasm_out) = wasm_out {
        bridge(&package, &out, options, &features, &programs, &wasm_out)?;
    }
    Ok(())
}

/// Written into every wasm package this tool builds. Only a `--wasm-out`
/// directory holding it (or an empty or missing one) is replaced by a new
/// package.
const PACKAGE_MARKER: &str = ".zolana-zk-package";

/// Xark's worker pool and client modules, copied into a package with a prover.
const XARK_POOL_FILES: [&str; 5] = [
    "pool.mjs",
    "pool-worker.mjs",
    "pool.d.ts",
    "client.mjs",
    "client.d.ts",
];

/// Where a wasm package is installed.
struct WasmOutput {
    directory: PathBuf,
    /// The default `wasm` directory inside the CLI's own build directory,
    /// which is replaced even when an earlier CLI left it without a marker.
    cli_owned: bool,
}

fn wasm_output(package: &Package, out: &Path, options: &CompileOptions) -> Result<WasmOutput> {
    let directory = options.wasm_out.clone().unwrap_or_else(|| out.join("wasm"));
    let directory = std::path::absolute(directory)?;
    // Only the default package directory inside the default build directory
    // is the CLI's own: `--r1cs-out` can point into a user's project, and a
    // symlink anywhere in `<target>/zk/<package>/wasm` can lead anywhere.
    let default_out = fs::canonicalize(&package.target)
        .ok()
        .map(|target| target.join("zk").join(&package.name));
    let cli_owned = options.wasm_out.is_none()
        && options.r1cs_out.is_none()
        && default_out.is_some_and(|default| fs::canonicalize(out).is_ok_and(|out| out == default))
        && !fs::symlink_metadata(&directory)
            .is_ok_and(|metadata| metadata.file_type().is_symlink());
    let directory = if directory.exists() {
        fs::canonicalize(directory)?
    } else {
        directory
    };
    if package.manifest.starts_with(&directory) || out.starts_with(&directory) {
        return Err(error(
            "wasm output cannot contain the program sources or circuit build directory",
        ));
    }
    let output = WasmOutput {
        directory,
        cli_owned,
    };
    ensure_replaceable(&output)?;
    Ok(output)
}

fn ensure_replaceable(output: &WasmOutput) -> Result<()> {
    if output.cli_owned {
        return Ok(());
    }
    let directory = &output.directory;
    let metadata = match fs::symlink_metadata(directory) {
        Ok(metadata) => metadata,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(source) => {
            return Err(BuildError::Io {
                path: directory.to_path_buf(),
                source,
            });
        }
    };
    if !metadata.is_dir() {
        return Err(error(format!(
            "wasm output {} exists and is not a directory",
            directory.display()
        )));
    }
    if directory.join(PACKAGE_MARKER).is_file() || fs::read_dir(directory)?.next().is_none() {
        return Ok(());
    }
    Err(error(format!(
        "refusing to replace wasm output {}: it is not empty and has no {PACKAGE_MARKER} marker from an earlier `zolana zk compile`; remove it or choose another --wasm-out",
        directory.display()
    )))
}

/// Moves a finished package from `staging` to `directory`, replacing a
/// previous package only after the new one is in place.
fn install_package(staging: &Path, output: &WasmOutput) -> Result<()> {
    ensure_replaceable(output)?;
    let directory = &output.directory;
    let parent = directory
        .parent()
        .ok_or_else(|| error("wasm output needs a parent directory"))?;
    let name = directory
        .file_name()
        .ok_or_else(|| error("wasm output needs a directory name"))?
        .to_string_lossy();
    let previous = parent.join(format!(".{name}.previous-{}", std::process::id()));
    let existed = directory.exists();
    if existed {
        fs::rename(directory, &previous)?;
    }
    if let Err(failure) = fs::rename(staging, directory) {
        if existed {
            fs::rename(&previous, directory)?;
        }
        return Err(error(failure));
    }
    if existed {
        fs::remove_dir_all(previous)?;
    }
    Ok(())
}

#[cfg(test)]
#[path = "../../../tests/unit/wasm_out.rs"]
mod wasm_out_tests;

fn bridge(
    package: &Package,
    out: &Path,
    options: &CompileOptions,
    features: &str,
    programs: &[ProgramMetadata],
    output: &WasmOutput,
) -> Result<()> {
    let directory = &output.directory;
    let parent = directory
        .parent()
        .ok_or_else(|| error("wasm output needs a parent directory"))?;
    fs::create_dir_all(parent)?;
    let name = directory
        .file_name()
        .ok_or_else(|| error("wasm output needs a directory name"))?
        .to_string_lossy();
    let wasm_target = match options.wasm_target.unwrap_or_default() {
        WasmTarget::Web => "web",
        WasmTarget::Nodejs => "nodejs",
    };
    let settings = wasm_cache::Settings {
        crate_dir: package.crate_dir()?,
        workspace_root: &package.root,
        dependency_graph: &package.metadata,
        options: serde_json::json!({
            "target": wasm_target,
            "wasmOpt": options.wasm_opt,
            "features": features,
            "threads": options.threads(),
            "noProver": options.no_prover,
        }),
        artifacts: programs
            .iter()
            .map(|program| (program.name.as_str(), out.join(&program.name)))
            .collect(),
        copied: if options.no_prover {
            Vec::new()
        } else {
            XARK_POOL_FILES
                .iter()
                .map(|file| package.xark_source.join("crates/wasm/js").join(file))
                .collect()
        },
    }
    .digest()?;
    if wasm_cache::up_to_date(directory, &settings) {
        println!("wasm package {} is up to date", directory.display());
        return Ok(());
    }
    let staging = parent.join(format!(".{name}.building-{}", std::process::id()));
    fs::create_dir(&staging)?;
    let mut command = Command::new("wasm-pack");
    command
        .arg("build")
        .arg(package.crate_dir()?)
        .args([
            "--release",
            "--target",
            wasm_target,
            "--no-pack",
            "--out-dir",
        ])
        .arg(&staging);
    if !options.wasm_opt {
        command.arg("--no-opt");
    }
    if !features.is_empty() {
        command.arg("--").arg("--features").arg(features);
    }
    let started = std::time::SystemTime::now();
    let build = (|| -> Result<()> {
        run(&mut command)?;
        fs::write(
            staging.join(PACKAGE_MARKER),
            wasm_cache::Fingerprint::new(
                settings,
                wasm_cache::built_sources(&package.target, package.lib_name.as_deref(), started)?,
            )
            .marker()?,
        )?;
        if !options.no_prover {
            let mut proving_keys = std::collections::BTreeMap::new();
            for program in programs {
                proving_keys.insert(
                    &program.name,
                    verifier::key_setup_metadata(&out.join(&program.name))?,
                );
            }
            fs::write(
                staging.join("proving-keys.json"),
                serde_json::to_vec_pretty(&proving_keys)?,
            )?;
        }
        for program in programs {
            let client_out = staging.join(&program.name);
            fs::create_dir_all(&client_out)?;
            xark_cli::client(&out.join(&program.name), &client_out, true).map_err(error)?;
        }
        fs::write(
            staging.join("runtime-options.json"),
            serde_json::to_vec_pretty(&serde_json::json!({ "threads": options.threads() }))?,
        )?;
        if options.wasm_target == Some(WasmTarget::Nodejs) {
            fs::write(staging.join("package.json"), "{\"type\":\"commonjs\"}\n")?;
        }
        if !options.no_prover {
            let pool = staging.join("xark");
            fs::create_dir(&pool)?;
            for file in XARK_POOL_FILES {
                fs::copy(
                    package.xark_source.join("crates/wasm/js").join(file),
                    pool.join(file),
                )?;
            }
        }
        install_package(&staging, output)
    })();
    if staging.exists() {
        fs::remove_dir_all(staging)?;
    }
    build
}

fn setup_one(artifact: &Path, test: bool) -> Result<()> {
    if key_cache::reusable(
        artifact,
        if test {
            key_cache::Mode::Test
        } else {
            key_cache::Mode::Default
        },
    )? {
        return Ok(());
    }
    let options = if test {
        xark_cli::SetupOptions {
            insecure_dev_mode: true,
            deterministic_rng: Some(0),
            domain: xark_cli::QapDomain::Radix2,
            ..Default::default()
        }
    } else {
        xark_cli::SetupOptions::default()
    };
    xark_cli::setup(artifact, options).map_err(error)
}

fn require_cached_setup(artifact: &Path) -> Result<()> {
    if key_cache::reusable(artifact, key_cache::Mode::Existing)? {
        return Ok(());
    }
    Err(error(
        "--check requires complete keys for the current circuit; generate them before checking",
    ))
}

pub fn setup(options: &SetupOptions) -> Result<()> {
    let package = package(&options.package)?;
    let out = output_dir(&package, &options.out);
    match compiled(&out)? {
        Compiled::Programs(programs) => {
            for program in programs {
                setup_one(&out.join(program.name), options.test)?;
            }
            Ok(())
        }
        Compiled::Plain(_) => setup_one(&out, options.test),
    }
}

/// Exports every verifier from keys the trusted manifest pins, or nothing:
/// every circuit is checked before any file is written.
pub fn export_verifier(options: &ExportVerifierOptions) -> Result<()> {
    let package = package(&options.package)?;
    let out = output_dir(&package, &options.out);
    let manifest = key_cache::TrustedManifest::load(&options.checksums)?;
    let files = match compiled(&out)? {
        Compiled::Programs(programs) => {
            let mut files = Vec::new();
            for program in &programs {
                let keys = manifest.pinned_keys(&out.join(&program.name), &program.name)?;
                files.extend(verifier::program_files(program, &keys)?);
            }
            files
        }
        Compiled::Plain(name) => {
            let keys = manifest.pinned_keys(&out, &name)?;
            vec![verifier::plain_file(&name, &keys)?]
        }
    };
    verifier::sync(&package.verifier_dir()?, &files, false)
}

pub fn build(options: &BuildOptions) -> Result<()> {
    compile(&options.compile)?;
    if !options.compile.check && !options.sbf.skip_sbf {
        let package = package(&options.compile.package)?;
        let mut command = Command::new("cargo");
        command
            .arg("build-sbf")
            .arg("--manifest-path")
            .arg(package.manifest);
        if let Some(out) = &options.sbf.sbf_out_dir {
            command.arg("--sbf-out-dir").arg(out);
        }
        if let Some(features) = &options.sbf.sbf_features {
            command.args(["--", "--features", features]);
        }
        run(&mut command)?;
    }
    Ok(())
}

/// The wasm package flags that only a ZkProgram package's wasm build reads.
fn program_only_flags(options: &CompileOptions) -> Vec<&'static str> {
    [
        (options.wasm_target.is_some(), "--wasm-target"),
        (options.wasm_features.is_some(), "--wasm-features"),
        (options.verifier, "--verifier"),
        (options.no_prover, "--no-prover"),
        (options.single_threaded, "--single-threaded"),
        (options.wasm_opt, "--wasm-opt"),
    ]
    .into_iter()
    .filter_map(|(set, flag)| set.then_some(flag))
    .collect()
}

#[cfg(test)]
#[path = "../../../tests/unit/compile.rs"]
mod compile_tests;

fn compile_plain(package: &Package, out: &Path, options: &CompileOptions) -> Result<()> {
    let flags = program_only_flags(options);
    if !flags.is_empty() {
        return Err(error(format!(
            "{} derives no ZK program, so it builds a plain Xark circuit and its TypeScript client, which do not take {}",
            package.manifest.display(),
            flags.join(", ")
        )));
    }
    let crate_dir = package.crate_dir()?;
    if !options.skip_r1cs || !out.join("circuit.xbc").is_file() {
        xark_cli::build(crate_dir, out).map_err(error)?;
    }
    let name = plain_circuit_name(out)?;
    if options.check {
        require_cached_setup(out)?;
    } else if !options.skip_keys {
        setup_one(out, options.test)?;
    }
    let verifier_dir = package.verifier_dir()?;
    if verifier_dir.is_dir() && (options.check || !options.skip_keys) {
        let file = verifier::plain_file(&name, &verifier::KeyArtifacts::read(out)?)?;
        verifier::sync(&verifier_dir, &[file], options.check)?;
    }
    if !options.skip_wasm && !options.check {
        let client_out = options
            .wasm_out
            .clone()
            .unwrap_or_else(|| out.join("client"));
        fs::create_dir_all(&client_out)?;
        // Arbitrary artifact directories do not identify the source crate that
        // defines the Rust input helpers.
        xark_cli::client_with_source(out, crate_dir, &client_out).map_err(error)?;
    }
    Ok(())
}
