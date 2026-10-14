use std::{
    collections::{BTreeMap, BTreeSet},
    ffi::OsStr,
    io::ErrorKind,
    path::{Path, PathBuf},
    process::{Command, Stdio},
};

use anyhow::{bail, Context, Result};
use serde_json::Value;
use sha2::{Digest, Sha256};
use zolana_program::{Groth16Keys, R1cs, SetupKind, VerifyingKeyExport};

use crate::args::{
    ZkBuildOptions, ZkCommand, ZkCompileOptions, ZkExportVerifierOptions, ZkImportOptions,
    ZkPackageOptions, ZkSetupKind, ZkSetupOptions, ZkWasmTarget,
};

const R1CS_MARKER: &str = "zolana-zk-r1cs: ";
const R1CS_HOOK: &str = "__zk_r1cs_";
const VERIFIER_GLUE: &str = "verifier.rs";
const VERIFIER_MOD: &str = "mod.rs";
const STAGING: &str = ".staging";
const WASM_STAMP: &str = ".zolana-wasm.stamp";
const OPTIMIZED_PACKAGES: [&str; 9] = [
    "zolana-program",
    "ark-ff",
    "ark-ec",
    "ark-bn254",
    "ark-poly",
    "ark-relations",
    "ark-r1cs-std",
    "ark-std",
    "light-poseidon",
];
const PRODUCTION_KEY: &str = "VERIFYINGKEY_INSECURE_TEST_SETUP: bool = false";

const THREADS_LINK_ARGS: [&str; 7] = [
    "--shared-memory",
    "--max-memory=1073741824",
    "--import-memory",
    "--export=__wasm_init_tls",
    "--export=__tls_size",
    "--export=__tls_align",
    "--export=__tls_base",
];
const UNTYPED_THREAD_POOL: &str =
    "export function initThreadPool(num_threads: number): Promise<any>;";
const TYPED_THREAD_POOL: &str = "export function initThreadPool(threads: number): Promise<void>;";

pub(crate) fn run_build_zk_program(opts: ZkBuildOptions) -> Result<()> {
    let circuits = CircuitCrate::resolve(&opts.compile.package)?;
    compile_circuits(&opts.compile, &circuits)?;
    if opts.compile.check {
        return Ok(());
    }
    std::thread::scope(|scope| {
        let wasm = (!opts.compile.skip_wasm)
            .then(|| scope.spawn(|| compile_wasm(&opts.compile, &circuits)));
        let sbf = if opts.skip_sbf {
            Ok(())
        } else {
            build_sbf(&opts, &circuits)
        };
        let wasm = wasm.map_or(Ok(()), |wasm| {
            wasm.join()
                .unwrap_or_else(|_| Err(anyhow::anyhow!("the wasm build panicked")))
        });
        sbf.and(wasm)
    })
}

fn build_sbf(opts: &ZkBuildOptions, circuits: &CircuitCrate) -> Result<()> {
    let mut build_sbf = Command::new(cargo());
    build_sbf
        .args(["build-sbf", "--manifest-path"])
        .arg(&circuits.manifest);
    if let Some(dir) = &opts.sbf_out_dir {
        build_sbf.arg("--sbf-out-dir").arg(dir);
    }
    if let Some(features) = &opts.sbf_features {
        build_sbf.args(["--", "--features", features]);
    }
    let status = build_sbf
        .status()
        .context("running cargo build-sbf; install the Solana platform tools")?;
    if !status.success() {
        bail!(
            "cargo build-sbf failed for {} ({status})",
            circuits.manifest.display()
        );
    }
    Ok(())
}

pub(crate) fn run_zk(command: ZkCommand) -> Result<()> {
    match command {
        ZkCommand::Compile(opts) => compile(opts),
        ZkCommand::Setup(opts) => setup(opts),
        ZkCommand::Import(opts) => import(opts),
        ZkCommand::ExportVerifier(opts) => export_verifier(opts),
    }
}

struct CircuitCrate {
    manifest: PathBuf,
    dir: PathBuf,
    lib_name: String,
    target_dir: PathBuf,
    build_dir: PathBuf,
    verifier_dir: PathBuf,
}

impl CircuitCrate {
    fn resolve(selection: &ZkPackageOptions) -> Result<Self> {
        let manifest = match &selection.manifest_path {
            Some(path) => path.clone(),
            None => nearest_manifest()?,
        };
        let output = Command::new(cargo())
            .args([
                "metadata",
                "--format-version",
                "1",
                "--no-deps",
                "--manifest-path",
            ])
            .arg(&manifest)
            .stderr(Stdio::inherit())
            .output()
            .with_context(|| format!("running cargo metadata for {}", manifest.display()))?;
        if !output.status.success() {
            bail!("cargo metadata failed for {}", manifest.display());
        }
        let metadata: Value =
            serde_json::from_slice(&output.stdout).context("reading cargo metadata")?;
        let manifest = manifest
            .canonicalize()
            .with_context(|| format!("resolving {}", manifest.display()))?;
        let packages = metadata
            .get("packages")
            .and_then(Value::as_array)
            .context("cargo metadata lists no packages")?;
        let package = match &selection.package {
            Some(name) => packages
                .iter()
                .find(|package| package.get("name").and_then(Value::as_str) == Some(name))
                .with_context(|| {
                    format!(
                        "the workspace of {} has no package `{name}`",
                        manifest.display()
                    )
                })?,
            None => packages
                .iter()
                .find(|package| {
                    package
                        .get("manifest_path")
                        .and_then(Value::as_str)
                        .is_some_and(|path| Path::new(path) == manifest)
                })
                .with_context(|| {
                    format!(
                        "{} is not a package manifest; pass -p <package> or --manifest-path",
                        manifest.display()
                    )
                })?,
        };
        let manifest = PathBuf::from(
            package
                .get("manifest_path")
                .and_then(Value::as_str)
                .context("cargo metadata lists a package without a manifest")?,
        );
        let name = package
            .get("name")
            .and_then(Value::as_str)
            .context("cargo metadata lists a package without a name")?;
        let lib_name = package
            .get("targets")
            .and_then(Value::as_array)
            .and_then(|targets| {
                targets.iter().find(|target| {
                    target
                        .get("crate_types")
                        .and_then(Value::as_array)
                        .is_some_and(|types| types.iter().any(|kind| kind == "cdylib"))
                })
            })
            .and_then(|target| target.get("name"))
            .and_then(Value::as_str)
            .unwrap_or(name)
            .replace('-', "_");
        let target_dir = PathBuf::from(
            metadata
                .get("target_directory")
                .and_then(Value::as_str)
                .context("cargo metadata has no target directory")?,
        );
        let dir = manifest
            .parent()
            .with_context(|| format!("{} has no directory", manifest.display()))?
            .to_path_buf();
        Ok(Self {
            build_dir: target_dir.join("zk").join(name),
            verifier_dir: dir.join("src").join("verifier"),
            manifest,
            dir,
            lib_name,
            target_dir,
        })
    }
}

fn compile(opts: ZkCompileOptions) -> Result<()> {
    let circuits = CircuitCrate::resolve(&opts.package)?;
    compile_with(&opts, &circuits)
}

fn compile_with(opts: &ZkCompileOptions, circuits: &CircuitCrate) -> Result<()> {
    if opts.skip_r1cs && opts.skip_keys && opts.skip_wasm && !opts.check {
        bail!("--skip-r1cs, --skip-keys and --skip-wasm leave nothing to compile");
    }
    compile_circuits(opts, circuits)?;
    if !opts.skip_wasm && !opts.check {
        compile_wasm(opts, circuits)?;
    }
    Ok(())
}

fn compile_circuits(opts: &ZkCompileOptions, circuits: &CircuitCrate) -> Result<()> {
    let r1cs_dir = output_dir(
        opts.r1cs_out
            .clone()
            .unwrap_or_else(|| circuits.build_dir.clone()),
    )?;
    let exported = if opts.skip_r1cs {
        Vec::new()
    } else {
        compile_r1cs(opts, circuits, &r1cs_dir)?
    };
    let exported_glue = exported
        .iter()
        .map(|path| Ok(r1cs_dir.join(renamed(path, VERIFIER_GLUE)?)))
        .collect::<Result<Vec<_>>>()?;
    if !opts.skip_keys {
        let r1cs = if exported.is_empty() {
            inputs_or_all(Vec::new(), &r1cs_dir, "r1cs", "zolana zk compile")?
        } else {
            exported
        };
        write_test_keys(&r1cs, circuits)?;
    }
    if opts.skip_r1cs && opts.skip_keys && !opts.check {
        return Ok(());
    }
    let glue = inputs_or_all(exported_glue, &r1cs_dir, VERIFIER_GLUE, "zolana zk compile")?;
    let keys = glue
        .iter()
        .map(|path| {
            let name = program_name(path)?;
            Ok(KeyModule {
                source: circuits.build_dir.join(format!("{name}.vk.rs")),
                name,
                replace_production: false,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    let modules = verifier_modules(&glue, &keys, circuits)?;
    if opts.check {
        check_verifier_modules(&modules)
    } else {
        write_verifier_modules(&modules)
    }
}

fn compile_r1cs(
    opts: &ZkCompileOptions,
    circuits: &CircuitCrate,
    out: &Path,
) -> Result<Vec<PathBuf>> {
    let mut cargo = Command::new(cargo());
    cargo.args(["test", "--lib", "--config", "profile.dev.debug=0"]);
    for package in OPTIMIZED_PACKAGES {
        cargo
            .arg("--config")
            .arg(format!("profile.dev.package.{package}.opt-level=3"));
    }
    let output = cargo
        .arg("--manifest-path")
        .arg(&circuits.manifest)
        .args([
            "--features",
            &format!("{},r1cs-export", opts.r1cs_features),
            "--",
            R1CS_HOOK,
            "--nocapture",
            "--test-threads=1",
        ])
        .env("ZOLANA_ZK_R1CS_OUT", out)
        .stderr(Stdio::inherit())
        .output()
        .with_context(|| format!("running cargo test for {}", circuits.manifest.display()))?;
    let printed = String::from_utf8_lossy(&output.stdout);
    if !output.status.success() {
        bail!(
            "exporting the circuits of {} failed ({})\n{printed}",
            circuits.manifest.display(),
            output.status
        );
    }
    let written: Vec<PathBuf> = printed
        .lines()
        .filter_map(|line| line.split_once(R1CS_MARKER).map(|(_, path)| path))
        .map(PathBuf::from)
        .collect();
    if written.is_empty() {
        bail!(
            "{} derives no ZK program: a program is a struct with exactly `private` and `public` fields deriving ProofInput",
            circuits.manifest.display()
        );
    }
    for path in &written {
        let r1cs = load_r1cs(path)?;
        println!(
            "{}: {} constraints, {} public inputs, {} private variables",
            path.display(),
            r1cs.constraints(),
            r1cs.public_inputs(),
            r1cs.private_variables()
        );
    }
    Ok(written)
}

fn write_test_keys(r1cs: &[PathBuf], circuits: &CircuitCrate) -> Result<()> {
    let out = output_dir(circuits.build_dir.clone())?;
    for path in r1cs {
        if is_production_key(&circuits.verifier_dir.join(renamed(path, "vk.rs")?)) {
            continue;
        }
        let keys = Groth16Keys::new_with_test_setup(&load_r1cs(path)?)
            .with_context(|| format!("setting up {}", path.display()))?;
        let pk = out.join(renamed(path, "pk")?);
        save_key_image(&keys, &pk)?;
        export_module(&keys, &pk, &out, SetupKind::InsecureTest)?;
    }
    Ok(())
}

fn is_production_key(module: &Path) -> bool {
    std::fs::read_to_string(module).is_ok_and(|text| text.contains(PRODUCTION_KEY))
}

fn export_module(keys: &Groth16Keys, pk: &Path, out: &Path, setup: SetupKind) -> Result<()> {
    let module = renamed(pk, "vk.rs")?;
    let staging = output_dir(out.join(STAGING))?;
    keys.export_verifying_key(&VerifyingKeyExport {
        output_dir: &staging,
        output_filename: &module,
        setup,
    })
    .with_context(|| format!("exporting the verifying key of {}", pk.display()))?;
    let target = out.join(&module);
    write_if_changed(&target, &rustfmt_staged(&staging.join(&module))?)?;
    println!("{}", target.display());
    Ok(())
}

fn rustfmt_staged(staged: &Path) -> Result<Vec<u8>> {
    let formatted = Command::new("rustfmt")
        .args(["--edition", "2021"])
        .arg(staged)
        .output()
        .with_context(|| {
            format!(
                "running rustfmt on {}; install it with `rustup component add rustfmt`",
                staged.display()
            )
        })?;
    if !formatted.status.success() {
        bail!(
            "rustfmt failed on {} ({})\n{}",
            staged.display(),
            formatted.status,
            String::from_utf8_lossy(&formatted.stderr)
        );
    }
    let generated =
        std::fs::read(staged).with_context(|| format!("reading {}", staged.display()))?;
    std::fs::remove_file(staged).with_context(|| format!("removing {}", staged.display()))?;
    Ok(generated)
}

fn write_if_changed(path: &Path, contents: &[u8]) -> Result<()> {
    if std::fs::read(path).is_ok_and(|current| current == contents) {
        return Ok(());
    }
    std::fs::write(path, contents).with_context(|| format!("writing {}", path.display()))
}

struct KeyModule {
    name: String,
    source: PathBuf,
    replace_production: bool,
}

struct VerifierModules {
    dir: PathBuf,
    names: Vec<String>,
    files: Vec<(PathBuf, Vec<u8>)>,
}

fn verifier_modules(
    glue: &[PathBuf],
    keys: &[KeyModule],
    circuits: &CircuitCrate,
) -> Result<VerifierModules> {
    let programs = glue
        .iter()
        .map(|path| Ok((program_name(path)?, path)))
        .collect::<Result<BTreeMap<_, _>>>()?;
    let dir = circuits.verifier_dir.clone();
    let staging = output_dir(circuits.build_dir.join(STAGING))?;
    let mut files = Vec::new();
    for (name, path) in &programs {
        let staged = staging.join(format!("{name}.rs"));
        std::fs::copy(path, &staged).with_context(|| {
            format!(
                "copying {} to {}; run `zolana zk compile` to write the verifier module",
                path.display(),
                staged.display()
            )
        })?;
        files.push((dir.join(format!("{name}.rs")), rustfmt_staged(&staged)?));
    }
    for key in keys {
        if !programs.contains_key(&key.name) {
            bail!(
                "{name} has a verifying key but no {name}.{VERIFIER_GLUE}; run `zolana zk compile` first",
                name = key.name
            );
        }
        let module = dir.join(format!("{}.vk.rs", key.name));
        if !key.replace_production && is_production_key(&module) {
            println!("{}: production key kept", module.display());
            continue;
        }
        let contents = std::fs::read(&key.source).with_context(|| {
            format!(
                "reading {}; run `zolana zk compile` without --skip-keys or `zolana zk export-verifier`",
                key.source.display()
            )
        })?;
        files.push((module, contents));
    }
    let listing: String = programs
        .keys()
        .map(|name| format!("pub mod {name};\n"))
        .collect();
    files.push((dir.join(VERIFIER_MOD), listing.into_bytes()));
    files.sort_by(|left, right| left.0.cmp(&right.0));
    Ok(VerifierModules {
        dir,
        names: programs.into_keys().collect(),
        files,
    })
}

fn write_verifier_modules(modules: &VerifierModules) -> Result<()> {
    output_dir(modules.dir.clone())?;
    for (path, contents) in &modules.files {
        write_if_changed(path, contents)?;
        println!("{}", path.display());
    }
    for path in ungenerated_modules(modules)? {
        eprintln!(
            "warning: {} is not a generated verifier module",
            path.display()
        );
    }
    Ok(())
}

fn check_verifier_modules(modules: &VerifierModules) -> Result<()> {
    let mut stale = Vec::new();
    for (path, contents) in &modules.files {
        match std::fs::read(path) {
            Ok(current) if current == *contents => {}
            Ok(_) => stale.push(format!(
                "{}: differs from the generated module",
                path.display()
            )),
            Err(error) if error.kind() == ErrorKind::NotFound => {
                stale.push(format!("{}: missing", path.display()))
            }
            Err(error) => {
                return Err(error).with_context(|| format!("reading {}", path.display()));
            }
        }
    }
    for path in ungenerated_modules(modules)? {
        stale.push(format!("{}: not generated", path.display()));
    }
    if stale.is_empty() {
        println!("{}: up to date", modules.dir.display());
        return Ok(());
    }
    for line in &stale {
        eprintln!("{line}");
    }
    bail!(
        "{} verifier module file(s) in {} are out of date; rerun without --check to regenerate them",
        stale.len(),
        modules.dir.display()
    )
}

fn ungenerated_modules(modules: &VerifierModules) -> Result<Vec<PathBuf>> {
    if !modules.dir.is_dir() {
        return Ok(Vec::new());
    }
    let expected: BTreeSet<String> = modules
        .names
        .iter()
        .flat_map(|name| [format!("{name}.rs"), format!("{name}.vk.rs")])
        .chain([VERIFIER_MOD.to_string()])
        .collect();
    let mut found = Vec::new();
    for entry in std::fs::read_dir(&modules.dir)
        .with_context(|| format!("reading {}", modules.dir.display()))?
    {
        let path = entry
            .with_context(|| format!("reading {}", modules.dir.display()))?
            .path();
        let generated = path
            .file_name()
            .and_then(OsStr::to_str)
            .is_some_and(|name| expected.contains(name));
        if path.extension() == Some(OsStr::new("rs")) && !generated {
            found.push(path);
        }
    }
    found.sort();
    Ok(found)
}

fn program_name(glue: &Path) -> Result<String> {
    glue.file_name()
        .and_then(OsStr::to_str)
        .and_then(|name| name.strip_suffix(VERIFIER_GLUE))
        .and_then(|name| name.strip_suffix('.'))
        .filter(|name| !name.is_empty())
        .map(str::to_string)
        .with_context(|| {
            format!(
                "{} is not a <program>.{VERIFIER_GLUE} module",
                glue.display()
            )
        })
}

fn compile_wasm(opts: &ZkCompileOptions, circuits: &CircuitCrate) -> Result<()> {
    let out = output_dir(
        opts.wasm_out
            .clone()
            .unwrap_or_else(|| circuits.build_dir.join("wasm")),
    )?;
    let out = std::path::absolute(&out).with_context(|| format!("resolving {}", out.display()))?;
    let threads = opts.threads();

    let mut features = vec![opts.wasm_features.as_str()];
    if !opts.no_prover {
        features.push("zolana-program/wasm-prover");
    }
    if threads {
        features.push("zolana-program/wasm-threads");
    }
    if opts.verifier {
        features.push("zolana-program/wasm-verify");
    }
    let features = features.join(",");
    let digest = hex::encode(Sha256::digest(features.as_bytes()));
    let variant = if threads { "threads" } else { "single" };
    let target_dir = circuits.target_dir.join(format!(
        "zk-wasm-{variant}-{}",
        digest.get(..12).unwrap_or(&digest)
    ));

    let mut rustflags = vec![format!(
        "-C target-feature={}",
        if threads {
            "+atomics,+bulk-memory,+simd128"
        } else {
            "+simd128"
        }
    )];
    if threads {
        rustflags.extend(
            THREADS_LINK_ARGS
                .iter()
                .map(|arg| format!("-C link-arg={arg}")),
        );
    }

    let target = match opts.wasm_target {
        ZkWasmTarget::Web => "web",
        ZkWasmTarget::Nodejs => "nodejs",
    };
    let mut cargo_args = vec!["--features", features.as_str()];
    if threads {
        cargo_args.extend(["-Z", "build-std=panic_abort,std"]);
    }
    let configure = |command: &mut Command| {
        command
            .current_dir(&circuits.dir)
            .envs([
                ("CARGO_PROFILE_RELEASE_OPT_LEVEL", "3"),
                ("CARGO_PROFILE_RELEASE_LTO", "fat"),
                ("CARGO_PROFILE_RELEASE_CODEGEN_UNITS", "1"),
                ("CARGO_PROFILE_RELEASE_OVERFLOW_CHECKS", "false"),
                ("CARGO_PROFILE_RELEASE_PANIC", "abort"),
                ("CARGO_INCREMENTAL", "0"),
            ])
            .env(
                "CARGO_TARGET_WASM32_UNKNOWN_UNKNOWN_RUSTFLAGS",
                rustflags.join(" "),
            )
            .env("CARGO_TARGET_DIR", &target_dir)
            .env_remove("RUSTFLAGS")
            .env_remove("CARGO_ENCODED_RUSTFLAGS");
        if threads {
            command
                .env("RUSTUP_TOOLCHAIN", &opts.nightly)
                .env_remove("CARGO");
        }
    };

    let mut build = Command::new("cargo");
    build
        .args([
            "build",
            "--lib",
            "--release",
            "--target",
            "wasm32-unknown-unknown",
        ])
        .args(&cargo_args);
    configure(&mut build);
    let status = build
        .status()
        .with_context(|| format!("building the wasm of {}", circuits.manifest.display()))?;
    if !status.success() {
        bail!(
            "the wasm build of {} failed ({status})",
            circuits.manifest.display()
        );
    }
    let artifact = target_dir
        .join("wasm32-unknown-unknown")
        .join("release")
        .join(format!("{}.wasm", circuits.lib_name));
    let compiled =
        std::fs::read(&artifact).with_context(|| format!("reading {}", artifact.display()))?;
    let stamp = format!(
        "{}\n{target}\nthreads={}\nwasm-opt={}\n",
        hex::encode(Sha256::digest(&compiled)),
        threads,
        opts.wasm_opt
    );
    let stamp_path = out.join(WASM_STAMP);
    let module = out.join(format!("{}_bg.wasm", circuits.lib_name));
    if module.is_file()
        && std::fs::read_to_string(&stamp_path).is_ok_and(|current| current == stamp)
    {
        println!("{} (unchanged)", module.display());
        return Ok(());
    }

    let mut wasm_pack = Command::new("wasm-pack");
    wasm_pack
        .arg("build")
        .arg(&circuits.dir)
        .args(["--release", "--target", target])
        .args((!opts.wasm_opt).then_some("--no-opt"))
        .arg("--out-dir")
        .arg(&out)
        .arg("--")
        .args(&cargo_args);
    configure(&mut wasm_pack);
    let status = wasm_pack
        .status()
        .context("running wasm-pack; install it with `cargo install wasm-pack`")?;
    if !status.success() {
        bail!(
            "wasm-pack failed for {} ({status})",
            circuits.manifest.display()
        );
    }
    if threads {
        type_thread_pool(&out.join(format!("{}.d.ts", circuits.lib_name)))?;
    }
    std::fs::write(&stamp_path, stamp)
        .with_context(|| format!("writing {}", stamp_path.display()))?;
    println!("{}", module.display());
    Ok(())
}

fn type_thread_pool(declarations: &Path) -> Result<()> {
    let text = std::fs::read_to_string(declarations)
        .with_context(|| format!("reading {}", declarations.display()))?;
    if !text.contains(UNTYPED_THREAD_POOL) {
        bail!(
            "wasm-bindgen-rayon no longer declares initThreadPool as expected in {}",
            declarations.display()
        );
    }
    std::fs::write(
        declarations,
        text.replace(UNTYPED_THREAD_POOL, TYPED_THREAD_POOL),
    )
    .with_context(|| format!("writing {}", declarations.display()))
}

fn setup(opts: ZkSetupOptions) -> Result<()> {
    if !opts.test {
        bail!(
            "only the test setup runs here; pass --test for local keys, \
             or run a ceremony and `zolana zk import` its zkey"
        );
    }
    let build = CircuitCrate::resolve(&opts.package)?.build_dir;
    let inputs = inputs_or_all(opts.r1cs, &build, "r1cs", "zolana zk compile")?;
    let out = output_dir(opts.out.unwrap_or(build))?;
    for path in inputs {
        let keys = Groth16Keys::new_with_test_setup(&load_r1cs(&path)?)
            .with_context(|| format!("setting up {}", path.display()))?;
        let pk = out.join(renamed(&path, "pk")?);
        save_key_image(&keys, &pk)?;
        println!("{}", pk.display());
    }
    Ok(())
}

fn import(opts: ZkImportOptions) -> Result<()> {
    let build = CircuitCrate::resolve(&opts.package)?.build_dir;
    let r1cs_path = match opts.r1cs {
        Some(path) => path,
        None => build.join(renamed(&opts.zkey, "r1cs")?),
    };
    let zkey =
        std::fs::read(&opts.zkey).with_context(|| format!("reading {}", opts.zkey.display()))?;
    let keys =
        Groth16Keys::from_zkey_for_r1cs(&zkey, &load_r1cs(&r1cs_path)?).with_context(|| {
            format!(
                "importing {} for {}",
                opts.zkey.display(),
                r1cs_path.display()
            )
        })?;
    let pk = output_dir(opts.out.unwrap_or(build))?.join(renamed(&r1cs_path, "pk")?);
    save_key_image(&keys, &pk)?;
    println!("{}", pk.display());
    Ok(())
}

// The checksum is recorded when trusted key material is converted to an image,
// not recomputed from an image at load time.
fn save_key_image(keys: &Groth16Keys, path: &Path) -> Result<()> {
    let bytes = keys.to_image_bytes();
    std::fs::write(path, &bytes).with_context(|| format!("writing {}", path.display()))?;
    let name = path
        .file_name()
        .and_then(OsStr::to_str)
        .context("non-UTF-8 key filename")?;
    let manifest = path.with_extension("pk.sha256");
    std::fs::write(
        &manifest,
        format!("{}  {name}\n", hex::encode(Sha256::digest(&bytes))),
    )
    .with_context(|| format!("writing {}", manifest.display()))?;
    Ok(())
}

fn key_checksums(manifest: &Path) -> Result<BTreeMap<PathBuf, [u8; 32]>> {
    let text = std::fs::read_to_string(manifest)
        .with_context(|| format!("reading {}", manifest.display()))?;
    let directory = manifest
        .parent()
        .context("checksum manifest has no parent")?;
    let mut checksums = BTreeMap::new();
    for (index, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let (digest, name) = line.split_once(char::is_whitespace).with_context(|| {
            format!(
                "{}:{}: expected `<sha256>  <file>`",
                manifest.display(),
                index + 1
            )
        })?;
        let mut checksum = [0; 32];
        hex::decode_to_slice(digest, &mut checksum)
            .with_context(|| format!("{}:{}: invalid SHA-256", manifest.display(), index + 1))?;
        let name = name
            .trim_start()
            .strip_prefix('*')
            .unwrap_or(name.trim_start());
        if name.is_empty() {
            bail!("{}:{}: missing key filename", manifest.display(), index + 1);
        }
        let path = directory.join(name);
        let path = path
            .canonicalize()
            .with_context(|| format!("resolving {}", path.display()))?;
        if checksums.insert(path.clone(), checksum).is_some() {
            bail!("duplicate checksum for {}", path.display());
        }
    }
    if checksums.is_empty() {
        bail!("{} contains no key checksums", manifest.display());
    }
    Ok(checksums)
}

fn export_verifier(opts: ZkExportVerifierOptions) -> Result<()> {
    let checksums = key_checksums(&opts.checksums)?;
    let circuits = CircuitCrate::resolve(&opts.package)?;
    let inputs = inputs_or_all(
        opts.pk,
        &circuits.build_dir,
        "pk",
        "zolana zk setup or zolana zk import",
    )?;
    let out = output_dir(opts.out.unwrap_or_else(|| circuits.build_dir.clone()))?;
    let setup = match opts.setup {
        ZkSetupKind::Production => SetupKind::Production,
        ZkSetupKind::Test => SetupKind::InsecureTest,
    };
    let mut keys = Vec::new();
    for pk in inputs {
        let canonical = pk
            .canonicalize()
            .with_context(|| format!("resolving {}", pk.display()))?;
        let checksum = checksums.get(&canonical).with_context(|| {
            format!(
                "{} has no checksum in {}",
                pk.display(),
                opts.checksums.display()
            )
        })?;
        let loaded = Groth16Keys::load_image_checked(&pk, checksum)
            .with_context(|| format!("checking {}", pk.display()))?;
        export_module(&loaded, &pk, &out, setup)?;
        keys.push(KeyModule {
            name: file_stem(&pk)?.to_string(),
            source: out.join(renamed(&pk, "vk.rs")?),
            replace_production: true,
        });
    }
    let glue = inputs_or_all(
        Vec::new(),
        &circuits.build_dir,
        VERIFIER_GLUE,
        "zolana zk compile",
    )?;
    write_verifier_modules(&verifier_modules(&glue, &keys, &circuits)?)
}

fn nearest_manifest() -> Result<PathBuf> {
    let cwd = std::env::current_dir().context("reading the current directory")?;
    cwd.ancestors()
        .map(|dir| dir.join("Cargo.toml"))
        .find(|manifest| manifest.is_file())
        .with_context(|| format!("no Cargo.toml in {} or its parents", cwd.display()))
}

fn cargo() -> std::ffi::OsString {
    std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into())
}

fn output_dir(dir: PathBuf) -> Result<PathBuf> {
    std::fs::create_dir_all(&dir).with_context(|| format!("creating {}", dir.display()))?;
    Ok(dir)
}

fn load_r1cs(path: &Path) -> Result<R1cs> {
    R1cs::load(path).with_context(|| format!("reading {}", path.display()))
}

fn file_stem(path: &Path) -> Result<&str> {
    path.file_stem()
        .and_then(OsStr::to_str)
        .with_context(|| format!("{} has no UTF-8 file name", path.display()))
}

fn renamed(path: &Path, extension: &str) -> Result<String> {
    Ok(format!("{}.{extension}", file_stem(path)?))
}

fn inputs_or_all(
    inputs: Vec<PathBuf>,
    dir: &Path,
    extension: &str,
    producer: &str,
) -> Result<Vec<PathBuf>> {
    if !inputs.is_empty() {
        return Ok(inputs);
    }
    let suffix = format!(".{extension}");
    let mut found = Vec::new();
    if dir.is_dir() {
        for entry in std::fs::read_dir(dir).with_context(|| format!("reading {}", dir.display()))? {
            let path = entry
                .with_context(|| format!("reading {}", dir.display()))?
                .path();
            if path
                .file_name()
                .and_then(OsStr::to_str)
                .is_some_and(|name| name.ends_with(&suffix))
            {
                found.push(path);
            }
        }
    }
    if found.is_empty() {
        bail!(
            "no .{extension} files in {}; run `{producer}` first or pass the files",
            dir.display()
        );
    }
    found.sort();
    Ok(found)
}
