//! Build-script half of `zolana-gnark-ffi-prover`, kept dependency-free so it
//! adds nothing to the build-dependency graph. A prover crate's `build.rs` is
//! `fn main() { zolana_gnark_ffi_prover_build::build_prover_archive() }`.
//!
//! The prover crate keeps a Go `main` package in `circuits/` whose `go.mod`
//! requires the bridge module `zolana/gnarkffiprover` but does not replace it.
//! The bridge ships inside this crate, in `go/`, and the build supplies the
//! `replace` that points at it. The bridge is therefore found wherever this
//! crate is unpacked (workspace member, path or git dependency, registry
//! download), and it always matches the `zolana-gnark-ffi-prover` release
//! whose `prover!` macro declares its exports.
//!
//! The build reads `circuits/go.mod` and `circuits/go.sum` but never writes
//! them and never runs `go mod tidy`: both must already be complete for the
//! module graph with the bridge replaced, so a build with a warm Go module
//! cache needs no network. Any other `replace` in `circuits/go.mod` (for
//! example local circuit gadget modules) is the prover crate's own and is kept
//! as written; relative targets resolve against `circuits/`.

use std::{
    collections::BTreeSet,
    env,
    ffi::{OsStr, OsString},
    fs, io,
    path::{Path, PathBuf},
    process::Command,
};

/// Module path of the Go bridge in this crate's `go/` directory.
const BRIDGE_MODULE: &str = "zolana/gnarkffiprover";

/// Build the calling crate's `circuits/` Go `main` package into a C archive
/// and link it. The archive exports the bridge functions that
/// `zolana_gnark_ffi_prover::prover!` declares.
pub fn build_prover_archive() {
    let manifest_dir = env_path("CARGO_MANIFEST_DIR");
    let out_dir = env_path("OUT_DIR");
    let circuits = manifest_dir.join("circuits");
    let bridge = Path::new(env!("CARGO_MANIFEST_DIR")).join("go");
    let modfile = write_modfile(&circuits, &bridge, &out_dir);
    let archive = out_dir.join("libprover.a");

    go(
        &circuits,
        [
            OsStr::new("build"),
            OsStr::new("-modfile"),
            modfile.as_os_str(),
            OsStr::new("-buildmode=c-archive"),
            OsStr::new("-o"),
            archive.as_os_str(),
            OsStr::new("."),
        ],
    );

    // A stale archive proves a circuit the keys were not made for, so every
    // source compiled into it must rebuild it.
    for path in archive_sources(&circuits, &bridge, &modfile) {
        println!("cargo:rerun-if-changed={}", path.display());
    }

    println!("cargo:rustc-link-search=native={}", out_dir.display());
    println!("cargo:rustc-link-lib=static=prover");
    if env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("macos") {
        println!("cargo:rustc-link-lib=framework=CoreFoundation");
        println!("cargo:rustc-link-lib=framework=Security");
        println!("cargo:rustc-link-lib=resolv");
    }
}

/// Copy `circuits/go.mod` and `circuits/go.sum` into `out_dir` and add the
/// bridge `replace` to the copy. The returned modfile overrides any `replace`
/// of the bridge the circuits module declares: the archive must export the
/// ABI of the bridge shipped with this crate.
fn write_modfile(circuits: &Path, bridge: &Path, out_dir: &Path) -> PathBuf {
    let modfile = out_dir.join("circuits.mod");
    // `go -modfile=<name>.mod` reads its checksums from `<name>.sum`.
    let sums = out_dir.join("circuits.sum");
    copy(&circuits.join("go.mod"), &modfile);
    let circuit_sums = circuits.join("go.sum");
    if circuit_sums.is_file() {
        copy(&circuit_sums, &sums);
    } else if let Err(e) = fs::remove_file(&sums) {
        assert!(
            e.kind() == io::ErrorKind::NotFound,
            "failed to remove {}: {e}",
            sums.display()
        );
    }

    let mut replace = OsString::from(format!("-replace={BRIDGE_MODULE}="));
    replace.push(bridge);
    go(
        circuits,
        [
            OsStr::new("mod"),
            OsStr::new("edit"),
            replace.as_os_str(),
            modfile.as_os_str(),
        ],
    );
    modfile
}

/// The paths whose changes must rebuild the archive: the circuits directory,
/// the bridge, and every package the archive compiles from a local-directory
/// `replace` of the circuits module, with that module's `go.mod`. Packages
/// are watched rather than whole replacement modules, so unrelated files there
/// (binaries, downloaded keys) do not rebuild the archive. The circuits
/// module's own `go.mod` as Go reports it is the generated modfile, which is
/// rewritten on every build and must never be watched.
fn archive_sources(circuits: &Path, bridge: &Path, modfile: &Path) -> BTreeSet<PathBuf> {
    let template = "{{with .Module}}{{if not .Main}}{{with .Replace}}{{if not .Version}}\
                    {{$.Dir}}\n{{$.Module.GoMod}}{{end}}{{end}}{{end}}{{end}}";
    let listed = go_output(
        circuits,
        [
            OsStr::new("list"),
            OsStr::new("-modfile"),
            modfile.as_os_str(),
            OsStr::new("-deps"),
            OsStr::new("-f"),
            OsStr::new(template),
            OsStr::new("."),
        ],
    );
    let mut paths: BTreeSet<PathBuf> = listed
        .lines()
        .filter(|line| !line.is_empty())
        .map(PathBuf::from)
        .collect();
    paths.insert(circuits.to_path_buf());
    paths.insert(bridge.to_path_buf());
    paths
}

fn env_path(name: &str) -> PathBuf {
    PathBuf::from(env::var_os(name).unwrap_or_else(|| panic!("{name} is not set")))
}

fn copy(from: &Path, to: &Path) {
    if let Err(e) = fs::copy(from, to) {
        panic!("failed to copy {} to {}: {e}", from.display(), to.display());
    }
}

/// A `go` invocation in the circuits module. `GOWORK=off` keeps a `go.work`
/// above the prover crate from switching Go to workspace mode, which rejects
/// `-modfile`.
fn go_command(dir: &Path, args: &[&OsStr]) -> Command {
    let mut command = Command::new("go");
    command
        .current_dir(dir)
        .env("CGO_ENABLED", "1")
        .env("GOWORK", "off")
        .args(args);
    command
}

fn describe(dir: &Path, args: &[&OsStr]) -> String {
    let args: Vec<_> = args.iter().map(|arg| arg.to_string_lossy()).collect();
    format!("go {} (in {})", args.join(" "), dir.display())
}

fn go<const N: usize>(dir: &Path, args: [&OsStr; N]) {
    let status = go_command(dir, &args)
        .status()
        .unwrap_or_else(|e| panic!("failed to run {}: {e}", describe(dir, &args)));
    assert!(status.success(), "{} failed", describe(dir, &args));
}

fn go_output<const N: usize>(dir: &Path, args: [&OsStr; N]) -> String {
    let output = go_command(dir, &args)
        .output()
        .unwrap_or_else(|e| panic!("failed to run {}: {e}", describe(dir, &args)));
    assert!(
        output.status.success(),
        "{} failed:\n{}",
        describe(dir, &args),
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout)
        .unwrap_or_else(|e| panic!("{} printed non-UTF-8: {e}", describe(dir, &args)))
}
