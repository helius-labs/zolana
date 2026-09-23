//! Build-script half of `zolana-gnark-ffi-prover`, kept dependency-free so it
//! adds nothing to the build-dependency graph. A prover crate's `build.rs` is
//! `fn main() -> Result<(), zolana_gnark_ffi_prover_build::BuildError> {
//! zolana_gnark_ffi_prover_build::build_prover_archive() }`.
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
    env, error,
    ffi::{OsStr, OsString},
    fmt, fs, io,
    path::{Path, PathBuf},
    process::{Command, ExitStatus},
    string::FromUtf8Error,
};

/// Module path of the Go bridge in this crate's `go/` directory.
const BRIDGE_MODULE: &str = "zolana/gnarkffiprover";

/// `Debug` prints the `Display` message, since a build script reports an `Err`
/// from `main` through `Debug`.
pub enum BuildError {
    MissingEnvVar(&'static str),
    CopyFile {
        from: PathBuf,
        to: PathBuf,
        source: io::Error,
    },
    RemoveStaleFile {
        path: PathBuf,
        source: io::Error,
    },
    GoNotStarted {
        command: String,
        source: io::Error,
    },
    /// `stderr` is empty when the output went straight to the build log.
    GoFailed {
        command: String,
        status: ExitStatus,
        stderr: String,
    },
    GoOutputNotUtf8 {
        command: String,
        source: FromUtf8Error,
    },
}

impl fmt::Display for BuildError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingEnvVar(name) => {
                write!(
                    f,
                    "{name} is not set; run build_prover_archive from a build script"
                )
            }
            Self::CopyFile { from, to, source } => write!(
                f,
                "failed to copy {} to {}: {source}",
                from.display(),
                to.display()
            ),
            Self::RemoveStaleFile { path, source } => {
                write!(f, "failed to remove {}: {source}", path.display())
            }
            Self::GoNotStarted { command, source } => {
                write!(f, "failed to run {command}: {source}")
            }
            Self::GoFailed {
                command,
                status,
                stderr,
            } => {
                write!(f, "{command} failed ({status})")?;
                if stderr.is_empty() {
                    Ok(())
                } else {
                    write!(f, ":\n{stderr}")
                }
            }
            Self::GoOutputNotUtf8 { command, source } => {
                write!(f, "{command} printed non-UTF-8 output: {source}")
            }
        }
    }
}

impl fmt::Debug for BuildError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

impl error::Error for BuildError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match self {
            Self::CopyFile { source, .. }
            | Self::RemoveStaleFile { source, .. }
            | Self::GoNotStarted { source, .. } => Some(source),
            Self::GoOutputNotUtf8 { source, .. } => Some(source),
            Self::MissingEnvVar(_) | Self::GoFailed { .. } => None,
        }
    }
}

/// Build the calling crate's `circuits/` Go `main` package into a C archive
/// and link it. The archive exports the bridge functions that
/// `zolana_gnark_ffi_prover::prover!` declares.
pub fn build_prover_archive() -> Result<(), BuildError> {
    let manifest_dir = env_path("CARGO_MANIFEST_DIR")?;
    let out_dir = env_path("OUT_DIR")?;
    let circuits = manifest_dir.join("circuits");
    let bridge = Path::new(env!("CARGO_MANIFEST_DIR")).join("go");
    let modfile = write_modfile(&circuits, &bridge, &out_dir)?;
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
    )?;

    // A stale archive proves a circuit the keys were not made for, so every
    // source compiled into it must rebuild it.
    for path in archive_sources(&circuits, &bridge, &modfile)? {
        println!("cargo:rerun-if-changed={}", path.display());
    }

    println!("cargo:rustc-link-search=native={}", out_dir.display());
    println!("cargo:rustc-link-lib=static=prover");
    if env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("macos") {
        println!("cargo:rustc-link-lib=framework=CoreFoundation");
        println!("cargo:rustc-link-lib=framework=Security");
        println!("cargo:rustc-link-lib=resolv");
    }
    Ok(())
}

/// Copy `circuits/go.mod` and `circuits/go.sum` into `out_dir` and add the
/// bridge `replace` to the copy. The returned modfile overrides any `replace`
/// of the bridge the circuits module declares: the archive must export the
/// ABI of the bridge shipped with this crate.
fn write_modfile(circuits: &Path, bridge: &Path, out_dir: &Path) -> Result<PathBuf, BuildError> {
    let modfile = out_dir.join("circuits.mod");
    // `go -modfile=<name>.mod` reads its checksums from `<name>.sum`.
    let sums = out_dir.join("circuits.sum");
    copy(&circuits.join("go.mod"), &modfile)?;
    let circuit_sums = circuits.join("go.sum");
    if circuit_sums.is_file() {
        copy(&circuit_sums, &sums)?;
    } else if let Err(source) = fs::remove_file(&sums) {
        if source.kind() != io::ErrorKind::NotFound {
            return Err(BuildError::RemoveStaleFile { path: sums, source });
        }
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
    )?;
    Ok(modfile)
}

/// The paths whose changes must rebuild the archive: the circuits directory,
/// the bridge, and every package the archive compiles from a local-directory
/// `replace` of the circuits module, with that module's `go.mod`. Packages
/// are watched rather than whole replacement modules, so unrelated files there
/// (binaries, downloaded keys) do not rebuild the archive. The circuits
/// module's own `go.mod` as Go reports it is the generated modfile, which is
/// rewritten on every build and must never be watched.
fn archive_sources(
    circuits: &Path,
    bridge: &Path,
    modfile: &Path,
) -> Result<BTreeSet<PathBuf>, BuildError> {
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
    )?;
    let mut paths: BTreeSet<PathBuf> = listed
        .lines()
        .filter(|line| !line.is_empty())
        .map(PathBuf::from)
        .collect();
    paths.insert(circuits.to_path_buf());
    paths.insert(bridge.to_path_buf());
    Ok(paths)
}

fn env_path(name: &'static str) -> Result<PathBuf, BuildError> {
    env::var_os(name)
        .map(PathBuf::from)
        .ok_or(BuildError::MissingEnvVar(name))
}

fn copy(from: &Path, to: &Path) -> Result<(), BuildError> {
    match fs::copy(from, to) {
        Ok(_) => Ok(()),
        Err(source) => Err(BuildError::CopyFile {
            from: from.to_path_buf(),
            to: to.to_path_buf(),
            source,
        }),
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

fn go<const N: usize>(dir: &Path, args: [&OsStr; N]) -> Result<(), BuildError> {
    let status = go_command(dir, &args)
        .status()
        .map_err(|source| BuildError::GoNotStarted {
            command: describe(dir, &args),
            source,
        })?;
    if status.success() {
        Ok(())
    } else {
        Err(BuildError::GoFailed {
            command: describe(dir, &args),
            status,
            stderr: String::new(),
        })
    }
}

fn go_output<const N: usize>(dir: &Path, args: [&OsStr; N]) -> Result<String, BuildError> {
    let output = go_command(dir, &args)
        .output()
        .map_err(|source| BuildError::GoNotStarted {
            command: describe(dir, &args),
            source,
        })?;
    if !output.status.success() {
        return Err(BuildError::GoFailed {
            command: describe(dir, &args),
            status: output.status,
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        });
    }
    String::from_utf8(output.stdout).map_err(|source| BuildError::GoOutputNotUtf8 {
        command: describe(dir, &args),
        source,
    })
}
