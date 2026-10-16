use std::{path::PathBuf, process::ExitStatus};

use crate::ProverError;

/// Why building a circuit crate failed.
#[derive(Debug, thiserror::Error)]
pub enum BuildError {
    #[error("{action} {}: {error}", path.display())]
    File {
        action: &'static str,
        path: PathBuf,
        error: std::io::Error,
    },
    #[error("running {command}{hint}: {error}")]
    Spawn {
        command: String,
        hint: &'static str,
        error: std::io::Error,
    },
    #[error("{command} failed ({status}){output}")]
    CommandFailed {
        command: String,
        status: ExitStatus,
        output: String,
    },
    #[error("cargo metadata for {}: {reason}", manifest.display())]
    Metadata {
        manifest: PathBuf,
        reason: &'static str,
    },
    #[error("no Cargo.toml in {} or its parents", .0.display())]
    NoManifest(PathBuf),
    #[error("the workspace of {} has no package `{package}`", manifest.display())]
    NoSuchPackage { manifest: PathBuf, package: String },
    #[error("{} is not a package manifest; pass -p <package> or --manifest-path", .0.display())]
    NotAPackage(PathBuf),
    #[error(
        "{} depends on neither zolana-zk-dsl nor zolana-program, so it has no wasm runtime to build",
        .0.display()
    )]
    NoCircuitLibrary(PathBuf),
    #[error(
        "{} derives no ZK circuit: a circuit is a struct with exactly `private` and `public` fields deriving ZkCircuit",
        .0.display()
    )]
    NoCircuits(PathBuf),
    #[error("skipping the r1cs, the keys and the wasm leaves nothing to compile")]
    NothingToCompile,
    #[error(
        "only the test setup runs here; pass `test` for local keys, or run a ceremony and import its zkey"
    )]
    TestSetupNotAcknowledged,
    #[error("no .{extension} files in {}; run `{producer}` first or pass the files", dir.display())]
    NoInputs {
        extension: &'static str,
        dir: PathBuf,
        producer: &'static str,
    },
    #[error("{} has no UTF-8 file name", .0.display())]
    FileName(PathBuf),
    #[error("{} is not a <circuit>.verifier.rs module", .0.display())]
    NotAVerifierModule(PathBuf),
    #[error("{0} has a verifying key but no {0}.verifier.rs; compile the circuits first")]
    KeyWithoutVerifier(String),
    #[error(
        "{count} verifier module file(s) in {} are out of date; rerun without the check to regenerate them",
        dir.display()
    )]
    StaleVerifierModules { count: usize, dir: PathBuf },
    #[error("{}:{line}: {reason}", manifest.display())]
    ChecksumManifest {
        manifest: PathBuf,
        line: usize,
        reason: &'static str,
    },
    #[error("{} contains no key checksums", .0.display())]
    NoChecksums(PathBuf),
    #[error("duplicate checksum for {}", .0.display())]
    DuplicateChecksum(PathBuf),
    #[error("{} has no checksum in {}", key.display(), manifest.display())]
    MissingChecksum { key: PathBuf, manifest: PathBuf },
    #[error(
        "wasm-bindgen-rayon no longer declares initThreadPool as expected in {}",
        .0.display()
    )]
    ThreadPoolDeclaration(PathBuf),
    #[error("the wasm build panicked")]
    WasmBuildPanicked,
    #[error("{action} {}: {error}", path.display())]
    Prover {
        action: &'static str,
        path: PathBuf,
        error: ProverError,
    },
}

impl BuildError {
    pub(crate) fn file(
        action: &'static str,
        path: impl Into<PathBuf>,
    ) -> impl FnOnce(std::io::Error) -> Self {
        let path = path.into();
        move |error| Self::File {
            action,
            path,
            error,
        }
    }

    pub(crate) fn prover(
        action: &'static str,
        path: impl Into<PathBuf>,
    ) -> impl FnOnce(ProverError) -> Self {
        let path = path.into();
        move |error| Self::Prover {
            action,
            path,
            error,
        }
    }
}
