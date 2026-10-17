//! circomlib's `circuits` directory at a pinned commit, for circom references
//! that `include` its templates. circomlib is GPL-3.0: it is fetched into
//! `CARGO_TARGET_TMPDIR` and never committed.
//!
//! `CIRCOMLIB_DIR` may name a local clone instead of the fetch. It must be a
//! git checkout whose `HEAD` is exactly [`COMMIT`] and whose `circuits/` has no
//! uncommitted change, so every run compiles the same templates; any other
//! state panics rather than falling back to the fetch.
//!
//! Without it, the first caller fetches [`COMMIT`] alone (`git init`, then a
//! depth-1 `git fetch` of the commit and a detached checkout) into
//! `CARGO_TARGET_TMPDIR/zolana-program-unit/circomlib`, behind the harness file
//! lock; later callers find `HEAD` at the commit and reuse it.

#![cfg(feature = "external-tools")]

use std::{
    path::{Path, PathBuf},
    process::Command,
};

use super::{artifacts, circom, locked, path};

pub const COMMIT: &str = "35e54ea21da3e8762557234298dbb553c175ea8d";
pub const REPOSITORY: &str = "https://github.com/iden3/circomlib";
pub const DIR_VARIABLE: &str = "CIRCOMLIB_DIR";

pub fn circuits() -> PathBuf {
    match std::env::var_os(DIR_VARIABLE) {
        Some(dir) => local(Path::new(&dir)),
        None => fetched(),
    }
}

/// Compiles a circom file under `tests/unit` with circomlib's `circuits` on
/// the include path, so it can `include "comparators.circom";`.
pub fn compile(relative: &str) -> circom::Compiled {
    circom::compile_with(relative, &[circuits()])
}

fn local(root: &Path) -> PathBuf {
    let head = git(root, &["rev-parse", "HEAD"]);
    assert_eq!(
        (
            head.as_deref(),
            git(root, &["status", "--porcelain", "--", "circuits"]).as_deref()
        ),
        (Ok(COMMIT), Ok("")),
        "{DIR_VARIABLE}={} must be a clean circomlib checkout at {COMMIT}",
        root.display()
    );
    root.join("circuits")
}

fn fetched() -> PathBuf {
    let root = artifacts().join("circomlib");
    let _lock = locked(&root);
    if git(&root, &["rev-parse", "HEAD"]).as_deref() != Ok(COMMIT) {
        for args in [
            &["init", "--quiet"][..],
            &["fetch", "--quiet", "--depth", "1", REPOSITORY, COMMIT],
            &["checkout", "--quiet", "--force", "--detach", "FETCH_HEAD"],
        ] {
            if let Err(log) = git(&root, args) {
                panic!("git {args:?} in {} failed:\n{log}", root.display());
            }
        }
        assert_eq!(
            git(&root, &["rev-parse", "HEAD"]).as_deref(),
            Ok(COMMIT),
            "fetched circomlib HEAD"
        );
    }
    root.join("circuits")
}

fn git(dir: &Path, args: &[&str]) -> Result<String, String> {
    let output = Command::new("git")
        .arg("-C")
        .arg(path(dir))
        .args(args)
        .output()
        .expect("git on PATH");
    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if output.status.success() {
        Ok(stdout)
    } else {
        Err(format!(
            "{stdout}\n{}",
            String::from_utf8_lossy(&output.stderr)
        ))
    }
}
