//! Reuse of an up-to-date wasm package, the way cargo skips an unchanged
//! build. The package marker records what the package was built from: one
//! digest over the build settings, and the SHA-256 of every local source file
//! cargo read for the wasm build. A compile whose settings digest matches and
//! whose recorded sources are unchanged leaves the package as it is.
//!
//! The settings cover the CLI binary, the Rust toolchain and wasm-pack, the
//! cargo and rustc environment, the workspace and crate manifests (profiles)
//! and every cargo config file that applies, the compile options and
//! features, the resolved dependency graph, the circuit artifacts each
//! program's client is generated from, and the files copied into the package
//! as they are. Files under the cargo
//! home are versioned by that dependency graph, so only the other sources the
//! build's dep-info lists are hashed.

use super::{error, read, Result};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
    process::Command,
    time::SystemTime,
};

/// How much earlier than the build start a source must have been modified to
/// count as read in its recorded state.
const MTIME_MARGIN: std::time::Duration = std::time::Duration::from_secs(5);

/// Changes whenever the marker layout or the inputs it covers change, so a
/// marker from another CLI version never matches.
const FINGERPRINT_VERSION: u64 = 1;

/// What one wasm package was built from.
#[derive(Debug, PartialEq, Eq)]
pub(super) struct Fingerprint {
    settings: String,
    sources: BTreeMap<PathBuf, String>,
}

impl Fingerprint {
    pub(super) fn new(settings: String, sources: BTreeMap<PathBuf, String>) -> Self {
        Self { settings, sources }
    }

    /// The marker body: a note for readers and the fingerprint.
    pub(super) fn marker(&self) -> Result<Vec<u8>> {
        Ok(serde_json::to_vec_pretty(&json!({
            "note": "Written by `zolana zk compile`, which rebuilds this directory when its inputs change.",
            "version": FINGERPRINT_VERSION,
            "settings": self.settings,
            "sources": self.sources,
        }))?)
    }

    fn parse(marker: &[u8]) -> Option<Self> {
        let value: Value = serde_json::from_slice(marker).ok()?;
        if value["version"].as_u64() != Some(FINGERPRINT_VERSION) {
            return None;
        }
        let sources = value["sources"]
            .as_object()?
            .iter()
            .map(|(path, digest)| Some((PathBuf::from(path), digest.as_str()?.to_owned())))
            .collect::<Option<_>>()?;
        Some(Self {
            settings: value["settings"].as_str()?.to_owned(),
            sources,
        })
    }
}

/// Whether the package in `directory` still holds its wasm module and was
/// built from `settings` and sources that are unchanged on disk. A missing,
/// older or unreadable marker is not.
pub(super) fn up_to_date(directory: &Path, settings: &str) -> bool {
    let Some(recorded) = fs::read(directory.join(super::PACKAGE_MARKER))
        .ok()
        .and_then(|bytes| Fingerprint::parse(&bytes))
    else {
        return false;
    };
    let has_module = fs::read_dir(directory).is_ok_and(|mut entries| {
        entries.any(|entry| {
            entry.is_ok_and(|entry| entry.path().extension().is_some_and(|ext| ext == "wasm"))
        })
    });
    has_module
        && recorded.settings == settings
        && !recorded.sources.is_empty()
        && recorded
            .sources
            .iter()
            .all(|(path, digest)| fs::read(path).is_ok_and(|contents| sha256(&contents) == *digest))
}

/// Inputs to the settings digest that are not read from the filesystem.
pub(super) struct Settings<'a> {
    pub(super) crate_dir: &'a Path,
    pub(super) workspace_root: &'a Path,
    /// `cargo metadata` of the workspace, which resolves every manifest and
    /// the lockfile.
    pub(super) dependency_graph: &'a [u8],
    pub(super) options: Value,
    /// Each program's circuit artifact directory.
    pub(super) artifacts: Vec<(&'a str, PathBuf)>,
    /// Files copied into the package as they are, outside any cargo build.
    pub(super) copied: Vec<PathBuf>,
}

impl Settings<'_> {
    pub(super) fn digest(&self) -> Result<String> {
        let mut hasher = Sha256::new();
        let mut part = |label: &str, bytes: &[u8]| {
            hasher.update((label.len() as u64).to_le_bytes());
            hasher.update(label.as_bytes());
            hasher.update((bytes.len() as u64).to_le_bytes());
            hasher.update(bytes);
        };
        part("version", &FINGERPRINT_VERSION.to_le_bytes());
        part("cli", &read(&std::env::current_exe()?)?);
        part(
            "rustc",
            &output(Command::new("rustc").arg("-vV"), self.crate_dir)?,
        );
        part(
            "wasm-pack",
            &output(Command::new("wasm-pack").arg("--version"), self.crate_dir)?,
        );
        for (name, value) in build_environment(std::env::vars_os()) {
            part(&name, value.as_encoded_bytes());
        }
        for file in cargo_configuration(self.crate_dir, self.workspace_root, cargo_home()) {
            part(&file.to_string_lossy(), &read(&file)?);
        }
        part("options", &serde_json::to_vec(&self.options)?);
        part("dependency-graph", self.dependency_graph);
        for (name, artifact) in &self.artifacts {
            part("program", name.as_bytes());
            let mut files = fs::read_dir(artifact)?
                .map(|entry| entry.map(|entry| entry.path()))
                .collect::<std::io::Result<Vec<_>>>()?;
            files.sort();
            for file in files.iter().filter(|file| file.is_file()) {
                let name = file.file_name().unwrap_or_default().to_string_lossy();
                part(&name, &read(file)?);
            }
        }
        for file in &self.copied {
            part(&file.to_string_lossy(), &read(file)?);
        }
        Ok(hex::encode(hasher.finalize()))
    }
}

/// The variables that change what cargo and rustc build, sorted by name.
fn build_environment(
    variables: impl Iterator<Item = (std::ffi::OsString, std::ffi::OsString)>,
) -> BTreeMap<String, std::ffi::OsString> {
    const NAMES: [&str; 7] = [
        "RUSTUP_TOOLCHAIN",
        "RUSTFLAGS",
        "RUSTDOCFLAGS",
        "RUSTC",
        "RUSTC_WRAPPER",
        "RUSTC_WORKSPACE_WRAPPER",
        "RUSTC_BOOTSTRAP",
    ];
    const PREFIXES: [&str; 6] = [
        "CARGO_BUILD_",
        "CARGO_PROFILE_",
        "CARGO_TARGET_",
        "CARGO_ENCODED_",
        "CARGO_UNSTABLE_",
        "WASM_BINDGEN_",
    ];
    variables
        .filter_map(|(name, value)| Some((name.into_string().ok()?, value)))
        .filter(|(name, _)| {
            NAMES.contains(&name.as_str()) || PREFIXES.iter().any(|prefix| name.starts_with(prefix))
        })
        .collect()
}

/// The manifests whose profiles apply to the build and every cargo config
/// file cargo reads for it: `.cargo/config[.toml]` in the crate directory and
/// each ancestor, and in the cargo home.
fn cargo_configuration(
    crate_dir: &Path,
    workspace_root: &Path,
    cargo_home: Option<PathBuf>,
) -> Vec<PathBuf> {
    let mut files = vec![
        workspace_root.join("Cargo.toml"),
        crate_dir.join("Cargo.toml"),
    ];
    let config_dirs = crate_dir
        .ancestors()
        .map(|dir| dir.join(".cargo"))
        .chain(cargo_home);
    for dir in config_dirs {
        files.push(dir.join("config.toml"));
        files.push(dir.join("config"));
    }
    files.retain(|file| file.is_file());
    files.dedup();
    files
}

/// The local sources the release wasm build of the library `lib_name` read,
/// from its dep-info under `target_dir`. None are recorded, so the package is
/// rebuilt next time, without a dep-info, when a listed path is not a readable
/// file, or when a source changed after `started`, as the build may have read
/// the earlier content.
pub(super) fn built_sources(
    target_dir: &Path,
    lib_name: Option<&str>,
    started: SystemTime,
) -> Result<BTreeMap<PathBuf, String>> {
    let (Some(lib_name), Some(cargo_home)) = (lib_name, cargo_home()) else {
        return Ok(BTreeMap::new());
    };
    let dep_info = target_dir
        .join("wasm32-unknown-unknown/release")
        .join(format!("{lib_name}.d"));
    if !dep_info.is_file() {
        return Ok(BTreeMap::new());
    }
    sources(&dep_info, &cargo_home, started)
}

/// The local source files a build read, from cargo's dep-info for its output,
/// with their SHA-256. Files under `cargo_home` are left out. Empty when a
/// listed path is not a readable file or was modified after `started`.
fn sources(
    dep_info: &Path,
    cargo_home: &Path,
    started: SystemTime,
) -> Result<BTreeMap<PathBuf, String>> {
    let contents = String::from_utf8(read(dep_info)?).map_err(error)?;
    let line = contents
        .lines()
        .next()
        .ok_or_else(|| error(format!("{} is empty", dep_info.display())))?;
    let (_, dependencies) = split_unescaped(line, ':')
        .ok_or_else(|| error(format!("{} is not cargo dep-info", dep_info.display())))?;
    // File timestamps can lag the clock and round down to a coarse
    // granularity, so a file saved just after the build started may carry an
    // earlier time. Only files older than this margin count as unchanged.
    let settled = started
        .checked_sub(MTIME_MARGIN)
        .unwrap_or(SystemTime::UNIX_EPOCH);
    let mut sources = BTreeMap::new();
    for path in dep_info_paths(dependencies) {
        if path.starts_with(cargo_home) {
            continue;
        }
        let unchanged = fs::metadata(&path)
            .and_then(|metadata| metadata.modified())
            .is_ok_and(|modified| modified < settled);
        let Some(contents) = unchanged.then(|| fs::read(&path).ok()).flatten() else {
            return Ok(BTreeMap::new());
        };
        sources.insert(path, sha256(&contents));
    }
    Ok(sources)
}

/// The cargo home, under which registry and git dependency sources live.
fn cargo_home() -> Option<PathBuf> {
    std::env::var_os("CARGO_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".cargo")))
}

/// Splits `line` at the first `separator` that is not escaped by a backslash.
fn split_unescaped(line: &str, separator: char) -> Option<(&str, &str)> {
    let mut escaped = false;
    for (index, character) in line.char_indices() {
        if escaped {
            escaped = false;
        } else if character == '\\' {
            escaped = true;
        } else if character == separator {
            let rest = line.get(index + character.len_utf8()..)?;
            return Some((line.get(..index)?, rest));
        }
    }
    None
}

/// The paths of a dep-info dependency list: separated by spaces, with a space
/// inside a path escaped as `\ `.
fn dep_info_paths(list: &str) -> Vec<PathBuf> {
    let mut paths = Vec::new();
    let mut current = String::new();
    let mut characters = list.chars().peekable();
    while let Some(character) = characters.next() {
        match character {
            '\\' if characters.peek() == Some(&' ') => {
                current.push(' ');
                characters.next();
            }
            ' ' | '\t' => {
                if !current.is_empty() {
                    paths.push(PathBuf::from(std::mem::take(&mut current)));
                }
            }
            _ => current.push(character),
        }
    }
    if !current.is_empty() {
        paths.push(PathBuf::from(current));
    }
    paths
}

fn output(command: &mut Command, directory: &Path) -> Result<Vec<u8>> {
    let display = format!("{command:?}");
    let output = command
        .current_dir(directory)
        .output()
        .map_err(|e| error(format!("{display}: {e}")))?;
    if !output.status.success() {
        return Err(error(format!("{display} failed: {}", output.status)));
    }
    Ok(output.stdout)
}

fn sha256(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

#[cfg(test)]
#[path = "../../../tests/unit/wasm_cache.rs"]
mod tests;
