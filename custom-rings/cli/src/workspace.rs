use std::{
    collections::BTreeMap,
    env,
    fs::{self, File},
    io::{self, Read},
    path::{Path, PathBuf},
    process::Command,
};

use serde::Deserialize;
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::tool::{Tool, ToolError};

const RING_KEYS: [&str; 5] = [
    "custom_ring_base.key",
    "custom_ring_policy.key",
    "custom_ring_compressed_policy.key",
    "custom_ring_compressed_register.key",
    "custom_ring_delegate_policy.key",
];

/// Resolves checked local artifacts within a dedicated service process scope.
pub(crate) struct Workspace {
    pub root: PathBuf,
    pub scope: PathBuf,
    surfpool: PathBuf,
    keys_dir: PathBuf,
}

#[derive(Debug, Error)]
pub enum WorkspaceError {
    #[error("local artifacts require ZOLANA_RING_WORKSPACE and ZOLANA_PROCESS_SCOPE_DIR")]
    MissingEnvironment,
    #[error("workspace artifacts are only supported on localnet")]
    WrongTarget,
    #[error("{0} is not a dedicated absolute process scope directory")]
    InvalidScope(PathBuf),
    #[error("local artifact {0} is missing or outside the workspace")]
    MissingArtifact(PathBuf),
    #[error("set SURFPOOL_BIN to the pinned local surfpool binary")]
    MissingSurfpool,
    #[error("local key {0} disagrees with the workspace proving key manifest")]
    KeyMismatch(String),
    #[error("the workspace proving key manifest does not parse")]
    Manifest(#[from] serde_json::Error),
    #[error("cannot read local artifact {path}")]
    Io { path: PathBuf, source: io::Error },
    #[error(transparent)]
    Tool(#[from] ToolError),
    #[error("scratch account directory already exists at {0}")]
    ExistingAccounts(PathBuf),
}

/// Pins the proving keys accepted by the local workspace binary.
#[derive(Deserialize)]
struct KeyManifest {
    keys: BTreeMap<String, KeyDigest>,
}

/// Authenticates a cached proving key before a local prover starts.
#[derive(Deserialize)]
struct KeyDigest {
    size: u64,
    sha256: String,
}

impl Workspace {
    pub fn from_env() -> Result<Option<Self>, WorkspaceError> {
        // 1. Require an explicit workspace and independent process scope together.
        let root = env::var_os("ZOLANA_RING_WORKSPACE");
        let scope = env::var_os("ZOLANA_PROCESS_SCOPE_DIR");
        if root.is_none() && scope.is_none() {
            return Ok(None);
        }
        let root = PathBuf::from(root.ok_or(WorkspaceError::MissingEnvironment)?);
        let scope = PathBuf::from(scope.ok_or(WorkspaceError::MissingEnvironment)?);
        let root =
            fs::canonicalize(&root).map_err(|source| WorkspaceError::Io { path: root, source })?;
        validate_scope(&scope, &root)?;
        let surfpool = env::var_os("SURFPOOL_BIN")
            .map(PathBuf::from)
            .filter(|path| path.is_absolute() && path.is_file())
            .ok_or(WorkspaceError::MissingSurfpool)?;
        let keys_dir = env::var_os("ZOLANA_PROVER_KEYS_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|| root.join("prover/server/proving-keys"));
        if !keys_dir.is_absolute() {
            return Err(WorkspaceError::MissingArtifact(keys_dir));
        }
        let keys_dir =
            fs::canonicalize(&keys_dir).map_err(|_| WorkspaceError::MissingArtifact(keys_dir))?;
        let workspace = Self {
            root,
            scope,
            surfpool,
            keys_dir,
        };
        // 2. Validate local binaries and pinned ring keys without downloading replacements.
        for file in [
            "Cargo.toml",
            "target/debug/zolana",
            "target/debug/photon",
            "target/debug/ring-rpc",
            "target/debug/xtask",
            "target/prover-server",
            "target/deploy/shielded_pool_program.so",
            "target/deploy/custom_ring_program.so",
        ] {
            workspace.artifact(file)?;
        }
        workspace.check_keys()?;
        Ok(Some(workspace))
    }

    pub fn artifact(&self, relative: &str) -> Result<PathBuf, WorkspaceError> {
        let path = self.root.join(relative);
        let resolved =
            fs::canonicalize(&path).map_err(|_| WorkspaceError::MissingArtifact(path.clone()))?;
        if !resolved.starts_with(&self.root) || !resolved.is_file() {
            return Err(WorkspaceError::MissingArtifact(path));
        }
        Ok(resolved)
    }

    pub fn command(&self) -> Result<Command, WorkspaceError> {
        let mut command = Command::new(self.artifact("target/debug/zolana")?);
        command
            .current_dir(&self.root)
            .env("ZOLANA_PROCESS_SCOPE_DIR", &self.scope)
            .env("SURFPOOL_BIN", &self.surfpool)
            .env("ZOLANA_PHOTON_BIN", self.artifact("target/debug/photon")?)
            .env("PROVER_BIN", self.artifact("target/prover-server")?)
            .env("ZOLANA_PROVER_KEYS_DIR", &self.keys_dir);
        Ok(command)
    }

    pub fn account_snapshots(&self) -> Result<PathBuf, WorkspaceError> {
        let accounts = self
            .scope
            .join(format!("ring-accounts-{}", std::process::id()));
        if accounts.exists() {
            return Err(WorkspaceError::ExistingAccounts(accounts));
        }
        Tool {
            name: "local account snapshots",
            install: "build the workspace xtask",
        }
        .run(
            Command::new(self.artifact("target/debug/xtask")?)
                .arg("generate-account-snapshots")
                .arg("--deploy-dir")
                .arg(self.root.join("target/deploy"))
                .arg("--accounts-dir")
                .arg(&accounts),
        )?;
        Ok(accounts)
    }

    fn check_keys(&self) -> Result<(), WorkspaceError> {
        let path = self.artifact("prover/server/prover/provingkeys/proving-keys.lock")?;
        let file = File::open(&path).map_err(|source| WorkspaceError::Io { path, source })?;
        let manifest: KeyManifest = serde_json::from_reader(file)?;
        for name in RING_KEYS {
            let key = manifest
                .keys
                .get(name)
                .ok_or_else(|| WorkspaceError::KeyMismatch(name.into()))?;
            let path = self.keys_dir.join(name);
            let resolved = fs::canonicalize(&path)
                .map_err(|_| WorkspaceError::MissingArtifact(path.clone()))?;
            if !resolved.starts_with(&self.keys_dir) || !resolved.is_file() {
                return Err(WorkspaceError::MissingArtifact(path));
            }
            if !key
                .matches(&path)
                .map_err(|source| WorkspaceError::Io { path, source })?
            {
                return Err(WorkspaceError::KeyMismatch(name.into()));
            }
        }
        Ok(())
    }
}

impl KeyDigest {
    fn matches(&self, path: &Path) -> io::Result<bool> {
        let mut file = File::open(path)?;
        if file.metadata()?.len() != self.size {
            return Ok(false);
        }
        let mut hash = Sha256::new();
        let mut buffer = [0u8; 65536];
        loop {
            let read = file.read(&mut buffer)?;
            if read == 0 {
                break;
            }
            hash.update(&buffer[..read]);
        }
        Ok(hex::encode(hash.finalize()) == self.sha256)
    }
}

fn validate_scope(scope: &Path, root: &Path) -> Result<(), WorkspaceError> {
    let metadata =
        fs::symlink_metadata(scope).map_err(|_| WorkspaceError::InvalidScope(scope.into()))?;
    let canonical =
        fs::canonicalize(scope).map_err(|_| WorkspaceError::InvalidScope(scope.into()))?;
    if !scope.is_absolute()
        || !metadata.is_dir()
        || metadata.file_type().is_symlink()
        || canonical.parent().is_none()
        || scope == root
        || canonical == root
        || env::var_os("HOME").is_some_and(|home| canonical == home)
    {
        return Err(WorkspaceError::InvalidScope(scope.into()));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn local_keys_must_match_manifest_size_and_digest() {
        let root = env::temp_dir().join(format!(
            "ring-workspace-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir(&root).unwrap();
        let path = root.join("key");
        fs::write(&path, b"pinned key").unwrap();
        let key = KeyDigest {
            size: 10,
            sha256: hex::encode(Sha256::digest(b"pinned key")),
        };
        assert!(key.matches(&path).unwrap());
        fs::write(&path, b"edited key").unwrap();
        assert!(!key.matches(&path).unwrap());
        fs::write(&path, b"short").unwrap();
        assert!(!key.matches(&path).unwrap());
        assert!(validate_scope(&root, &root).is_err());
        assert!(validate_scope(&root, Path::new("/workspace")).is_ok());
        fs::remove_file(path).unwrap();
        fs::remove_dir(root).unwrap();
    }
}
