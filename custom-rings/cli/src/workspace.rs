use std::{
    collections::BTreeMap,
    env,
    fs::{self, File},
    io,
    path::{Path, PathBuf},
    process::Command,
};

use serde::Deserialize;
use thiserror::Error;

use crate::{
    release::{self, Asset, RingKey},
    tool::{Tool, ToolError},
};

pub(crate) const WORKSPACE_ENV: &str = "ZOLANA_RING_WORKSPACE";
pub(crate) const PROCESS_SCOPE_ENV: &str = "ZOLANA_PROCESS_SCOPE_DIR";
const SURFPOOL_ENV: &str = "SURFPOOL_BIN";
const PROVER_KEYS_ENV: &str = "ZOLANA_PROVER_KEYS_DIR";
const ZOLANA_BIN: &str = "target/debug/zolana";
const PHOTON_BIN: &str = "target/debug/photon";
const RING_RPC_BIN: &str = "target/debug/ring-rpc";
const XTASK_BIN: &str = "target/debug/xtask";
const PROVER_BIN: &str = "target/prover-server";
const SHIELDED_POOL_SO: &str = "target/deploy/shielded_pool_program.so";
const RING_PROGRAM_SO: &str = "target/deploy/custom_ring_program.so";
const PROVING_KEYS_LOCK: &str = "prover/server/prover/provingkeys/proving-keys.lock";
const PROVING_KEYS_DIR: &str = "prover/server/proving-keys";

pub(crate) struct Workspace {
    pub root: PathBuf,
    pub scope: PathBuf,
    surfpool: PathBuf,
    keys_dir: PathBuf,
}

#[derive(Debug, Error)]
pub enum WorkspaceError {
    #[error("local artifacts require {WORKSPACE_ENV} and {PROCESS_SCOPE_ENV}")]
    MissingEnvironment,
    #[error("workspace artifacts are only supported on localnet")]
    WrongTarget,
    #[error("{0} is not a dedicated absolute process scope directory")]
    InvalidScope(PathBuf),
    #[error("local artifact {0} is missing or outside the workspace")]
    MissingArtifact(PathBuf),
    #[error("set {SURFPOOL_ENV} to the pinned local surfpool binary")]
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

#[derive(Deserialize)]
struct KeyManifest {
    keys: BTreeMap<String, KeyPin>,
}

#[derive(Deserialize)]
struct KeyPin {
    size: u64,
    sha256: String,
}

impl Workspace {
    /// `Ok(None)` outside a workspace, both variables or neither.
    pub fn from_env() -> Result<Option<Self>, WorkspaceError> {
        let root = env::var_os(WORKSPACE_ENV);
        let scope = env::var_os(PROCESS_SCOPE_ENV);
        if root.is_none() && scope.is_none() {
            return Ok(None);
        }
        let root = PathBuf::from(root.ok_or(WorkspaceError::MissingEnvironment)?);
        let scope = PathBuf::from(scope.ok_or(WorkspaceError::MissingEnvironment)?);
        let root =
            fs::canonicalize(&root).map_err(|source| WorkspaceError::Io { path: root, source })?;
        validate_scope(&scope, &root)?;
        let surfpool = env::var_os(SURFPOOL_ENV)
            .map(PathBuf::from)
            .filter(|path| path.is_absolute() && path.is_file())
            .ok_or(WorkspaceError::MissingSurfpool)?;
        let keys_dir = env::var_os(PROVER_KEYS_ENV)
            .map(PathBuf::from)
            .unwrap_or_else(|| root.join(PROVING_KEYS_DIR));
        if !keys_dir.is_absolute() {
            return Err(WorkspaceError::MissingArtifact(keys_dir));
        }
        let keys_dir =
            fs::canonicalize(&keys_dir).map_err(|_| WorkspaceError::MissingArtifact(keys_dir))?;
        Ok(Some(Self {
            root,
            scope,
            surfpool,
            keys_dir,
        }))
    }

    pub fn ring_program_so(&self) -> Result<PathBuf, WorkspaceError> {
        self.artifact(RING_PROGRAM_SO)
    }

    pub fn shielded_pool_so(&self) -> Result<PathBuf, WorkspaceError> {
        self.artifact(SHIELDED_POOL_SO)
    }

    pub fn ring_rpc(&self) -> Result<PathBuf, WorkspaceError> {
        self.artifact(RING_RPC_BIN)
    }

    pub fn command(&self) -> Result<Command, WorkspaceError> {
        let mut command = Command::new(self.artifact(ZOLANA_BIN)?);
        command
            .current_dir(&self.root)
            .env(PROCESS_SCOPE_ENV, &self.scope)
            .env(SURFPOOL_ENV, &self.surfpool)
            .env("ZOLANA_PHOTON_BIN", self.artifact(PHOTON_BIN)?)
            .env("PROVER_BIN", self.artifact(PROVER_BIN)?)
            .env(PROVER_KEYS_ENV, &self.keys_dir);
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
            Command::new(self.artifact(XTASK_BIN)?)
                .arg("generate-account-snapshots")
                .arg("--deploy-dir")
                .arg(self.root.join("target/deploy"))
                .arg("--accounts-dir")
                .arg(&accounts),
        )?;
        Ok(accounts)
    }

    pub fn check_artifacts(&self) -> Result<(), WorkspaceError> {
        for file in [
            "Cargo.toml",
            ZOLANA_BIN,
            PHOTON_BIN,
            RING_RPC_BIN,
            XTASK_BIN,
            PROVER_BIN,
            SHIELDED_POOL_SO,
            RING_PROGRAM_SO,
        ] {
            self.artifact(file)?;
        }
        let path = self.artifact(PROVING_KEYS_LOCK)?;
        let file = File::open(&path).map_err(|source| WorkspaceError::Io { path, source })?;
        let manifest: KeyManifest = serde_json::from_reader(file)?;
        for key in RingKey::ALL {
            let name = key.file_name();
            let pin = manifest
                .keys
                .get(name)
                .ok_or_else(|| WorkspaceError::KeyMismatch(name.into()))?;
            let path = self.keys_dir.join(name);
            let resolved = fs::canonicalize(&path)
                .map_err(|_| WorkspaceError::MissingArtifact(path.clone()))?;
            if !resolved.starts_with(&self.keys_dir) || !resolved.is_file() {
                return Err(WorkspaceError::MissingArtifact(path));
            }
            let bytes =
                fs::read(&resolved).map_err(|source| WorkspaceError::Io { path, source })?;
            release::verify(&bytes, &pin.asset(name))
                .map_err(|_| WorkspaceError::KeyMismatch(name.into()))?;
        }
        Ok(())
    }

    fn artifact(&self, relative: &str) -> Result<PathBuf, WorkspaceError> {
        let path = self.root.join(relative);
        let resolved =
            fs::canonicalize(&path).map_err(|_| WorkspaceError::MissingArtifact(path.clone()))?;
        if !resolved.starts_with(&self.root) || !resolved.is_file() {
            return Err(WorkspaceError::MissingArtifact(path));
        }
        Ok(resolved)
    }
}

impl KeyPin {
    fn asset(&self, name: &str) -> Asset {
        Asset {
            name: name.to_owned(),
            size: self.size,
            sha256: self.sha256.clone(),
        }
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
    fn the_scope_is_neither_the_workspace_nor_a_link() {
        let root = env::temp_dir().join(format!(
            "ring-workspace-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir(&root).unwrap();
        assert!(validate_scope(&root, &root).is_err());
        assert!(validate_scope(&root, Path::new("/workspace")).is_ok());
        assert!(validate_scope(Path::new("relative"), Path::new("/workspace")).is_err());
        fs::remove_dir(root).unwrap();
    }
}
