use std::{
    env, fs,
    path::{Path, PathBuf},
    process::Command,
};

use anyhow::{bail, ensure, Context as _, Result};
use zolana_cli_common::{
    process::PROCESS_SCOPE_ENV,
    release::{verify, Asset},
};

use crate::{release::RING_KEYS, tool::Tool};

const WORKSPACE_ENV: &str = "ZOLANA_RING_WORKSPACE";
pub(crate) const WRONG_TARGET: &str = "workspace artifacts are only supported on localnet";
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

/// Local builds of every service, run in a dedicated process scope.
pub(crate) struct Workspace {
    root: PathBuf,
    scope: PathBuf,
    surfpool: PathBuf,
    keys_dir: PathBuf,
}

impl Workspace {
    /// `Ok(None)` outside a workspace, both variables or neither.
    pub fn from_env() -> Result<Option<Self>> {
        let (root, scope) = match (env::var_os(WORKSPACE_ENV), env::var_os(PROCESS_SCOPE_ENV)) {
            (None, None) => return Ok(None),
            (Some(root), Some(scope)) => (PathBuf::from(root), PathBuf::from(scope)),
            _ => bail!("local artifacts require {WORKSPACE_ENV} and {PROCESS_SCOPE_ENV}"),
        };
        let root =
            fs::canonicalize(&root).with_context(|| format!("cannot read {}", root.display()))?;
        validate_scope(&scope, &root)?;
        let surfpool = env::var_os(SURFPOOL_ENV)
            .map(PathBuf::from)
            .filter(|path| path.is_absolute() && path.is_file())
            .with_context(|| format!("set {SURFPOOL_ENV} to the pinned local surfpool binary"))?;
        let keys_dir =
            env::var_os(PROVER_KEYS_ENV).map_or_else(|| root.join(PROVING_KEYS_DIR), PathBuf::from);
        let keys_dir = fs::canonicalize(&keys_dir)
            .ok()
            .filter(|_| keys_dir.is_absolute())
            .with_context(|| missing(&keys_dir))?;
        Ok(Some(Self {
            root,
            scope,
            surfpool,
            keys_dir,
        }))
    }

    pub fn ring_program_so(&self) -> Result<PathBuf> {
        self.artifact(RING_PROGRAM_SO)
    }

    pub fn shielded_pool_so(&self) -> Result<PathBuf> {
        self.artifact(SHIELDED_POOL_SO)
    }

    pub fn ring_rpc(&self) -> Result<PathBuf> {
        self.artifact(RING_RPC_BIN)
    }

    /// The workspace `zolana` cli, pointed at the workspace services and keys.
    pub fn command(&self) -> Result<Command> {
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

    pub fn account_snapshots(&self) -> Result<PathBuf> {
        let accounts = self
            .scope
            .join(format!("ring-accounts-{}", std::process::id()));
        let shown = accounts.display();
        ensure!(
            !accounts.exists(),
            "scratch account directory already exists at {shown}"
        );
        let snapshots = Tool::new("local account snapshots", "build the workspace xtask");
        snapshots.run(
            Command::new(self.artifact(XTASK_BIN)?)
                .arg("generate-account-snapshots")
                .arg("--deploy-dir")
                .arg(self.root.join("target/deploy"))
                .arg("--accounts-dir")
                .arg(&accounts),
        )?;
        Ok(accounts)
    }

    /// Every binary is built and each ring key matches the workspace lockfile.
    pub fn check_artifacts(&self) -> Result<()> {
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
        let lock: serde_json::Value =
            serde_json::from_slice(&fs::read(self.artifact(PROVING_KEYS_LOCK)?)?)?;
        for key in RING_KEYS {
            let name = key.file_name();
            let pin = &lock["keys"][&name];
            let pinned = Asset {
                name: name.clone(),
                size: pin["size"].as_u64().unwrap_or_default(),
                sha256: pin["sha256"].as_str().unwrap_or_default().to_owned(),
            };
            let bytes = fs::read(within(&self.keys_dir, &self.keys_dir.join(&name))?)?;
            verify(&bytes, &pinned).with_context(|| {
                format!("local key {name} disagrees with the workspace proving key manifest")
            })?;
        }
        Ok(())
    }

    fn artifact(&self, relative: &str) -> Result<PathBuf> {
        within(&self.root, &self.root.join(relative))
    }
}

/// The resolved file, refused when a link leads outside `root`.
fn within(root: &Path, path: &Path) -> Result<PathBuf> {
    fs::canonicalize(path)
        .ok()
        .filter(|resolved| resolved.starts_with(root) && resolved.is_file())
        .with_context(|| missing(path))
}

fn missing(path: &Path) -> String {
    let path = path.display();
    format!("local artifact {path} is missing or outside the workspace")
}

fn validate_scope(scope: &Path, root: &Path) -> Result<()> {
    let shown = scope.display();
    let refused = || format!("{shown} is not a dedicated absolute process scope directory");
    let metadata = fs::symlink_metadata(scope).with_context(refused)?;
    let canonical = fs::canonicalize(scope).with_context(refused)?;
    ensure!(
        scope.is_absolute()
            && metadata.is_dir()
            && !metadata.file_type().is_symlink()
            && canonical.parent().is_some()
            && scope != root
            && canonical != root
            && env::var_os("HOME").is_none_or(|home| canonical != home),
        refused()
    );
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
        let root = fs::canonicalize(root).unwrap();
        assert!(validate_scope(&root, &root).is_err());
        assert!(validate_scope(&root, Path::new("/workspace")).is_ok());
        assert!(validate_scope(Path::new("relative"), Path::new("/workspace")).is_err());
        let file = root.join("file");
        fs::write(&file, b"x").unwrap();
        assert!(within(&root, &file).is_ok());
        assert!(within(&root.join("nested"), &file).is_err());
        fs::remove_dir_all(root).unwrap();
    }
}
