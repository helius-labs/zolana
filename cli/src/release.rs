use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
};

use anyhow::{anyhow, bail, Context, Result};
use serde::Deserialize;
use solana_pubkey::Pubkey;
use zolana_cli_common::release::{
    cache_dir, download, ensure_cached, host_platform, make_executable, Asset, BinaryAsset,
};

use crate::{args::ProgramSpec, process::path_string};

const LOCK_JSON: &str = include_str!("../release-artifacts.lock");

const SURFPOOL_BASE_URL: &str = "https://github.com/Lightprotocol/surfpool/releases/download";
/// The surfpool tarball has no pinned size.
const SURFPOOL_MAX_BYTES: u64 = 1 << 30;

// The Squads smart-account program id is fixed on mainnet; shielded-pool and
// user-registry ids come from the interface crates so they cannot drift.
const SMART_ACCOUNT_PROGRAM_ID: &str = "SMRTzfY6DfH5ik3TKiyLFfXexV8uSG3d2UksSCYdunG";

#[derive(Debug, Deserialize)]
pub(crate) struct ReleaseLock {
    pub release_tag: String,
    pub surfpool_tag: String,
    pub surfpool_version: String,
    pub programs: Vec<ProgramAsset>,
    pub accounts: Asset,
    pub binaries: Vec<BinaryAsset>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct ProgramAsset {
    pub role: String,
    #[serde(flatten)]
    pub file: Asset,
}

pub(crate) struct Release {
    lock: ReleaseLock,
}

impl Release {
    pub(crate) fn load() -> Result<Self> {
        let lock = serde_json::from_str(LOCK_JSON)
            .context("failed to parse embedded release-artifacts.lock")?;
        Ok(Self { lock })
    }

    pub(crate) fn tag(&self) -> &str {
        &self.lock.release_tag
    }

    /// Downloads (cache-first) each pinned program `.so` and pairs it with the
    /// on-chain program id so the caller can build `--bpf-program` args.
    pub(crate) fn program_specs(&self) -> Result<Vec<ProgramSpec>> {
        self.lock
            .programs
            .iter()
            .map(|program| {
                let path = ensure_cached(&self.lock.release_tag, &program.file)?;
                Ok(ProgramSpec {
                    address: program_id_for_role(&program.role)?,
                    path: path_string(&path)?,
                })
            })
            .collect()
    }

    /// Downloads and extracts the account-snapshot bundle, returning the
    /// directory to hand to the validator via `--account-dir`.
    pub(crate) fn accounts_dir(&self) -> Result<PathBuf> {
        let archive = ensure_cached(&self.lock.release_tag, &self.lock.accounts)?;
        let dir = cache_dir(&self.lock.release_tag).join("accounts");
        // Re-extract each run: the archive is checksum-verified and extraction is
        // cheap, so a partially-populated dir from an interrupted run self-heals.
        extract_tar_gz(&archive, &dir)?;
        Ok(dir)
    }

    pub(crate) fn prover_binary(&self) -> Result<PathBuf> {
        self.binary("prover")
    }

    pub(crate) fn photon_binary(&self) -> Result<PathBuf> {
        self.binary("photon")
    }

    fn binary(&self, role: &str) -> Result<PathBuf> {
        let (os, arch) = host_platform()?;
        let asset = select_binary(&self.lock, role, os, arch).ok_or_else(|| {
            anyhow!("release-artifacts.lock has no {role} binary for {os}-{arch}")
        })?;
        let path = ensure_cached(&self.lock.release_tag, &asset.asset)?;
        make_executable(&path)?;
        Ok(path)
    }

    /// Downloads the custom surfpool binary from its own release. The tarball has
    /// no lockfile checksum (separate repo), so integrity is asserted via
    /// `surfpool --version`, matching the `just install-surfpool` recipe.
    pub(crate) fn surfpool_binary(&self) -> Result<PathBuf> {
        let (os, arch) = host_platform()?;
        let dir = cache_dir(&self.lock.release_tag).join("surfpool");
        let bin = dir.join("surfpool");
        if bin.is_file() && surfpool_version_matches(&bin, &self.lock.surfpool_version) {
            return Ok(bin);
        }

        fs::create_dir_all(&dir).with_context(|| format!("failed to create {}", dir.display()))?;
        let asset_name = format!("surfpool-{os}-{arch}.tar.gz");
        let url = format!(
            "{SURFPOOL_BASE_URL}/{}/{asset_name}",
            self.lock.surfpool_tag
        );
        println!("Downloading {url}");
        let bytes = download(&url, SURFPOOL_MAX_BYTES)?;
        let archive = dir.join(&asset_name);
        fs::write(&archive, &bytes)
            .with_context(|| format!("failed to write {}", archive.display()))?;
        extract_tar_gz(&archive, &dir)?;

        let found = find_named(&dir, "surfpool")?
            .ok_or_else(|| anyhow!("surfpool binary not found in {asset_name}"))?;
        if found != bin {
            fs::copy(&found, &bin)
                .with_context(|| format!("failed to place surfpool at {}", bin.display()))?;
        }
        make_executable(&bin)?;

        if !surfpool_version_matches(&bin, &self.lock.surfpool_version) {
            bail!(
                "downloaded surfpool does not report version {}",
                self.lock.surfpool_version
            );
        }
        Ok(bin)
    }
}

fn program_id_for_role(role: &str) -> Result<String> {
    let id = match role {
        "shielded_pool" => {
            Pubkey::new_from_array(zolana_interface::SHIELDED_POOL_PROGRAM_ID).to_string()
        }
        "user_registry" => {
            Pubkey::new_from_array(zolana_user_registry_interface::USER_REGISTRY_PROGRAM_ID)
                .to_string()
        }
        "smart_account" => SMART_ACCOUNT_PROGRAM_ID.to_string(),
        other => bail!("unknown program role in release-artifacts.lock: {other}"),
    };
    Ok(id)
}

fn select_binary<'a>(
    lock: &'a ReleaseLock,
    role: &str,
    os: &str,
    arch: &str,
) -> Option<&'a BinaryAsset> {
    lock.binaries
        .iter()
        .find(|binary| binary.role == role && binary.os == os && binary.arch == arch)
}

fn extract_tar_gz(archive: &Path, dest: &Path) -> Result<()> {
    fs::create_dir_all(dest).with_context(|| format!("failed to create {}", dest.display()))?;
    // Exclude macOS AppleDouble/.DS_Store sidecars: if a snapshot tarball was
    // packed on macOS with them, GNU tar would materialize them into the account
    // dir and the validator would try to parse them as account JSON and fail.
    let status = Command::new("tar")
        .args(["--exclude=._*", "--exclude=.DS_Store", "-xzf"])
        .arg(archive)
        .arg("-C")
        .arg(dest)
        .status()
        .with_context(|| format!("failed to run tar on {}", archive.display()))?;
    if !status.success() {
        bail!("tar extraction failed for {}", archive.display());
    }
    Ok(())
}

fn find_named(dir: &Path, name: &str) -> Result<Option<PathBuf>> {
    for entry in fs::read_dir(dir).with_context(|| format!("failed to read {}", dir.display()))? {
        let path = entry?.path();
        if path.is_dir() {
            if let Some(found) = find_named(&path, name)? {
                return Ok(Some(found));
            }
        } else if path.file_name().and_then(|n| n.to_str()) == Some(name) {
            return Ok(Some(path));
        }
    }
    Ok(None)
}

fn surfpool_version_matches(bin: &Path, version: &str) -> bool {
    Command::new(bin)
        .arg("--version")
        .output()
        .ok()
        .filter(|output| output.status.success())
        .map(|output| String::from_utf8_lossy(&output.stdout).contains(version))
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lock() -> ReleaseLock {
        serde_json::from_str(LOCK_JSON).expect("embedded lock parses")
    }

    #[test]
    fn embedded_lock_parses_with_expected_shape() {
        let lock = lock();
        let program_roles: Vec<&str> = lock.programs.iter().map(|p| p.role.as_str()).collect();
        assert!(program_roles.contains(&"shielded_pool"));
        assert!(program_roles.contains(&"user_registry"));
        assert!(program_roles.contains(&"smart_account"));

        let binary_roles: Vec<&str> = lock.binaries.iter().map(|b| b.role.as_str()).collect();
        assert!(binary_roles.contains(&"prover"));
        assert!(binary_roles.contains(&"photon"));
        assert!(!lock.accounts.name.is_empty());
    }

    #[test]
    fn selects_binary_by_role_and_platform() {
        let lock = lock();
        let prover = select_binary(&lock, "prover", "linux", "x64").expect("prover linux x64");
        assert_eq!(prover.role, "prover");
        assert_eq!(prover.os, "linux");
        assert_eq!(prover.arch, "x64");
        assert!(select_binary(&lock, "prover", "windows", "x64").is_none());
        assert!(select_binary(&lock, "unknown", "linux", "x64").is_none());
    }

    #[test]
    fn program_id_for_role_maps_known_roles() {
        let smart = program_id_for_role("smart_account").unwrap();
        assert_eq!(smart, SMART_ACCOUNT_PROGRAM_ID);
        assert!(!program_id_for_role("shielded_pool").unwrap().is_empty());
        assert!(!program_id_for_role("user_registry").unwrap().is_empty());
        assert!(program_id_for_role("nope").is_err());
    }
}
