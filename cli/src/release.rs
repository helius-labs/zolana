use std::{
    env, fs,
    path::{Path, PathBuf},
    process::Command,
    time::Duration,
};

use anyhow::{anyhow, bail, Context, Result};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use solana_pubkey::Pubkey;

use crate::{args::ProgramSpec, cli_config::config_dir, process::path_string};

const LOCK_JSON: &str = include_str!("../release-artifacts.lock");

const DEFAULT_RELEASE_BASE_URL: &str = "https://github.com/helius-labs/zolana/releases/download";
const SURFPOOL_BASE_URL: &str = "https://github.com/Lightprotocol/surfpool/releases/download";

const DOWNLOAD_TIMEOUT: Duration = Duration::from_secs(600);

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
pub(crate) struct Asset {
    #[serde(rename = "asset")]
    pub name: String,
    pub size: u64,
    pub sha256: String,
}

#[derive(Debug, Deserialize)]
pub(crate) struct ProgramAsset {
    pub role: String,
    #[serde(flatten)]
    pub file: Asset,
}

#[derive(Debug, Deserialize)]
pub(crate) struct BinaryAsset {
    pub role: String,
    pub os: String,
    pub arch: String,
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
        let base = release_base_url();
        self.lock
            .programs
            .iter()
            .map(|program| {
                let path = ensure_file(&self.lock.release_tag, &program.file, &base)?;
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
        let base = release_base_url();
        let archive = ensure_file(&self.lock.release_tag, &self.lock.accounts, &base)?;
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
        let (os, arch) = current_platform()?;
        let asset = select_binary(&self.lock, role, os, arch).ok_or_else(|| {
            anyhow!("release-artifacts.lock has no {role} binary for {os}-{arch}")
        })?;
        let base = release_base_url();
        let path = ensure_file(&self.lock.release_tag, &asset.file, &base)?;
        make_executable(&path)?;
        Ok(path)
    }

    /// Downloads the custom surfpool binary from its own release. The tarball has
    /// no lockfile checksum (separate repo), so integrity is asserted via
    /// `surfpool --version`, matching the `just install-surfpool` recipe.
    pub(crate) fn surfpool_binary(&self) -> Result<PathBuf> {
        let (os, arch) = current_platform()?;
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
        let bytes = http_get(&url)?;
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

fn current_platform() -> Result<(&'static str, &'static str)> {
    let os = match env::consts::OS {
        "linux" => "linux",
        "macos" => "darwin",
        other => bail!("unsupported OS for release artifacts: {other}"),
    };
    let arch = match env::consts::ARCH {
        "x86_64" => "x64",
        "aarch64" => "arm64",
        other => bail!("unsupported architecture for release artifacts: {other}"),
    };
    Ok((os, arch))
}

fn cache_dir(tag: &str) -> PathBuf {
    config_dir().join("cache").join(tag)
}

fn release_base_url() -> String {
    env::var("ZOLANA_RELEASE_URL").unwrap_or_else(|_| DEFAULT_RELEASE_BASE_URL.to_string())
}

fn ensure_file(tag: &str, asset: &Asset, base_url: &str) -> Result<PathBuf> {
    let dir = cache_dir(tag);
    fs::create_dir_all(&dir).with_context(|| format!("failed to create {}", dir.display()))?;
    let path = dir.join(&asset.name);
    if path.is_file() && file_matches(&path, asset)? {
        return Ok(path);
    }

    let url = format!("{base_url}/{tag}/{}", asset.name);
    println!("Downloading {url}");
    let bytes = http_get(&url)?;
    verify_bytes(&bytes, asset)?;
    // Write to a temp file then rename so an interrupted download never leaves a
    // corrupt file at the cache path (rename is atomic on the same filesystem).
    let tmp = path.with_extension("part");
    fs::write(&tmp, &bytes).with_context(|| format!("failed to write {}", tmp.display()))?;
    fs::rename(&tmp, &path).with_context(|| format!("failed to finalize {}", path.display()))?;
    Ok(path)
}

fn verify_bytes(bytes: &[u8], asset: &Asset) -> Result<()> {
    if asset.sha256.is_empty() {
        bail!(
            "no pinned checksum for {}: release-artifacts.lock is a placeholder. Publish a release with `cargo run -p xtask -- create-release`.",
            asset.name
        );
    }
    if bytes.len() as u64 != asset.size {
        bail!(
            "size mismatch for {}: expected {} bytes, got {}",
            asset.name,
            asset.size,
            bytes.len()
        );
    }
    let actual = sha256_hex(bytes);
    if actual != asset.sha256 {
        bail!(
            "sha256 mismatch for {}: expected {}, got {}",
            asset.name,
            asset.sha256,
            actual
        );
    }
    Ok(())
}

fn file_matches(path: &Path, asset: &Asset) -> Result<bool> {
    if asset.sha256.is_empty() {
        return Ok(false);
    }
    let bytes = fs::read(path).with_context(|| format!("failed to read {}", path.display()))?;
    Ok(bytes.len() as u64 == asset.size && sha256_hex(&bytes) == asset.sha256)
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}

fn http_get(url: &str) -> Result<Vec<u8>> {
    let client = reqwest::blocking::Client::builder()
        .timeout(DOWNLOAD_TIMEOUT)
        .build()
        .context("failed to build HTTP client")?;
    let response = client
        .get(url)
        .send()
        .with_context(|| format!("failed to GET {url}"))?;
    if !response.status().is_success() {
        bail!("GET {url} returned HTTP {}", response.status());
    }
    let bytes = response
        .bytes()
        .with_context(|| format!("failed to read response body from {url}"))?;
    Ok(bytes.to_vec())
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

fn make_executable(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(path)
            .with_context(|| format!("failed to stat {}", path.display()))?
            .permissions();
        perms.set_mode(perms.mode() | 0o755);
        fs::set_permissions(path, perms)
            .with_context(|| format!("failed to chmod {}", path.display()))?;
    }
    Ok(())
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

    #[test]
    fn current_platform_resolves_on_this_host() {
        assert!(current_platform().is_ok());
    }

    #[test]
    fn verify_bytes_enforces_size_and_hash() {
        // sha256("hello")
        let asset = Asset {
            name: "test".to_string(),
            size: 5,
            sha256: "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824".to_string(),
        };
        assert!(verify_bytes(b"hello", &asset).is_ok());
        assert!(verify_bytes(b"hell", &asset).is_err());
        assert!(verify_bytes(b"world", &asset).is_err());
    }

    #[test]
    fn verify_bytes_rejects_placeholder_checksum() {
        let asset = Asset {
            name: "unpublished".to_string(),
            size: 5,
            sha256: String::new(),
        };
        assert!(verify_bytes(b"hello", &asset).is_err());
    }
}
