use std::{
    env,
    fs::{self, File},
    io::{Read, Write},
    path::{Path, PathBuf},
    time::Duration,
};

use anyhow::{bail, ensure, Context, Result};
use serde::Deserialize;
use sha2::{Digest, Sha256};

use crate::config_dir;

const DEFAULT_RELEASE_BASE_URL: &str = "https://github.com/helius-labs/zolana/releases/download";
const DOWNLOAD_TIMEOUT: Duration = Duration::from_secs(600);

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct Asset {
    #[serde(rename = "asset")]
    pub name: String,
    pub size: u64,
    pub sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct BinaryAsset {
    pub role: String,
    pub os: String,
    pub arch: String,
    #[serde(flatten)]
    pub asset: Asset,
}

/// The `os` and `arch` names release binaries carry.
pub fn host_platform() -> Result<(&'static str, &'static str)> {
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

pub fn cache_dir(tag: &str) -> PathBuf {
    config_dir().join("cache").join(tag)
}

pub fn ensure_cached(tag: &str, asset: &Asset) -> Result<PathBuf> {
    let path = cache_dir(tag).join(&asset.name);
    ensure_at(tag, asset, &path)?;
    Ok(path)
}

/// A file at `path` is verified on every use, only a missing or wrong one is downloaded.
pub fn ensure_at(tag: &str, asset: &Asset, path: &Path) -> Result<()> {
    pinned(asset)?;
    if fs::read(path).is_ok_and(|bytes| verify(&bytes, asset).is_ok()) {
        return Ok(());
    }
    let base = env::var("ZOLANA_RELEASE_URL").unwrap_or_else(|_| DEFAULT_RELEASE_BASE_URL.into());
    let url = format!("{base}/{tag}/{}", asset.name);
    println!("Downloading {url}");
    let bytes = download(&url, asset.size)?;
    verify(&bytes, asset)?;
    write_atomic(path, &bytes)
}

pub fn verify(bytes: &[u8], asset: &Asset) -> Result<()> {
    pinned(asset)?;
    ensure!(
        bytes.len() as u64 == asset.size,
        "size mismatch for {}: expected {} bytes, got {}",
        asset.name,
        asset.size,
        bytes.len()
    );
    let found = hex::encode(Sha256::digest(bytes));
    ensure!(
        found == asset.sha256,
        "sha256 mismatch for {}: expected {}, got {found}",
        asset.name,
        asset.sha256
    );
    Ok(())
}

/// Rejects a stale program/key pairing and every marked insecure setup.
/// Setup markers identify the linked key generation. They do not certify program semantics.
pub fn verify_program_keys<'a>(
    binary: &[u8],
    expected: impl IntoIterator<Item = (&'a str, [u8; 32])>,
) -> Result<()> {
    let markers = groth16_solana::vk::setup::find_setup_txts(binary)
        .context("malformed program verifying-key setup marker")?;
    ensure!(
        !markers.is_empty(),
        "program contains no verifying-key setup markers"
    );
    ensure!(
        markers.iter().all(|marker| !marker.insecure_test_setup),
        "program contains an insecure test setup"
    );
    for (name, hash) in expected {
        ensure!(
            markers.iter().any(|marker| marker.proving_key_sha256 == hash),
            "program is missing the pinned verifier for {name}, rebuild the program and ship matching keys"
        );
    }
    Ok(())
}

/// Reads at most one byte past `max_len`, so a longer body fails.
pub fn download(url: &str, max_len: u64) -> Result<Vec<u8>> {
    let response = reqwest::blocking::Client::builder()
        .timeout(DOWNLOAD_TIMEOUT)
        .build()
        .context("failed to build HTTP client")?
        .get(url)
        .send()
        .and_then(reqwest::blocking::Response::error_for_status)
        .with_context(|| format!("failed to GET {url}"))?;
    if let Some(length) = response.content_length() {
        ensure!(
            length <= max_len,
            "{url} is {length} bytes, more than {max_len}"
        );
    }
    let mut bytes = Vec::new();
    response
        .take(max_len.saturating_add(1))
        .read_to_end(&mut bytes)
        .with_context(|| format!("failed to read the response body from {url}"))?;
    ensure!(
        bytes.len() as u64 <= max_len,
        "{url} is more than {max_len} bytes"
    );
    Ok(bytes)
}

pub fn make_executable(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut permissions = fs::metadata(path)
            .with_context(|| format!("failed to stat {}", path.display()))?
            .permissions();
        permissions.set_mode(permissions.mode() | 0o755);
        fs::set_permissions(path, permissions)
            .with_context(|| format!("failed to chmod {}", path.display()))?;
    }
    Ok(())
}

fn pinned(asset: &Asset) -> Result<()> {
    ensure!(
        !asset.sha256.is_empty(),
        "no pinned checksum for {}: the release lock is a placeholder",
        asset.name
    );
    Ok(())
}

/// The part file is unique per process, so concurrent downloads never write one file.
fn write_atomic(path: &Path, bytes: &[u8]) -> Result<()> {
    let name = path
        .file_name()
        .with_context(|| format!("{} names no file", path.display()))?;
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }
    let part = path.with_file_name(format!(
        "{}.{}.part",
        name.to_string_lossy(),
        std::process::id()
    ));
    let written = File::create(&part)
        .and_then(|mut file| {
            file.write_all(bytes)?;
            file.sync_all()
        })
        .and_then(|()| fs::rename(&part, path));
    if let Err(error) = written {
        let _ = fs::remove_file(&part);
        return Err(error).with_context(|| format!("failed to write {}", path.display()));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // sha256("hello")
    const HELLO: &str = "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824";

    fn asset(sha256: &str) -> Asset {
        Asset {
            name: "test".to_owned(),
            size: 5,
            sha256: sha256.to_owned(),
        }
    }

    fn setup_marker(hash: [u8; 32], insecure: bool) -> Vec<u8> {
        use groth16_solana::vk::setup::{SETUP_TXT_BEGIN, SETUP_TXT_END};
        format!(
            "{SETUP_TXT_BEGIN}name\0VERIFYINGKEY\0insecure_test_setup\0{insecure}\0proving_key_sha256\0{}\0{SETUP_TXT_END}",
            hex::encode(hash)
        )
        .into_bytes()
    }

    #[test]
    fn program_requires_every_pinned_key_and_allows_other_linked_verifiers() {
        let binary = [setup_marker([1; 32], false), setup_marker([2; 32], false)].concat();
        verify_program_keys(&binary, [("policy", [1; 32])]).unwrap();
        verify_program_keys(&binary, [("policy", [1; 32]), ("registry", [2; 32])]).unwrap();
        let error =
            verify_program_keys(&binary, [("policy", [1; 32]), ("audit", [3; 32])]).unwrap_err();
        assert!(error.to_string().contains("pinned verifier for audit"));
    }

    #[test]
    fn program_rejects_unmarked_malformed_and_insecure_setups() {
        use groth16_solana::vk::setup::SETUP_TXT_BEGIN;
        for (binary, reason) in [
            (Vec::new(), "no verifying-key setup markers"),
            (SETUP_TXT_BEGIN.as_bytes().to_vec(), "malformed program"),
            (
                [setup_marker([1; 32], false), setup_marker([2; 32], true)].concat(),
                "insecure test setup",
            ),
        ] {
            let error = verify_program_keys(&binary, [("policy", [1; 32])]).unwrap_err();
            assert!(error.to_string().contains(reason), "{error}");
        }
    }

    #[test]
    fn verify_enforces_size_and_hash() {
        assert!(verify(b"hello", &asset(HELLO)).is_ok());
        assert!(verify(b"hell", &asset(HELLO)).is_err());
        assert!(verify(b"world", &asset(HELLO)).is_err());
    }

    #[test]
    fn a_placeholder_checksum_is_refused_before_any_download() {
        assert!(verify(b"hello", &asset("")).is_err());
        let path = env::temp_dir().join(format!("zolana-placeholder-{}", std::process::id()));
        let error = ensure_at("v0", &asset(""), &path).expect_err("placeholder");
        assert!(error.to_string().contains("placeholder"), "{error}");
        assert!(!path.exists());
    }

    #[test]
    fn a_verified_file_is_used_without_a_download() {
        let dir = env::temp_dir().join(format!("zolana-release-cache-{}", std::process::id()));
        let path = dir.join("test");
        write_atomic(&path, b"hello").expect("write");
        ensure_at("v0", &asset(HELLO), &path).expect("cached file");
        let leftovers = fs::read_dir(&dir).expect("dir").count();
        assert_eq!(leftovers, 1, "no part file remains");
        fs::remove_dir_all(dir).expect("cleanup");
    }

    #[test]
    fn host_platform_resolves_on_this_host() {
        assert!(host_platform().is_ok());
    }

    #[test]
    fn a_binary_asset_flattens_its_file() {
        let binary: BinaryAsset = serde_json::from_str(
            r#"{"role":"prover","os":"linux","arch":"x64","asset":"prover-v1","size":5,"sha256":"x"}"#,
        )
        .expect("binary");
        assert_eq!(binary.asset.name, "prover-v1");
        assert_eq!(binary.asset.size, 5);
    }
}
