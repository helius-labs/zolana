//! The release the binary was built from.

use std::{
    env, fs,
    io::{self, Read},
    path::{Path, PathBuf},
    time::Duration,
};

use serde::Deserialize;
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::file::{self, FileError};

const LOCK_JSON: &str = include_str!("../release-artifacts.lock");
const DEFAULT_RELEASE_BASE_URL: &str = "https://github.com/helius-labs/zolana/releases/download";
const DOWNLOAD_TIMEOUT: Duration = Duration::from_secs(600);

pub struct RingProgram {
    pub tag: String,
    pub asset: Asset,
}

/// Everything a custom-rings release ships, parsed from the embedded lock.
pub struct RingRelease {
    pub tag: String,
    pub program: Asset,
    /// The rules-configured binary a policy ring deploys.
    pub program_policy: Option<Asset>,
    /// Absent from a lock older than the key.
    pub proving_key: Option<Asset>,
    pub binaries: Vec<Binary>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct Asset {
    #[serde(rename = "asset")]
    pub name: String,
    pub size: u64,
    pub sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct Binary {
    pub role: String,
    pub os: String,
    pub arch: String,
    #[serde(flatten)]
    pub asset: Asset,
}

#[derive(Debug, Error)]
pub enum ReleaseError {
    #[error("the embedded release lock does not parse")]
    Lock(#[from] serde_json::Error),
    #[error("release {tag} ships no ring program, pass --program-so")]
    NoRingProgram { tag: String },
    #[error("release {tag} ships no policy ring program, a ring with a [policy] needs a rules-configured build, pass --program-so")]
    NoPolicyRingProgram { tag: String },
    #[error("release {tag} ships no proving key for the prover")]
    NoProvingKey { tag: String },
    #[error("release {tag} ships no {role} for {os}-{arch}")]
    NoBinary {
        tag: String,
        role: String,
        os: &'static str,
        arch: &'static str,
    },
    #[error("unsupported platform {os} {arch}")]
    Platform { os: String, arch: String },
    #[error("cannot download {url}")]
    Download {
        url: String,
        #[source]
        source: reqwest::Error,
    },
    #[error("cannot read {url}")]
    Body {
        url: String,
        #[source]
        source: io::Error,
    },
    #[error("{name} is {found} bytes, the release lock pins {expected}")]
    Size {
        name: String,
        expected: u64,
        found: u64,
    },
    #[error("{name} hashes to {found}, the release lock pins {expected}")]
    Digest {
        name: String,
        expected: String,
        found: String,
    },
    #[error(transparent)]
    File(#[from] FileError),
}

#[derive(Debug, Deserialize)]
struct ReleaseLock {
    release_tag: String,
    #[serde(default)]
    ring_program: Option<Asset>,
    /// The rules-configured binary, absent until a release publishes it.
    #[serde(default)]
    ring_program_policy: Option<Asset>,
    #[serde(default)]
    proving_key: Option<Asset>,
    #[serde(default)]
    binaries: Vec<Binary>,
}

impl RingRelease {
    pub fn from_lock() -> Result<Self, ReleaseError> {
        let lock: ReleaseLock = serde_json::from_str(LOCK_JSON)?;
        let program = lock
            .ring_program
            .ok_or_else(|| ReleaseError::NoRingProgram {
                tag: lock.release_tag.clone(),
            })?;
        Ok(Self {
            tag: lock.release_tag,
            program,
            program_policy: lock.ring_program_policy,
            proving_key: lock.proving_key,
            binaries: lock.binaries,
        })
    }

    /// The binary a ring of the given tier deploys, a policy ring needs the
    /// rules-configured build.
    fn program_for(self, has_policy: bool) -> Result<(String, Asset), ReleaseError> {
        if has_policy {
            let asset = self
                .program_policy
                .ok_or(ReleaseError::NoPolicyRingProgram {
                    tag: self.tag.clone(),
                })?;
            Ok((self.tag, asset))
        } else {
            Ok((self.tag, self.program))
        }
    }

    pub fn proving_key(&self) -> Result<&Asset, ReleaseError> {
        self.proving_key
            .as_ref()
            .ok_or_else(|| ReleaseError::NoProvingKey {
                tag: self.tag.clone(),
            })
    }

    pub fn binary(
        &self,
        role: &str,
        os: &'static str,
        arch: &'static str,
    ) -> Result<&Asset, ReleaseError> {
        self.binaries
            .iter()
            .find(|binary| binary.role == role && binary.os == os && binary.arch == arch)
            .map(|binary| &binary.asset)
            .ok_or_else(|| ReleaseError::NoBinary {
                tag: self.tag.clone(),
                role: role.to_owned(),
                os,
                arch,
            })
    }

    pub fn ensure(&self, asset: &Asset) -> Result<PathBuf, ReleaseError> {
        ensure_cached(&self.tag, asset)
    }

    pub fn ensure_as(&self, asset: &Asset, path: &Path) -> Result<(), ReleaseError> {
        ensure_at(&self.tag, asset, path)
    }
}

impl RingProgram {
    pub fn from_lock() -> Result<Self, ReleaseError> {
        Self::from_lock_tier(false)
    }

    /// A policy ring deploys the rules-configured binary, an audit-only ring the
    /// plain one.
    pub fn from_lock_tier(has_policy: bool) -> Result<Self, ReleaseError> {
        let (tag, asset) = RingRelease::from_lock()?.program_for(has_policy)?;
        Ok(Self { tag, asset })
    }

    pub fn ensure(&self) -> Result<PathBuf, ReleaseError> {
        ensure_cached(&self.tag, &self.asset)
    }
}

/// A cached file is verified on every use, only a missing or wrong one is downloaded.
fn ensure_cached(tag: &str, asset: &Asset) -> Result<PathBuf, ReleaseError> {
    let path = cache_dir(tag).join(&asset.name);
    ensure_at(tag, asset, &path)?;
    Ok(path)
}

fn ensure_at(tag: &str, asset: &Asset, path: &Path) -> Result<(), ReleaseError> {
    if fs::read(path).is_ok_and(|bytes| verify(&bytes, asset).is_ok()) {
        return Ok(());
    }
    let url = format!("{}/{}/{}", release_base_url(), tag, asset.name);
    crate::line("download", &url);
    let bytes = download(&url, asset)?;
    verify(&bytes, asset)?;
    if let Some(parent) = path.parent() {
        file::create_dir_all(parent)?;
    }
    file::write(path, &bytes)?;
    Ok(())
}

/// The `os-arch` pair the release names its binaries by.
pub fn host_platform() -> Result<(&'static str, &'static str), ReleaseError> {
    let platform = |os: String, arch: String| ReleaseError::Platform { os, arch };
    let os = match std::env::consts::OS {
        "linux" => "linux",
        "macos" => "darwin",
        other => {
            return Err(platform(
                other.to_owned(),
                std::env::consts::ARCH.to_owned(),
            ))
        }
    };
    let arch = match std::env::consts::ARCH {
        "x86_64" => "x64",
        "aarch64" => "arm64",
        other => return Err(platform(os.to_owned(), other.to_owned())),
    };
    Ok((os, arch))
}

/// The same cache the `zolana` cli fills.
fn cache_dir(tag: &str) -> PathBuf {
    config_dir().join("cache").join(tag)
}

pub fn config_dir() -> PathBuf {
    match env::var_os("ZOLANA_CONFIG_DIR") {
        Some(path) => PathBuf::from(path),
        None => match env::var_os("HOME") {
            Some(home) => PathBuf::from(home).join(".config").join("zolana"),
            None => PathBuf::from(".zolana"),
        },
    }
}

fn release_base_url() -> String {
    env::var("ZOLANA_RELEASE_URL").unwrap_or_else(|_| DEFAULT_RELEASE_BASE_URL.to_owned())
}

/// Reads at most one byte past the pinned size, a longer body fails on size.
fn download(url: &str, asset: &Asset) -> Result<Vec<u8>, ReleaseError> {
    let failed = |source| ReleaseError::Download {
        url: url.to_owned(),
        source,
    };
    let client = reqwest::blocking::Client::builder()
        .timeout(DOWNLOAD_TIMEOUT)
        .build()
        .map_err(failed)?;
    let response = client
        .get(url)
        .send()
        .and_then(reqwest::blocking::Response::error_for_status)
        .map_err(failed)?;
    if let Some(length) = response
        .content_length()
        .filter(|length| *length != asset.size)
    {
        return Err(ReleaseError::Size {
            name: asset.name.clone(),
            expected: asset.size,
            found: length,
        });
    }
    let mut bytes = Vec::with_capacity(asset.size as usize);
    response
        .take(asset.size.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|source| ReleaseError::Body {
            url: url.to_owned(),
            source,
        })?;
    Ok(bytes)
}

fn verify(bytes: &[u8], asset: &Asset) -> Result<(), ReleaseError> {
    if bytes.len() as u64 != asset.size {
        return Err(ReleaseError::Size {
            name: asset.name.clone(),
            expected: asset.size,
            found: bytes.len() as u64,
        });
    }
    let found = hex::encode(Sha256::digest(bytes));
    if found != asset.sha256 {
        return Err(ReleaseError::Digest {
            name: asset.name.clone(),
            expected: asset.sha256.clone(),
            found,
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_embedded_lock_parses() {
        let lock: ReleaseLock = serde_json::from_str(LOCK_JSON).expect("lock");
        assert!(!lock.release_tag.is_empty());
    }

    #[test]
    fn verify_pins_size_and_digest() {
        let bytes = b"ring";
        let asset = Asset {
            name: "ring.so".to_owned(),
            size: 4,
            sha256: hex::encode(Sha256::digest(bytes)),
        };
        verify(bytes, &asset).expect("matches");
        assert!(matches!(
            verify(b"rings", &asset),
            Err(ReleaseError::Size { found: 5, .. })
        ));
        assert!(matches!(
            verify(b"rung", &asset),
            Err(ReleaseError::Digest { .. })
        ));
    }
}
