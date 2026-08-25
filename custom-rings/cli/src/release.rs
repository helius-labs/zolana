//! The ring program of the release this binary was built from.

use std::{
    env, fs,
    io::{self, Read},
    path::PathBuf,
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

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct Asset {
    #[serde(rename = "asset")]
    pub name: String,
    pub size: u64,
    pub sha256: String,
}

#[derive(Debug, Error)]
pub enum ReleaseError {
    #[error("the embedded release lock does not parse")]
    Lock(#[from] serde_json::Error),
    #[error("release {tag} ships no ring program, pass --program-so")]
    NoRingProgram { tag: String },
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
}

impl RingProgram {
    pub fn from_lock() -> Result<Self, ReleaseError> {
        let lock: ReleaseLock = serde_json::from_str(LOCK_JSON)?;
        let asset = lock
            .ring_program
            .ok_or_else(|| ReleaseError::NoRingProgram {
                tag: lock.release_tag.clone(),
            })?;
        Ok(Self {
            tag: lock.release_tag,
            asset,
        })
    }

    /// A cached file is verified on every use, only a missing or wrong one is downloaded.
    pub fn ensure(&self) -> Result<PathBuf, ReleaseError> {
        let path = cache_dir(&self.tag).join(&self.asset.name);
        if fs::read(&path).is_ok_and(|bytes| verify(&bytes, &self.asset).is_ok()) {
            return Ok(path);
        }
        let url = format!("{}/{}/{}", release_base_url(), self.tag, self.asset.name);
        crate::line("download", &url);
        let bytes = download(&url, &self.asset)?;
        verify(&bytes, &self.asset)?;
        if let Some(parent) = path.parent() {
            file::create_dir_all(parent)?;
        }
        file::write(&path, &bytes)?;
        Ok(path)
    }
}

/// The same cache the `zolana` cli fills.
fn cache_dir(tag: &str) -> PathBuf {
    let config_dir = match env::var_os("ZOLANA_CONFIG_DIR") {
        Some(path) => PathBuf::from(path),
        None => match env::var_os("HOME") {
            Some(home) => PathBuf::from(home).join(".config").join("zolana"),
            None => PathBuf::from(".zolana"),
        },
    };
    config_dir.join("cache").join(tag)
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
