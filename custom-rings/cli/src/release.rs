//! The release the binary was built from.

use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
};

use anyhow::{ensure, Context as _, Result};
use serde::Deserialize;
use zolana_cli_common::release::{ensure_at, ensure_cached, Asset, BinaryAsset};

const LOCK_JSON: &str = include_str!("../release-artifacts.lock");

/// Every asset is optional, a missing one fails at use.
#[derive(Debug, Deserialize)]
pub struct RingRelease {
    #[serde(rename = "release_tag")]
    pub tag: String,
    #[serde(default)]
    binaries: Vec<BinaryAsset>,
    #[serde(flatten)]
    assets: BTreeMap<String, Asset>,
}

pub struct RingProgram {
    pub tag: String,
    pub asset: Asset,
}

pub use custom_ring_interface::key_catalog::RingKey;

impl RingRelease {
    pub fn from_lock() -> Result<Self> {
        let release = Self::parse(LOCK_JSON)?;
        release.validate_keys()?;
        Ok(release)
    }

    /// Reject a partial or differently pinned release before downloading or deploying it.
    /// The program and all clients must use the same complete proving-key generation.
    fn validate_keys(&self) -> Result<()> {
        for (name, expected) in custom_ring_interface::proving_key_hashes() {
            let key = RingKey::ALL
                .iter()
                .find(|key| key.file_name() == name)
                .with_context(|| format!("no ring catalog entry for {name}"))?;
            let asset = self.key(*key)?;
            ensure!(asset.sha256 == hex::encode(expected),
                "release {} has an incompatible key for {name}, use a matching complete release or a workspace build",
                self.tag);
        }
        Ok(())
    }

    fn parse(lock: &str) -> Result<Self> {
        serde_json::from_str(lock).context("the embedded release lock does not parse")
    }

    pub fn program(&self) -> Result<&Asset> {
        self.assets.get("ring_program").with_context(|| {
            format!(
                "release {} ships no ring program, pass --program-so",
                self.tag
            )
        })
    }

    pub fn key(&self, key: RingKey) -> Result<&Asset> {
        self.assets.get(key.section).with_context(|| {
            format!(
                "release {} ships no key for {}, use a complete custom-rings release",
                self.tag,
                key.circuit()
            )
        })
    }

    pub fn binary(&self, role: &str, os: &str, arch: &str) -> Result<&Asset> {
        self.binaries
            .iter()
            .find(|binary| binary.role == role && binary.os == os && binary.arch == arch)
            .map(|binary| &binary.asset)
            .with_context(|| format!("release {} ships no {role} for {os}-{arch}", self.tag))
    }

    pub fn ensure(&self, asset: &Asset) -> Result<PathBuf> {
        ensure_cached(&self.tag, asset)
    }

    pub fn ensure_as(&self, asset: &Asset, path: &Path) -> Result<()> {
        ensure_at(&self.tag, asset, path)
    }
}

impl RingProgram {
    pub fn from_lock() -> Result<Self> {
        let release = RingRelease::from_lock()?;
        let asset = release.program()?.clone();
        Ok(Self {
            tag: release.tag,
            asset,
        })
    }

    pub fn ensure(&self) -> Result<PathBuf> {
        ensure_cached(&self.tag, &self.asset)
    }
}

#[cfg(test)]
mod tests {
    use std::{
        io::{Read, Write},
        net::TcpListener,
    };

    use sha2::{Digest, Sha256};

    use super::*;

    const BINARIES_ONLY_LOCK: &str = r#"{
        "release_tag": "v1",
        "binaries": [{"role": "ring_rpc", "os": "linux", "arch": "x64", "asset": "ring-rpc-linux-x64-v1", "size": 1, "sha256": "x"}]
    }"#;

    const FULL_LOCK: &str = r#"{
        "release_tag": "v1",
        "ring_program": {"asset": "custom-ring-program-v1.so", "size": 1, "sha256": "x"},
        "proving_key": {"asset": "custom-ring-key-v1.key", "size": 1, "sha256": "x"},
        "audit_key": {"asset": "custom-ring-audit-key-v1.key", "size": 1, "sha256": "x"}
    }"#;

    #[test]
    fn release_keys_must_be_complete_and_match_the_compiled_verifiers() {
        let mut lock: serde_json::Value = serde_json::from_str(FULL_LOCK).unwrap();
        for (file, hash) in custom_ring_interface::proving_key_hashes() {
            let key = RingKey::ALL
                .iter()
                .find(|key| key.file_name() == file)
                .unwrap();
            lock[key.section] =
                serde_json::json!({"asset": file, "size": 1, "sha256": hex::encode(hash)});
        }
        RingRelease::parse(&lock.to_string())
            .unwrap()
            .validate_keys()
            .unwrap();
        let section = RingKey::CONFIDENTIAL_AUDIT.section;
        lock[section]["sha256"] = serde_json::json!("00".repeat(32));
        assert!(RingRelease::parse(&lock.to_string())
            .unwrap()
            .validate_keys()
            .is_err());
        lock.as_object_mut().unwrap().remove(section);
        assert!(RingRelease::parse(&lock.to_string())
            .unwrap()
            .validate_keys()
            .is_err());
    }

    #[test]
    fn a_missing_asset_fails_at_use_and_never_at_parse() {
        let release = RingRelease::parse(BINARIES_ONLY_LOCK).expect("parses");
        let program = release.program().expect_err("no program").to_string();
        assert_eq!(
            program,
            "release v1 ships no ring program, pass --program-so"
        );
        let key = release
            .key(
                *RingKey::ALL
                    .iter()
                    .find(|key| key.section == "audit_key")
                    .unwrap(),
            )
            .expect_err("no key")
            .to_string();
        assert!(key.contains("ships no key for custom-ring-base"), "{key}");
        assert_eq!(
            release
                .binary("ring_rpc", "linux", "x64")
                .expect("binary")
                .name,
            "ring-rpc-linux-x64-v1"
        );
        assert!(release.binary("ring_rpc", "darwin", "x64").is_err());
    }

    #[test]
    fn every_ring_key_is_served_or_named_as_missing() {
        let mut lock: serde_json::Value = serde_json::from_str(FULL_LOCK).expect("json");
        for key in RingKey::ALL {
            lock[key.section] =
                serde_json::json!({"asset": key.file_name(), "size": 1, "sha256": "x"});
        }
        let release = RingRelease::parse(&lock.to_string()).expect("parses");
        for key in RingKey::ALL {
            assert_eq!(release.key(key).expect("served").name, key.file_name());
        }
        let partial = RingRelease::parse(FULL_LOCK).expect("parses");
        assert_eq!(
            partial.program().expect("program").name,
            "custom-ring-program-v1.so"
        );
        for missing in RingKey::ALL
            .into_iter()
            .filter(|key| !matches!(key.section, "proving_key" | "audit_key"))
        {
            let error = partial.key(missing).expect_err("missing").to_string();
            assert!(error.contains(missing.circuit()), "{error}");
        }
    }

    /// Answers every request with `body`, the release server the cache downloads from.
    fn serve(body: &'static [u8]) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let url = format!("http://{}", listener.local_addr().expect("addr"));
        std::thread::spawn(move || {
            for mut stream in listener.incoming().flatten() {
                let _ = stream.read(&mut [0; 4096]);
                let head = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                );
                let _ = stream.write_all(head.as_bytes());
                let _ = stream.write_all(body);
            }
        });
        url
    }

    #[test]
    fn a_release_asset_is_cached_whole_or_not_at_all() {
        std::env::set_var("ZOLANA_RELEASE_URL", serve(b"ring"));
        let dir = std::env::temp_dir().join(format!("ring-release-cache-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let release = RingRelease::parse(BINARIES_ONLY_LOCK).expect("parses");
        let asset = |sha256: String| Asset {
            name: "ring.so".to_owned(),
            size: 4,
            sha256,
        };
        let pinned = asset(hex::encode(Sha256::digest(b"ring")));
        release
            .ensure_as(&pinned, &dir.join("ring.so"))
            .expect("downloaded");
        assert_eq!(std::fs::read(dir.join("ring.so")).expect("cached"), b"ring");
        let wrong = asset(hex::encode(Sha256::digest(b"rung")));
        assert!(release.ensure_as(&wrong, &dir.join("rung.so")).is_err());
        let names: Vec<_> = std::fs::read_dir(&dir)
            .expect("dir")
            .map(|entry| entry.expect("entry").file_name())
            .collect();
        assert_eq!(names, ["ring.so"], "no part file and no refused download");
        std::fs::remove_dir_all(dir).expect("cleanup");
    }
}
