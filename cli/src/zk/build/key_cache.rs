use super::{
    error, read,
    verifier::{read_circuit_digest, KeyArtifacts},
    BuildError, Result,
};
use groth16_solana::vk::setup::proving_key_sha256;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
};

#[derive(Clone, Copy)]
pub(super) enum Mode {
    Existing,
    Test,
    Default,
}

pub(super) fn production_metadata(metadata: &Value) -> Result<bool> {
    if metadata["production_safe"].as_bool() != Some(true) {
        return Ok(false);
    }
    let mode = metadata["setup_mode"].as_str().unwrap_or("");
    let phase2 = mode == "phase2-from-ptau"
        || mode
            .strip_prefix("phase2-from-ptau+mpc[")
            .and_then(|suffix| suffix.strip_suffix(" contributors]"))
            .is_some_and(|count| {
                !count.is_empty()
                    && count.bytes().all(|byte| byte.is_ascii_digit())
                    && count.parse::<usize>().is_ok()
            });
    if metadata["protocol"] != "groth16"
        || metadata["curve"] != "bn254"
        || !phase2
        || metadata
            .get("deterministic_rng_seed")
            .is_some_and(|seed| !seed.is_null())
    {
        return Err(error(
            "inconsistent production setup metadata; existing keys were preserved",
        ));
    }
    Ok(true)
}

pub(super) fn reusable(artifact: &Path, requested: Mode) -> Result<bool> {
    let proving_key = artifact.join("pk.bin");
    let verifying_key = artifact.join("vk.bin");
    let metadata_path = artifact.join("metadata.json");
    if !metadata_path.exists() {
        if proving_key.exists() || verifying_key.exists() {
            return Err(error(
                "existing keys have no setup metadata; preserve them and use a separate output directory for a new setup",
            ));
        }
        return Ok(false);
    }

    let metadata: Value = serde_json::from_slice(&fs::read(metadata_path)?)?;
    let production = metadata["production_safe"].as_bool().ok_or_else(|| {
        error("setup metadata has no valid production_safe flag; existing keys were preserved")
    })?;
    let mode = metadata["setup_mode"]
        .as_str()
        .ok_or_else(|| error("setup metadata has no setup mode; existing keys were preserved"))?;
    let seed =
        match metadata.get("deterministic_rng_seed") {
            None | Some(Value::Null) => None,
            Some(seed) => Some(seed.as_u64().ok_or_else(|| {
                error("invalid setup seed metadata; existing keys were preserved")
            })?),
        };
    if metadata["protocol"] != "groth16"
        || metadata["curve"] != "bn254"
        || (!production && mode != "insecure-dev-mode")
    {
        return Err(error(
            "unrecognized or inconsistent setup metadata; existing keys were preserved",
        ));
    }
    production_metadata(&metadata)?;
    if production && matches!(requested, Mode::Test) {
        return Err(error(
            "--test cannot replace production keys; use a separate output directory for a test setup",
        ));
    }

    let digest = fs::read_to_string(artifact.join("digest"))?;
    let same_circuit = metadata["digest"].as_str() == Some(digest.trim());
    let same_mode = production
        || match requested {
            Mode::Existing => true,
            Mode::Test => seed == Some(0),
            Mode::Default => seed.is_none(),
        };
    let complete = proving_key.is_file() && verifying_key.is_file();
    let valid_keys = if complete {
        let verifying_key_sha256 = format!("{:x}", Sha256::digest(fs::read(&verifying_key)?));
        metadata["verifying_key_sha256"].as_str() == Some(&verifying_key_sha256)
            && xark_cli::keys_match(&proving_key, &verifying_key).unwrap_or(false)
    } else {
        false
    };
    if same_circuit && same_mode && valid_keys {
        return Ok(true);
    }
    if production {
        return Err(error(
            "production setup is incomplete or differs from the circuit; existing keys were preserved, restore the matching artifacts or use a separate output directory for a new ceremony",
        ));
    }
    Ok(false)
}

/// A trusted sha256sum manifest. Its file names are relative to the manifest's
/// directory, and each one pins the exact bytes of one artifact file.
pub(super) struct TrustedManifest {
    path: PathBuf,
    entries: BTreeMap<PathBuf, [u8; 32]>,
}

impl TrustedManifest {
    pub(super) fn load(path: &Path) -> Result<Self> {
        let text = fs::read_to_string(path).map_err(|source| BuildError::Io {
            path: path.to_path_buf(),
            source,
        })?;
        let parsed = crate::vks::parse_sha256_manifest(&text).map_err(|e| {
            error(format!(
                "invalid trusted checksum manifest {}: {e:#}",
                path.display()
            ))
        })?;
        let base = path
            .parent()
            .filter(|base| !base.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        let mut entries = BTreeMap::new();
        for (digest, file) in parsed {
            // An entry for a file that does not exist pins nothing.
            let Ok(file_path) = fs::canonicalize(base.join(&file)) else {
                continue;
            };
            if entries
                .insert(file_path, digest)
                .is_some_and(|previous| previous != digest)
            {
                return Err(error(format!(
                    "trusted checksum manifest {} pins {file} to different digests",
                    path.display()
                )));
            }
        }
        Ok(Self {
            path: path.to_path_buf(),
            entries,
        })
    }

    /// Requires `file` to have an entry for its own path whose digest matches.
    fn require(&self, label: &str, file: &Path, digest: [u8; 32]) -> Result<()> {
        let canonical = fs::canonicalize(file).map_err(|source| BuildError::Io {
            path: file.to_path_buf(),
            source,
        })?;
        match self.entries.get(&canonical) {
            Some(pinned) if *pinned == digest => Ok(()),
            Some(_) => Err(error(format!(
                "{label} {} does not match its entry in the trusted checksum manifest {}",
                file.display(),
                self.path.display()
            ))),
            None => Err(error(format!(
                "{label} {} is not pinned by the trusted checksum manifest {}",
                file.display(),
                self.path.display()
            ))),
        }
    }

    /// Reads the setup outputs of one circuit, requiring the verifying key,
    /// the setup metadata (which decides the setup kind) and the proving key
    /// (whose digest the verifier embeds) to be pinned, and the two keys to
    /// belong together.
    pub(super) fn pinned_keys(&self, artifact: &Path, circuit: &str) -> Result<KeyArtifacts> {
        let verifying_key_path = artifact.join("vk.bin");
        let verifying_key = read(&verifying_key_path)?;
        self.require(
            &format!("{circuit} verifying key"),
            &verifying_key_path,
            Sha256::digest(&verifying_key).into(),
        )?;
        let metadata_path = artifact.join("metadata.json");
        let metadata = read(&metadata_path)?;
        self.require(
            &format!("{circuit} setup metadata"),
            &metadata_path,
            Sha256::digest(&metadata).into(),
        )?;
        let proving_key_path = artifact.join("pk.bin");
        let proving_key_sha256 =
            proving_key_sha256(&proving_key_path).map_err(|source| BuildError::Io {
                path: proving_key_path.clone(),
                source,
            })?;
        self.require(
            &format!("{circuit} proving key"),
            &proving_key_path,
            proving_key_sha256,
        )?;
        if !xark_cli::keys_match(&proving_key_path, &verifying_key_path).map_err(error)? {
            return Err(error(format!(
                "{circuit} proving key {} does not belong to its verifying key",
                proving_key_path.display()
            )));
        }
        Ok(KeyArtifacts {
            verifying_key,
            metadata,
            circuit_digest: read_circuit_digest(artifact)?,
            proving_key_sha256,
        })
    }
}

#[cfg(test)]
#[path = "../../../tests/unit/key_cache.rs"]
mod tests;
