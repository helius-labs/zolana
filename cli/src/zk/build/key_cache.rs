use super::{error, Result};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{fs, path::Path};

#[derive(Clone, Copy)]
pub(super) enum Mode { Existing, Test, Default }

pub(super) fn production_metadata(metadata: &Value) -> Result<bool> {
    if metadata["production_safe"].as_bool() != Some(true) { return Ok(false); }
    let mode = metadata["setup_mode"].as_str().unwrap_or("");
    let phase2 = mode == "phase2-from-ptau" || mode.strip_prefix("phase2-from-ptau+mpc[")
        .and_then(|suffix| suffix.strip_suffix(" contributors]"))
        .is_some_and(|count| !count.is_empty() && count.bytes().all(|byte| byte.is_ascii_digit()) && count.parse::<usize>().is_ok());
    if metadata["protocol"] != "groth16" || metadata["curve"] != "bn254" || !phase2
        || metadata.get("deterministic_rng_seed").is_some_and(|seed| !seed.is_null()) {
        return Err(error("inconsistent production setup metadata; existing keys were preserved"));
    }
    Ok(true)
}

pub(super) fn reusable(artifact: &Path, requested: Mode) -> Result<bool> {
    let proving_key = artifact.join("pk.bin");
    let verifying_key = artifact.join("vk.bin");
    let metadata_path = artifact.join("metadata.json");
    if !metadata_path.exists() {
        if proving_key.exists() || verifying_key.exists() {
            return Err(error("existing keys have no setup metadata; preserve them and use a separate output directory for a new setup"));
        }
        return Ok(false);
    }

    let metadata: Value = serde_json::from_slice(&fs::read(metadata_path)?)?;
    let production = metadata["production_safe"].as_bool()
        .ok_or_else(|| error("setup metadata has no valid production_safe flag; existing keys were preserved"))?;
    let mode = metadata["setup_mode"].as_str()
        .ok_or_else(|| error("setup metadata has no setup mode; existing keys were preserved"))?;
    let seed = match metadata.get("deterministic_rng_seed") {
        None | Some(Value::Null) => None,
        Some(seed) => Some(seed.as_u64().ok_or_else(|| error("invalid setup seed metadata; existing keys were preserved"))?),
    };
    if metadata["protocol"] != "groth16" || metadata["curve"] != "bn254"
        || (!production && mode != "insecure-dev-mode") {
        return Err(error("unrecognized or inconsistent setup metadata; existing keys were preserved"));
    }
    production_metadata(&metadata)?;
    if production && matches!(requested, Mode::Test) {
        return Err(error("--test cannot replace production keys; use a separate output directory for a test setup"));
    }

    let digest = fs::read_to_string(artifact.join("digest"))?;
    let same_circuit = metadata["digest"].as_str() == Some(digest.trim());
    let same_mode = production || match requested {
        Mode::Existing => true,
        Mode::Test => seed == Some(0),
        Mode::Default => seed.is_none(),
    };
    let complete = proving_key.is_file() && verifying_key.is_file();
    let valid_keys = if complete {
        let verifying_key_sha256 = format!("{:x}", Sha256::digest(fs::read(&verifying_key)?));
        metadata["verifying_key_sha256"].as_str() == Some(&verifying_key_sha256)
            && xark_cli::keys_match(&proving_key, &verifying_key).unwrap_or(false)
    } else { false };
    if same_circuit && same_mode && valid_keys { return Ok(true); }
    if production {
        return Err(error("production setup is incomplete or differs from the circuit; existing keys were preserved, restore the matching artifacts or use a separate output directory for a new ceremony"));
    }
    Ok(false)
}

#[cfg(test)]
#[path = "../../../tests/unit/key_cache.rs"]
mod tests;
