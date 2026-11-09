use anyhow::{Context, Result};

const SEED_VAR: &str = "ZOLANA_RANDOM_SEED";

/// Reads `ZOLANA_RANDOM_SEED` as decimal or `0x` hex, random when unset.
pub fn random_seed() -> Result<u64> {
    let seed = match std::env::var(SEED_VAR) {
        Ok(raw) => {
            let trimmed = raw.trim();
            trimmed
                .strip_prefix("0x")
                .map_or_else(|| trimmed.parse(), |hex| u64::from_str_radix(hex, 16))
                .with_context(|| format!("{SEED_VAR}={raw}"))?
        }
        Err(std::env::VarError::NotPresent) => rand::random(),
        Err(err) => return Err(err).context(SEED_VAR),
    };
    println!("{SEED_VAR}={seed}");
    Ok(seed)
}
