//! One place the cli touches a path and names it in the failure.

use std::{fs, path::Path};

use anyhow::{anyhow, Context as _, Result};
use solana_keypair::Keypair;
use zolana_secret_file::{create_new, Visibility};

pub fn read(path: &Path) -> Result<String> {
    fs::read_to_string(path).with_context(|| format!("cannot read {}", path.display()))
}

pub fn write(path: &Path, contents: impl AsRef<[u8]>) -> Result<()> {
    fs::write(path, contents).with_context(|| format!("cannot write {}", path.display()))
}

pub fn create_dir_all(path: &Path) -> Result<()> {
    fs::create_dir_all(path).with_context(|| format!("cannot write {}", path.display()))
}

pub fn read_keypair(path: &Path) -> Result<Keypair> {
    solana_keypair::read_keypair_file(path)
        .map_err(|error| anyhow!("cannot read keypair {}, {error}", path.display()))
}

pub fn read_or_create_keypair(path: &Path) -> Result<Keypair> {
    if path.is_file() {
        return read_keypair(path);
    }
    let keypair = Keypair::new();
    write_keypair(&keypair, path)?;
    Ok(keypair)
}

/// Owner-only and never over an existing file.
pub fn write_keypair(keypair: &Keypair, path: &Path) -> Result<()> {
    let json = serde_json::to_string(&keypair.to_bytes().to_vec())?;
    create_new(path, json.as_bytes(), Visibility::Secret)
        .with_context(|| format!("cannot write keypair {}", path.display()))
}
