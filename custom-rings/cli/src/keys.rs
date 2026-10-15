//! `auditor-key`, the key file a local ring rpc serves.

use std::path::Path;

use anyhow::Result;
use zolana_keypair::ViewingKey;
use zolana_ring_client::rpc::{read_auditor_key, write_auditor_key};
use zolana_secret_file::Access;

pub fn run(key_file: &Path, create: bool) -> Result<()> {
    if create {
        let key = write_auditor_key(key_file)?;
        println!(
            "auditor key {} created at {}",
            hex::encode(key.pubkey().as_bytes()),
            key_file.display()
        );
    } else {
        println!("{}", hex::encode(read(key_file)?.pubkey().as_bytes()));
    }
    Ok(())
}

/// Creates the key a local ring rpc serves when the ring directory has none.
pub(crate) fn ensure(key_file: &Path) -> Result<()> {
    if key_file.is_file() {
        return Ok(());
    }
    run(key_file, true)
}

pub(crate) fn read(path: &Path) -> Result<ViewingKey> {
    Ok(read_auditor_key(path, Access::OwnerOnly)?)
}
