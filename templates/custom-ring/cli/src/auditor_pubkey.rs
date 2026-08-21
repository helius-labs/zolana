use std::path::PathBuf;

use anyhow::Result;
use clap::Parser;
use zolana_ring_rpc::{KeyAccess, KeyFile};

#[derive(Parser)]
struct Cli {
    key_file: PathBuf,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let key = KeyFile {
        path: &cli.key_file,
        access: KeyAccess::OwnerOnly,
    }
    .auditor_key()?;
    println!("{}", hex::encode(key.pubkey().as_bytes()));
    Ok(())
}
