//! `auditor-key`, the key file a local ring rpc serves.

use thiserror::Error;
use zolana_ring_client::keyfile::{write_auditor_key, KeyAccess, KeyFile, KeyFileError};

use crate::AuditorKeyArgs;

#[derive(Debug, Error)]
pub enum AuditorKeyError {
    #[error(transparent)]
    KeyFile(#[from] KeyFileError),
}

pub fn run(args: AuditorKeyArgs) -> Result<(), AuditorKeyError> {
    if args.create {
        let key = write_auditor_key(&args.key_file)?;
        println!(
            "auditor key {} created at {}",
            hex::encode(key.pubkey().as_bytes()),
            args.key_file.display()
        );
    } else {
        let key = KeyFile {
            path: &args.key_file,
            access: KeyAccess::OwnerOnly,
        }
        .auditor_key()?;
        println!("{}", hex::encode(key.pubkey().as_bytes()));
    }
    Ok(())
}
