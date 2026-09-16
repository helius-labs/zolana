//! `auditor-key`, the key file a local ring rpc serves.

use std::path::Path;

use zolana_keypair::ViewingKey;
use zolana_ring_rpc::{write_auditor_key, KeyAccess, KeyFile, KeyFileError};

use crate::{AuditorKeyArgs, ProjectRoot};

pub fn run(project_root: &ProjectRoot, args: AuditorKeyArgs) -> Result<(), KeyFileError> {
    let key_file = project_root.resolve(&args.key_file);
    if args.create {
        let key = write_auditor_key(&key_file)?;
        println!(
            "auditor key {} created at {}",
            hex::encode(key.pubkey().as_bytes()),
            key_file.display()
        );
    } else {
        let key = read_auditor_key(&key_file)?;
        println!("{}", hex::encode(key.pubkey().as_bytes()));
    }
    Ok(())
}

pub(crate) fn read_auditor_key(path: &Path) -> Result<ViewingKey, KeyFileError> {
    KeyFile {
        path,
        access: KeyAccess::OwnerOnly,
    }
    .auditor_key()
}
