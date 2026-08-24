//! `auditor-key`, the key file a local ring rpc serves.

use zolana_ring_rpc::{write_auditor_key, KeyAccess, KeyFile, KeyFileError};

use crate::AuditorKeyArgs;

pub fn run(args: AuditorKeyArgs) -> Result<(), KeyFileError> {
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
