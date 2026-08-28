//! `auditor-key`, the key file a local ring rpc serves.

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
        let key = KeyFile {
            path: &key_file,
            access: KeyAccess::OwnerOnly,
        }
        .auditor_key()?;
        println!("{}", hex::encode(key.pubkey().as_bytes()));
    }
    Ok(())
}
