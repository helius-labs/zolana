use anyhow::{bail, Result};
use solana_signer::Signer;
use zolana_client::{
    ensure_registered, fetch_user_record_optional_checked, update_registered_keys, ClientError,
    Rpc, SolanaRpc,
};
use zolana_transaction::Address;
use zolana_user_registry_interface::{instruction::set_merging_enabled, user_record_pda};

use super::material::load_existing_wallet;
use crate::{
    args::{MergingSetting, SetMergingOptions},
    cli_config::{resolve_keypair_path, resolve_rpc_url, CliConfigFile},
};

pub(super) fn run_set_merging(opts: SetMergingOptions) -> Result<()> {
    let enabled = matches!(opts.setting, MergingSetting::On);
    if opts.update_keys && !enabled {
        bail!("--update-keys is only valid with `wallet set-merging on`");
    }
    let config = CliConfigFile::load()?;
    let path = resolve_keypair_path(opts.wallet.keypair.keypair.as_deref(), &config);
    if !path.exists() {
        bail!(
            "wallet not found at {}; create it with `zolana wallet new --outfile {}`",
            path.display(),
            path.display()
        );
    }
    let material = load_existing_wallet(&path)?;
    let rpc = SolanaRpc::new(resolve_rpc_url(opts.wallet.rpc_url.as_deref(), &config));
    let owner = material.funding.pubkey();

    let record = fetch_user_record_optional_checked(&rpc, owner)?;
    if !enabled {
        match record {
            Some(record) if record.merging_enabled => {}
            Some(_) => {
                println!(
                    "ok set_merging owner={owner} enabled=false status=unchanged record=current"
                );
                return Ok(());
            }
            None => {
                println!(
                    "ok set_merging owner={owner} enabled=false status=unchanged record=absent"
                );
                return Ok(());
            }
        }
    } else {
        let already_enabled = record.as_ref().is_some_and(|record| record.merging_enabled);
        let registration = if opts.update_keys && record.is_some() {
            update_registered_keys(&rpc, &material.funding, &material.keypair)
        } else {
            ensure_registered(&rpc, &material.funding, &material.keypair)
        };
        let registration = match registration {
            Err(ClientError::RegistryKeysMismatch { .. }) => bail!(
                "the selected wallet does not match this owner's registry keys; rerun with \
                 `wallet set-merging on --update-keys` to replace the published identity. This \
                 changes future address resolution and cannot recover notes owned by the old keys"
            ),
            result => result?,
        };
        if let Some(signature) = registration {
            let status = if record.is_some() {
                "updated"
            } else {
                "created"
            };
            println!("ok set_merging owner={owner} record={status} signature={signature}");
        }
        if already_enabled {
            println!("ok set_merging owner={owner} enabled=true status=unchanged record=current");
            return Ok(());
        }
    }

    let (user_record, _bump) = user_record_pda(&owner);
    let ix = set_merging_enabled(user_record, owner, enabled);
    let signature = rpc.create_and_send_transaction(
        &[ix],
        Address::new_from_array(owner.to_bytes()),
        &[&material.funding],
    )?;

    println!("ok set_merging owner={owner} enabled={enabled} signature={signature}");
    Ok(())
}
