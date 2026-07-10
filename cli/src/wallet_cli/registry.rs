use anyhow::{bail, Result};
use solana_signer::Signer;
use zolana_client::{
    ensure_registered, fetch_user_record_optional_checked, validate_registered_keypair, Rpc,
    SolanaRpc,
};
use zolana_transaction::Address;
use zolana_user_registry_interface::{instruction::set_merging_enabled, user_record_pda};

use super::material::load_existing_wallet;
use crate::{
    args::{MergingSetting, SetMergingOptions},
    cli_config::{resolve_keypair_path, resolve_rpc_url, CliConfigFile},
};

pub(super) fn run_set_merging(opts: SetMergingOptions) -> Result<()> {
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
    let enabled = matches!(opts.setting, MergingSetting::On);

    if fetch_user_record_optional_checked(&rpc, owner)?.is_some() {
        validate_registered_keypair(&rpc, owner, &material.keypair)?;
    } else if !enabled {
        println!("ok set_merging owner={owner} enabled=false status=unchanged record=absent");
        return Ok(());
    } else {
        match ensure_registered(&rpc, &material.funding, &material.keypair)? {
            Some(signature) => {
                println!("ok set_merging owner={owner} record=created signature={signature}");
            }
            None => {
                println!("ok set_merging owner={owner} record=already_current");
            }
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
