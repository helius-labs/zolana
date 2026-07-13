use anyhow::{bail, Result};
use solana_signer::Signer;
use zolana_client::{
    ensure_registered, fetch_user_record_optional_checked, validate_registered_keypair, Rpc,
    SolanaRpc,
};
use zolana_transaction::Address;
use zolana_user_registry_interface::{instruction::set_merging_enabled, user_record_pda};

use super::{material::load_sender_from_resolved_sync, resolve::resolve_sync};
use crate::args::MergeOptions;

pub(super) fn run_merge(opts: MergeOptions) -> Result<()> {
    let sync = resolve_sync(&opts.sync)?;
    let rpc = SolanaRpc::new(sync.rpc_url.clone());
    let material = load_sender_from_resolved_sync(&sync)?;
    let owner = material.funding.pubkey();

    let enabled = match (opts.enable, opts.disable) {
        (true, false) => true,
        (false, true) => false,
        _ => bail!("provide exactly one of --enable or --disable"),
    };

    match fetch_user_record_optional_checked(&rpc, owner)? {
        Some(_) => validate_registered_keypair(&rpc, owner, &material.keypair)?,
        None if !enabled => {
            println!("ok merge owner={owner} enabled=false unchanged=true");
            return Ok(());
        }
        None => match ensure_registered(&rpc, &material.funding, &material.keypair)? {
            Some(signature) => println!("ok user_registry signature={signature}"),
            None => println!("ok user_registry current=true"),
        },
    }

    let (user_record, _bump) = user_record_pda(&owner);
    let ix = set_merging_enabled(user_record, owner, enabled);
    let signature = rpc.create_and_send_transaction(
        &[ix],
        Address::new_from_array(owner.to_bytes()),
        &[&material.funding],
    )?;

    println!("ok merge owner={owner} enabled={enabled} signature={signature}");
    Ok(())
}
