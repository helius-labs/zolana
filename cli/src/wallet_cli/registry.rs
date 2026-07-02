use anyhow::{bail, Result};
use solana_signature::Signature;
use solana_signer::Signer;
use zolana_client::{Rpc, SolanaRpc};
use zolana_transaction::Address;
use zolana_user_registry_interface::{instruction::set_merging_enabled, user_record_pda};

use super::{
    material::{load_sender_from_resolved_sync, WalletMaterial},
    resolve::resolve_sync,
};
use crate::args::MergeOptions;

pub(super) fn register_wallet_on_chain(
    rpc: &SolanaRpc,
    material: &WalletMaterial,
) -> Result<Option<Signature>> {
    // Idempotent register-or-update lives in the SDK; the CLI just supplies its
    // keypair + funding key.
    Ok(zolana_client::ensure_registered(
        rpc,
        &material.funding,
        &material.keypair,
    )?)
}

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
