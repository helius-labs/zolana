use anyhow::{bail, Result};
use solana_signature::Signature;
use solana_signer::Signer;
use zolana_client::{ensure_registered, Rpc, SolanaRpc};
use zolana_transaction::Address;
use zolana_user_registry_interface::{instruction::set_merging_enabled, user_record_pda};

use super::{
    material::{load_existing_wallet, load_sender_from_resolved_sync, WalletMaterial},
    resolve::resolve_sync,
};
use crate::{
    args::{RegisterOptions, SetMergingOptions},
    cli_config::{resolve_keypair_path, resolve_rpc_url, CliConfigFile},
};

pub(super) fn register_wallet_on_chain(
    rpc: &SolanaRpc,
    material: &WalletMaterial,
) -> Result<Option<Signature>> {
    // Idempotent register-or-update lives in the SDK; the CLI just supplies its
    // keypair + funding key.
    Ok(ensure_registered(
        rpc,
        &material.funding,
        &material.keypair,
    )?)
}

/// Publish the wallet's shielded keys under its Solana pubkey. Registration is
/// what makes the pubkey payable: senders resolve it through the registry, and
/// without a record a `transfer` to it degrades to a public withdrawal.
/// `ensure_registered` is idempotent: it registers if absent, updates on key
/// change, and no-ops when the on-chain record already matches.
pub(crate) fn run_register(opts: RegisterOptions) -> Result<()> {
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
    match ensure_registered(&rpc, &material.funding, &material.keypair)? {
        Some(signature) => {
            println!("ok register owner={owner} record=written signature={signature}")
        }
        None => println!("ok register owner={owner} record=current status=unchanged"),
    }
    Ok(())
}

/// Toggle the wallet's `merging_enabled` flag on its user-registry record. This is
/// the opt-in the merge service requires; the actual note consolidation is the
/// `merge` command.
pub(crate) fn run_set_merging(opts: SetMergingOptions) -> Result<()> {
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

    println!("ok set_merging owner={owner} enabled={enabled} signature={signature}");
    Ok(())
}
