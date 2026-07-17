use anyhow::{bail, Result};
use solana_signer::Signer;
use zolana_client::{
    user_registry::{register_if_absent, StrictRegistration},
    Rpc, SolanaRpc,
};
use zolana_transaction::Address;
use zolana_user_registry_interface::{instruction::set_merging_enabled, user_record_pda};

use super::{
    material::{load_existing_wallet, load_sender_from_resolved_sync},
    resolve::resolve_sync,
};
use crate::{
    args::{RegisterOptions, SetMergingOptions},
    cli_config::{resolve_keypair_path, resolve_rpc_url, CliConfigFile},
};

/// Publish the wallet's shielded keys under its Solana pubkey. Registration is
/// what makes the pubkey payable: senders resolve it through the registry, and
/// without a record a `transfer` to it degrades to a public withdrawal.
///
/// Strict by design: a shielded identity's nullifier key never rotates, so this
/// writes a record only when none exists, no-ops when the on-chain record
/// already matches this wallet, and errors when a differing record is present
/// rather than overwriting an existing on-chain identity.
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
    match register_if_absent(&rpc, &material.funding, &material.keypair)? {
        StrictRegistration::Written(signature) => {
            println!("ok register owner={owner} record=written signature={signature}")
        }
        StrictRegistration::Current => {
            println!("ok register owner={owner} record=current status=unchanged")
        }
        StrictRegistration::Mismatch => bail!(
            "wallet {owner} already has a different shielded identity registered on-chain; \
             the nullifier key never rotates, so `wallet register` refuses to overwrite it"
        ),
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
