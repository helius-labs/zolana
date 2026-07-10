use anyhow::{bail, Result};
use solana_signature::Signature;
use solana_signer::Signer;
use zolana_client::{
    fetch_user_record_optional_checked, validate_registered_keypair, Rpc, SolanaRpc,
};
use zolana_transaction::Address;
use zolana_user_registry_interface::{instruction::set_merging_enabled, user_record_pda};

use super::material::{load_existing_wallet, WalletMaterial};
use crate::{
    args::{MergingSetting, RegisterWalletOptions, SetMergingOptions},
    cli_config::{resolve_keypair_path, resolve_rpc_url, CliConfigFile},
};

pub(super) fn register_wallet_on_chain(
    rpc: &SolanaRpc,
    material: &WalletMaterial,
) -> Result<Option<Signature>> {
    Ok(zolana_client::ensure_registered(
        rpc,
        &material.funding,
        &material.keypair,
    )?)
}

pub(super) fn run_register(opts: RegisterWalletOptions) -> Result<()> {
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
    let mut rpc = SolanaRpc::new(resolve_rpc_url(opts.wallet.rpc_url.as_deref(), &config));
    let owner = material.funding.pubkey();
    let already_current = fetch_user_record_optional_checked(&rpc, owner)?.is_some();
    if already_current {
        validate_registered_keypair(&rpc, owner, &material.keypair)?;
    }
    if let Some(lamports) = opts.airdrop_lamports {
        let signature = rpc.airdrop(&owner, lamports)?;
        println!("ok airdrop signature={signature}");
    }
    let signature = if already_current {
        None
    } else {
        register_wallet_on_chain(&rpc, &material)?
    };
    match signature {
        Some(signature) => println!("ok user_registry signature={signature}"),
        None => println!("ok user_registry already current"),
    }
    Ok(())
}

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

    validate_registered_keypair(&rpc, owner, &material.keypair)?;

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
