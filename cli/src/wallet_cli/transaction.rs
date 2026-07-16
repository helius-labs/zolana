use anyhow::Result;
use solana_signer::Signer;
use zolana_client::{Rpc, SolanaRpc, ZolanaClient};
use zolana_transaction::Address;
use zolana_wallet::{
    create_split, create_transfer_sync, sign_private_transaction_sync, SplitParams, TransferParams,
};

use super::{
    material::WalletMaterial,
    resolve::get_network,
    sync::sync_context,
    util::{ensure_positive, format_address, parse_address, parse_hex_array, parse_pubkey},
};
use crate::args::{SplitOptions, TransferOptions};

pub(crate) fn run_transfer(opts: TransferOptions) -> Result<()> {
    ensure_positive(opts.amount)?;
    let asset = parse_address(&opts.mint)?;
    let network = get_network(&opts.network)?;
    let mut rpc = SolanaRpc::new(network.sync.rpc_url.clone());
    let ctx = sync_context(&opts.network.sync)?;
    maybe_airdrop(&mut rpc, &ctx.material, network.airdrop_lamports)?;
    let client = ZolanaClient::from_urls(
        rpc,
        network.sync.indexer_url.clone(),
        network.prover_url.clone(),
        Address::new_from_array(network.tree.to_bytes()),
    );
    let recipient = parse_pubkey(&opts.to)?;

    let transfer = create_transfer_sync(TransferParams {
        rpc: &client,
        wallet: &ctx.wallet,
        payer: Address::new_from_array(ctx.material.funding.pubkey().to_bytes()),
        recipient,
        asset,
        amount: opts.amount,
    })?;
    let transaction = sign_private_transaction_sync(
        transfer.transaction,
        &ctx.wallet,
        &ctx.material,
        &client,
        &ctx.material.funding,
    )?;
    let signature = client.rpc().send_transaction(&transaction)?;
    client.confirm_private_transaction_sync(signature)?;
    let mode = if transfer.recipient.is_public_withdrawal() {
        "withdraw"
    } else {
        "shielded"
    };
    println!(
        "ok transfer amount={} mint={} to={} mode={} signature={}",
        opts.amount,
        format_address(asset),
        transfer.recipient.pubkey(),
        mode,
        signature
    );
    Ok(())
}

pub(crate) fn run_split(opts: SplitOptions) -> Result<()> {
    let asset = parse_address(&opts.mint)?;
    let network = get_network(&opts.network)?;
    let mut rpc = SolanaRpc::new(network.sync.rpc_url.clone());
    let ctx = sync_context(&opts.network.sync)?;
    maybe_airdrop(&mut rpc, &ctx.material, network.airdrop_lamports)?;
    let client = ZolanaClient::from_urls(
        rpc,
        network.sync.indexer_url.clone(),
        network.prover_url.clone(),
        Address::new_from_array(network.tree.to_bytes()),
    );
    let input = opts
        .input
        .as_deref()
        .map(parse_hex_array::<32>)
        .transpose()?;

    let split = create_split(SplitParams {
        wallet: &ctx.wallet,
        payer: Address::new_from_array(ctx.material.funding.pubkey().to_bytes()),
        asset,
        parts: opts.parts,
        input,
    })?;
    let parts = split.num_outputs;
    let per_output = split.per_output_amount;
    let transaction = sign_private_transaction_sync(
        split.transaction,
        &ctx.wallet,
        &ctx.material,
        &client,
        &ctx.material.funding,
    )?;
    let signature = client.rpc().send_transaction(&transaction)?;
    client.confirm_private_transaction_sync(signature)?;
    println!(
        "ok split parts={} amount={} mint={} signature={}",
        parts,
        per_output,
        format_address(asset),
        signature
    );
    Ok(())
}

pub(super) fn maybe_airdrop(
    rpc: &mut SolanaRpc,
    material: &WalletMaterial,
    lamports: Option<u64>,
) -> Result<()> {
    let Some(lamports) = lamports else {
        return Ok(());
    };
    let signature = rpc.airdrop(&material.funding.pubkey(), lamports)?;
    println!("ok airdrop signature={signature}");
    Ok(())
}
