use anyhow::Result;
use solana_signer::Signer;
use zolana_client::{
    create_transfer_sync, sign_private_transaction_sync, Rpc, SolanaRpc, TransferParams,
    ZolanaClient,
};
use zolana_transaction::Address;

use super::{
    material::WalletMaterial,
    resolve::get_network,
    sync::sync_context,
    util::{ensure_positive, format_address, parse_address, parse_pubkey},
};
use crate::args::TransferOptions;

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
