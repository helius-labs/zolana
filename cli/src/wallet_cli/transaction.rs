use anyhow::Result;
use solana_signer::Signer;
use zolana_client::{
    create_transfer_sync, CreateTransfer, ProverClient, SolanaRpc, Submit, ZolanaIndexer,
};
use zolana_transaction::Address;

use super::{
    material::WalletMaterial,
    resolve::get_network,
    sync::sync_context,
    util::{ensure_positive, format_address, parse_address, parse_pubkey},
};
use crate::args::TransferOptions;

pub(super) fn run_transfer(opts: TransferOptions) -> Result<()> {
    ensure_positive(opts.amount)?;
    let asset = parse_address(&opts.mint)?;
    let network = get_network(&opts.network)?;
    let mut rpc = SolanaRpc::new(network.sync.rpc_url.clone());
    let indexer = ZolanaIndexer::new(network.sync.indexer_url.clone());
    let ctx = sync_context(&opts.network.sync)?;
    maybe_airdrop(&mut rpc, &ctx.material, network.airdrop_lamports)?;
    let recipient = parse_pubkey(&opts.to)?;
    let tree = network.tree;

    let transfer = create_transfer_sync(CreateTransfer {
        rpc: &rpc,
        wallet: &ctx.wallet,
        authority: &ctx.material,
        owner_pubkey: ctx.material.owner_pubkey(),
        payer: Address::new_from_array(ctx.material.funding.pubkey().to_bytes()),
        recipient,
        asset,
        amount: opts.amount,
        memo: None,
    })?;
    let prover = ProverClient::new(network.prover_url.clone());
    let signature = Submit {
        indexer: &indexer,
        rpc: &rpc,
        prover: &prover,
        payer: &ctx.material.funding,
        tree,
        cu_limit: None,
    }
    .execute(
        transfer.signed,
        transfer.recipient.withdrawal().cloned(),
        transfer.wait_tag,
    )?;
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
