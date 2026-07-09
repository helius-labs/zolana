use anyhow::Result;
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use zolana_client::{
    resolve_recipient, PrivateTransfer, ProverClient, SolanaRpc, Submit, ZolanaIndexer,
};

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
    let mint = Pubkey::new_from_array(asset.to_bytes());
    let network = get_network(&opts.network)?;
    let mut rpc = SolanaRpc::new(network.sync.rpc_url.clone());
    let indexer = ZolanaIndexer::new(network.sync.indexer_url.clone());
    let ctx = sync_context(&opts.network.sync)?;
    maybe_airdrop(&mut rpc, &ctx.material, network.airdrop_lamports)?;
    let recipient = parse_pubkey(&opts.to)?;
    let tree = network.tree;

    let prover = ProverClient::new(network.prover_url.clone());
    let submit = Submit {
        indexer: &indexer,
        rpc: &rpc,
        prover: &prover,
        payer: &ctx.material.funding,
        tree,
        cu_limit: None,
    };
    // An unregistered recipient resolves to a public withdrawal; the mode in
    // the output reports which way the transfer settled.
    let transfer = PrivateTransfer {
        source: &ctx.wallet,
        destination: resolve_recipient(&rpc, recipient)?,
        asset: mint,
        amount: opts.amount,
        authority: &ctx.material,
        payer: ctx.material.funding.pubkey(),
        memo: None,
    }
    .instruction()?;
    let signature = submit.execute(&transfer)?;
    let mode = if transfer.recipient.is_public() {
        "withdraw"
    } else {
        "shielded"
    };
    println!(
        "ok transfer amount={} mint={} to={} mode={} signature={}",
        opts.amount,
        format_address(asset),
        recipient,
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
