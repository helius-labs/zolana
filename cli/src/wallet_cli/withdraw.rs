use anyhow::Result;
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use zolana_client::{ProverClient, SolanaRpc, Submit, Withdrawal, ZolanaIndexer};

use super::{
    resolve::get_network,
    sync::sync_context,
    transaction::maybe_airdrop,
    util::{ensure_positive, format_address, parse_address, parse_pubkey},
};
use crate::args::WithdrawOptions;

pub(super) fn run_withdraw(opts: WithdrawOptions) -> Result<()> {
    ensure_positive(opts.amount)?;
    let asset = parse_address(&opts.mint)?;
    let network = get_network(&opts.network)?;
    let mut rpc = SolanaRpc::new(network.sync.rpc_url.clone());
    let indexer = ZolanaIndexer::new(network.sync.indexer_url.clone());
    let ctx = sync_context(&opts.network.sync)?;
    maybe_airdrop(&mut rpc, &ctx.material, network.airdrop_lamports)?;
    let tree = network.tree;
    let recipient = parse_pubkey(&opts.to)?;

    let withdrawal = Withdrawal {
        source: &ctx.wallet,
        destination: recipient,
        asset: Pubkey::new_from_array(asset.to_bytes()),
        amount: opts.amount,
        authority: &ctx.material,
        payer: ctx.material.funding.pubkey(),
    }
    .instruction()?;
    let prover = ProverClient::new(network.prover_url.clone());
    let signature = Submit {
        indexer: &indexer,
        rpc: &rpc,
        prover: &prover,
        payer: &ctx.material.funding,
        tree,
        cu_limit: None,
    }
    .execute(&withdrawal)?;
    println!(
        "ok withdraw amount={} mint={} to={} signature={}",
        opts.amount,
        format_address(asset),
        recipient,
        signature
    );
    Ok(())
}
