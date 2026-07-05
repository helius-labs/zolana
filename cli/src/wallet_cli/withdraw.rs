use anyhow::Result;
use solana_signer::Signer;
use zolana_client::{
    create_withdrawal_sync, CreateWithdrawal, ProverClient, SolanaRpc, Submit, ZolanaIndexer,
};
use zolana_transaction::Address;

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

    let withdrawal = create_withdrawal_sync(CreateWithdrawal {
        wallet: &ctx.wallet,
        authority: &ctx.material,
        owner_pubkey: ctx.material.owner_pubkey(),
        payer: Address::new_from_array(ctx.material.funding.pubkey().to_bytes()),
        recipient,
        asset,
        amount: opts.amount,
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
        withdrawal.signed,
        Some(withdrawal.withdrawal),
        withdrawal.wait_tag,
    )?;
    println!(
        "ok withdraw amount={} mint={} to={} signature={}",
        opts.amount,
        format_address(asset),
        recipient,
        signature
    );
    Ok(())
}
