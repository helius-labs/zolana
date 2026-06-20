use anyhow::Result;
use solana_signer::Signer;
use zolana_client::{create_withdrawal, SolanaRpc, ZolanaIndexer};
use zolana_transaction::{Address, SOL_MINT};

use crate::args::WithdrawOptions;

use super::sync::sync_context;
use super::transaction::{maybe_airdrop, submit_private_transaction, SubmitPrivateTx};
use super::util::{ensure_positive, ensure_sol, parse_pubkey};

pub(super) fn run_withdraw(opts: WithdrawOptions) -> Result<()> {
    ensure_sol(&opts.mint)?;
    ensure_positive(opts.amount)?;
    let mut rpc = SolanaRpc::new(opts.network.sync.rpc_url.clone());
    let indexer = ZolanaIndexer::new(opts.network.sync.indexer_url.clone());
    let ctx = sync_context(&opts.network.sync)?;
    maybe_airdrop(&mut rpc, &ctx.material, opts.network.airdrop_lamports)?;
    let tree = parse_pubkey(&opts.network.tree)?;
    let destination = parse_pubkey(&opts.to)?;

    let withdrawal = create_withdrawal(
        &ctx.wallet,
        &ctx.material.keypair,
        Address::new_from_array(ctx.material.funding.pubkey().to_bytes()),
        destination,
        SOL_MINT,
        opts.amount,
        &ctx.assets,
    )?;
    let signature = submit_private_transaction(
        SubmitPrivateTx {
            rpc: &rpc,
            indexer: &indexer,
            material: &ctx.material,
            tree,
            prover_url: &opts.network.prover_url,
            withdrawal: Some(withdrawal.withdrawal),
            wait_tag: withdrawal.wait_tag,
        },
        withdrawal.signed,
    )?;
    println!(
        "ok withdraw amount={} mint=SOL to={} signature={}",
        opts.amount, destination, signature
    );
    Ok(())
}
