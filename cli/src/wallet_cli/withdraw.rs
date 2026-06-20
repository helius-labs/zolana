use anyhow::Result;
use solana_signer::Signer;
use zolana_client::{create_withdrawal, CreateWithdrawal, SolanaRpc, ZolanaIndexer};
use zolana_transaction::Address;

use crate::args::WithdrawOptions;

use super::resolve::get_network;
use super::sync::sync_context;
use super::transaction::{maybe_airdrop, submit_private_transaction, SubmitPrivateTx};
use super::util::{ensure_positive, format_address, parse_address, parse_pubkey};

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

    let withdrawal = create_withdrawal(CreateWithdrawal {
        wallet: &ctx.wallet,
        keypair: &ctx.material.keypair,
        payer: Address::new_from_array(ctx.material.funding.pubkey().to_bytes()),
        recipient,
        asset,
        amount: opts.amount,
        assets: &ctx.assets,
    })?;
    let signature = submit_private_transaction(
        SubmitPrivateTx {
            rpc: &rpc,
            indexer: &indexer,
            material: &ctx.material,
            tree,
            prover_url: &network.prover_url,
            withdrawal: Some(withdrawal.withdrawal),
            wait_tag: withdrawal.wait_tag,
        },
        withdrawal.signed,
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
