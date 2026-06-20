use anyhow::Result;
use solana_signer::Signer;
use zolana_client::{SolanaRpc, Transaction, WithdrawalTarget, ZolanaIndexer};
use zolana_interface::instruction::{TransactSolWithdrawal, TransactWithdrawal};
use zolana_transaction::{Address, SOL_MINT};

use crate::args::WithdrawOptions;

use super::sync::sync_context;
use super::transaction::{
    maybe_airdrop, next_sender_view_tag, select_inputs, submit_private_transaction, SubmitPrivateTx,
};
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

    let sender_view_tag = next_sender_view_tag(&ctx)?;
    let inputs = select_inputs(&ctx, SOL_MINT, opts.amount)?;
    let mut tx = Transaction::new(
        ctx.material.keypair.shielded_address()?,
        inputs,
        Address::new_from_array(ctx.material.funding.pubkey().to_bytes()),
    );
    tx.withdraw(
        SOL_MINT,
        opts.amount,
        WithdrawalTarget::Sol {
            user_sol_account: Address::new_from_array(destination.to_bytes()),
        },
    )?;
    let signed = tx.sign(&ctx.material.keypair, &ctx.assets, sender_view_tag)?;
    let signature = submit_private_transaction(
        SubmitPrivateTx {
            rpc: &rpc,
            indexer: &indexer,
            material: &ctx.material,
            tree,
            prover_url: &opts.network.prover_url,
            withdrawal: Some(TransactWithdrawal::Sol(TransactSolWithdrawal {
                recipient: destination,
            })),
            wait_tag: sender_view_tag,
        },
        signed,
    )?;
    println!(
        "ok withdraw amount={} mint=SOL to={} signature={}",
        opts.amount, destination, signature
    );
    Ok(())
}
