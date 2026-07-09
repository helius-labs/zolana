use anyhow::Result;
use solana_signer::Signer;
use zolana_client::{create_withdrawal_sync, CreateWithdrawal, SolanaRpc, ZolanaIndexer};
use zolana_transaction::Address;

use super::{
    resolve::get_network_with_config,
    sync::sync_context,
    transaction::{
        maybe_airdrop, resolve_auto_spend_selection, submit_private_transaction, SubmitPrivateTx,
    },
    util::{
        ensure_positive, format_address, parse_address, parse_amount_for_asset,
        resolve_recipient_pubkey,
    },
};
use crate::{args::WithdrawOptions, cli_config::CliConfigFile};

pub(super) fn run_withdraw(opts: WithdrawOptions) -> Result<()> {
    let asset = parse_address(&opts.mint)?;
    let amount = parse_amount_for_asset(&opts.amount, asset)?;
    ensure_positive(amount)?;
    let config = CliConfigFile::load()?;
    let network = get_network_with_config(&opts.network, &config)?;
    let mut rpc = SolanaRpc::new(network.sync.rpc_url.clone());
    let indexer = ZolanaIndexer::new(network.sync.indexer_url.clone());
    let ctx = sync_context(&opts.network.sync)?;
    maybe_airdrop(&mut rpc, &ctx.material, network.airdrop_lamports)?;
    let tree = network.tree;
    let recipient = resolve_recipient_pubkey(&opts.to, &config)?;

    let (selection, reservations) =
        resolve_auto_spend_selection(&opts.network.sync, &config, &ctx, asset, amount)?;
    let withdrawal = create_withdrawal_sync(CreateWithdrawal {
        wallet: &ctx.wallet,
        authority: &ctx.material,
        owner_pubkey: ctx.material.owner_pubkey(),
        payer: Address::new_from_array(ctx.material.funding.pubkey().to_bytes()),
        recipient,
        asset,
        amount,
        assets: &ctx.wallet.registry,
        selection,
    })?;
    let (signature, outcome) = submit_private_transaction(
        SubmitPrivateTx {
            rpc: &rpc,
            indexer: &indexer,
            material: &ctx.material,
            tree,
            prover_url: &network.prover_url,
            withdrawal: Some(withdrawal.withdrawal),
            wait_output_hash: withdrawal.wait_output_hash,
            reservations: &reservations,
        },
        withdrawal.signed,
    )?;
    println!(
        "ok withdraw amount={} mint={} to={} signature={}{}",
        opts.amount,
        format_address(asset),
        recipient,
        signature,
        outcome.pending_suffix(),
    );
    Ok(())
}
