use anyhow::Result;
use solana_signer::Signer;
use zolana_client::{
    create_withdrawal, sign_private_transaction_sync, Rpc, SolanaRpc, WithdrawalParams,
    ZolanaClient,
};
use zolana_transaction::Address;

use super::{
    resolve::get_network,
    sync::sync_context,
    transaction::maybe_airdrop,
    util::{
        ensure_owner_spl_token_account, ensure_positive, format_address, parse_address,
        parse_pubkey,
    },
};
use crate::args::WithdrawOptions;

pub(crate) fn run_withdraw(opts: WithdrawOptions) -> Result<()> {
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

    // An SPL withdrawal settles into the recipient's associated token account,
    // which the on-chain settlement validates, so create it first (no-op for
    // SOL). The funding wallet pays for the account.
    ensure_owner_spl_token_account(&client, &ctx.material.funding, recipient, asset)?;

    let withdrawal = create_withdrawal(WithdrawalParams {
        wallet: &ctx.wallet,
        payer: Address::new_from_array(ctx.material.funding.pubkey().to_bytes()),
        recipient,
        asset,
        amount: opts.amount,
    })?;
    let transaction = sign_private_transaction_sync(
        withdrawal.transaction,
        &ctx.wallet,
        &ctx.material,
        &client,
        &ctx.material.funding,
    )?;
    let signature = client.rpc().send_transaction(&transaction)?;
    client.confirm_private_transaction_sync(signature)?;
    println!(
        "ok withdraw amount={} mint={} to={} signature={}",
        opts.amount,
        format_address(asset),
        recipient,
        signature
    );
    Ok(())
}
