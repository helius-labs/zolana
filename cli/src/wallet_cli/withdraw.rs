use anyhow::Result;
use solana_signer::Signer;
use zolana_client::SolanaRpc;
use zolana_transaction::{instructions::transact::ConfidentialTransaction, Address};

use super::{
    resolve::get_network,
    spend::{send_private, Send},
    sync::sync_context,
    transaction::{client, maybe_airdrop},
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
    let client = client(rpc, &network)?;
    let recipient = parse_pubkey(&opts.to)?;

    // An SPL withdrawal settles into the recipient's associated token account,
    // which the on-chain settlement validates, so create it first (no-op for
    // SOL). The funding wallet pays for the account.
    let spl_token_program =
        ensure_owner_spl_token_account(&client, &ctx.material.funding, recipient, asset)?
            .map(|(_, token_program)| token_program);

    let inputs = ctx
        .spendable
        .select_spend(asset, opts.amount, &Default::default())?;
    let payer = Address::new_from_array(ctx.material.funding.pubkey().to_bytes());
    let mut transaction = ConfidentialTransaction::new(inputs, payer)?;
    let settlement = transaction.withdraw_to(asset, opts.amount, recipient, spl_token_program)?;
    let signature = send_private(&ctx, &client, transaction, vec![settlement], Send::Checked)?;
    println!(
        "ok withdraw amount={} mint={} to={} signature={}",
        opts.amount,
        format_address(asset),
        recipient,
        signature
    );
    Ok(())
}
