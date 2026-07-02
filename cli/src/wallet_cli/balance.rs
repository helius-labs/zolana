use anyhow::Result;
use solana_pubkey::Pubkey;
use zolana_transaction::SOL_MINT;

use super::{
    sync::sync_context,
    util::{format_address, parse_address},
};
use crate::args::BalanceOptions;

pub(super) fn run_balance(opts: BalanceOptions) -> Result<()> {
    let ctx = sync_context(&opts.sync)?;
    let balances = ctx.wallet.balances(true)?;

    if let Some(mint) = &opts.mint {
        let mint = parse_address(mint)?;
        let amount = balances
            .iter()
            .find_map(|balance| (balance.mint == mint).then_some(balance.amount))
            .unwrap_or(0);
        println!("ok balance mint={} amount={amount}", format_address(mint));
        return Ok(());
    }

    let sol_amount = balances
        .iter()
        .find_map(|balance| (balance.mint == SOL_MINT).then_some(balance.amount))
        .unwrap_or(0);
    println!("ok balance mint=SOL amount={sol_amount}");

    let mut printed_spl = Vec::new();
    for balance in balances {
        if balance.mint == SOL_MINT {
            continue;
        }
        printed_spl.push(balance.mint);
        println!(
            "ok balance mint={} amount={}",
            format_address(balance.mint),
            balance.amount
        );
    }
    for asset in &ctx.local_assets {
        let mint = asset.mint.parse::<Pubkey>()?;
        let mint = zolana_transaction::Address::new_from_array(mint.to_bytes());
        if !printed_spl.contains(&mint) {
            println!("ok balance mint={} amount=0", format_address(mint));
        }
    }
    Ok(())
}
