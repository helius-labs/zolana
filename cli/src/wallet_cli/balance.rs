use anyhow::Result;
use zolana_transaction::SOL_MINT;

use crate::args::BalanceOptions;

use super::sync::sync_context;
use super::util::{ensure_sol, format_address};

pub(super) fn run_balance(opts: BalanceOptions) -> Result<()> {
    let ctx = sync_context(&opts.sync)?;
    let balances = ctx.wallet.balances(&ctx.assets, true)?;

    if let Some(mint) = &opts.mint {
        ensure_sol(mint)?;
        let amount = balances
            .iter()
            .find_map(|balance| (balance.mint == SOL_MINT).then_some(balance.amount))
            .unwrap_or(0);
        println!("ok balance mint=SOL amount={amount}");
        return Ok(());
    }

    if balances.is_empty() {
        println!("ok balance mint=SOL amount=0");
        return Ok(());
    }
    for balance in balances {
        println!(
            "ok balance mint={} amount={}",
            format_address(balance.mint),
            balance.amount
        );
    }
    Ok(())
}
