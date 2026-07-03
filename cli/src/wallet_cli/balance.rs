use anyhow::Result;
use solana_pubkey::Pubkey;
use zolana_transaction::SOL_MINT;

use super::{
    sync::sync_context,
    util::{format_address, lamports_to_sol_string, parse_address},
};
use crate::args::BalanceOptions;

/// SOL balances are printed in human units (`sol=`); SPL balances only carry raw
/// base units, so they print `amount=` alone.
fn print_balance(mint: zolana_transaction::Address, amount: u64) {
    if mint == SOL_MINT {
        println!(
            "ok balance mint=SOL sol={} amount={amount}",
            lamports_to_sol_string(amount)
        );
    } else {
        println!("ok balance mint={} amount={amount}", format_address(mint));
    }
}

pub(super) fn run_balance(opts: BalanceOptions) -> Result<()> {
    let ctx = sync_context(&opts.sync)?;
    let balances = ctx.wallet.balances(true)?;

    if let Some(mint) = &opts.mint {
        let mint = parse_address(mint)?;
        let amount = balances
            .iter()
            .find_map(|balance| (balance.mint == mint).then_some(balance.amount))
            .unwrap_or(0);
        print_balance(mint, amount);
        return Ok(());
    }

    let sol_amount = balances
        .iter()
        .find_map(|balance| (balance.mint == SOL_MINT).then_some(balance.amount))
        .unwrap_or(0);
    print_balance(SOL_MINT, sol_amount);

    let mut printed_spl = Vec::new();
    for balance in balances {
        if balance.mint == SOL_MINT {
            continue;
        }
        printed_spl.push(balance.mint);
        print_balance(balance.mint, balance.amount);
    }
    for asset in &ctx.local_assets {
        let mint = asset.mint.parse::<Pubkey>()?;
        let mint = zolana_transaction::Address::new_from_array(mint.to_bytes());
        if !printed_spl.contains(&mint) {
            print_balance(mint, 0);
        }
    }
    Ok(())
}
