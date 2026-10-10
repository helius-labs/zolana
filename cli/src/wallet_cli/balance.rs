use std::collections::BTreeMap;

use anyhow::Result;
use solana_pubkey::Pubkey;
use zolana_transaction::{Address, SpendableDecryptionResult, SOL_MINT};

use super::{
    sync::{sync_context, sync_rpc},
    util::{format_address, parse_address},
};
use crate::args::BalanceOptions;

/// Unspent amounts by asset id, with the mint each id names.
type AssetAmounts = BTreeMap<u64, (Address, u64)>;

/// The default ring's amounts, and each other ring's.
fn amounts(
    spendable: &SpendableDecryptionResult,
) -> (AssetAmounts, BTreeMap<Address, AssetAmounts>) {
    let mut default_ring = AssetAmounts::new();
    let mut rings = BTreeMap::<Address, AssetAmounts>::new();
    for utxo in spendable.utxos() {
        let assets = match utxo.utxo.ring_program_id {
            Some(ring) => rings.entry(ring).or_default(),
            None => &mut default_ring,
        };
        let asset = utxo.utxo.asset;
        let (_, amount) = assets.entry(asset.asset_id).or_insert((asset.asset, 0));
        *amount = amount.saturating_add(utxo.utxo.amount);
    }
    (default_ring, rings)
}

pub(crate) fn run_balance(opts: BalanceOptions) -> Result<()> {
    let ctx = sync_context(&opts.sync, &sync_rpc(&opts.sync)?)?;
    let (default_ring, rings) = amounts(&ctx.spendable);
    let amount_of = |mint: Address| {
        default_ring
            .values()
            .find_map(|&(held, amount)| (held == mint).then_some(amount))
            .unwrap_or(0)
    };

    if let Some(mint) = &opts.mint {
        let mint = parse_address(mint)?;
        println!(
            "ok balance mint={} amount={}",
            format_address(mint),
            amount_of(mint)
        );
        for (ring, assets) in &rings {
            if let Some((_, amount)) = assets.values().find(|(held, _)| *held == mint) {
                println!(
                    "ok balance ring={} mint={} amount={amount}",
                    format_address(*ring),
                    format_address(mint),
                );
            }
        }
        return Ok(());
    }

    println!("ok balance mint=SOL amount={}", amount_of(SOL_MINT));

    let mut printed_spl = Vec::new();
    for &(mint, amount) in default_ring.values() {
        if mint == SOL_MINT {
            continue;
        }
        printed_spl.push(mint);
        println!("ok balance mint={} amount={amount}", format_address(mint));
    }
    for asset in &ctx.local_assets {
        let mint = asset.mint.parse::<Pubkey>()?;
        let mint = Address::new_from_array(mint.to_bytes());
        if !printed_spl.contains(&mint) {
            println!("ok balance mint={} amount=0", format_address(mint));
        }
    }
    for (ring, assets) in &rings {
        for (mint, amount) in assets.values() {
            println!(
                "ok balance ring={} mint={} amount={amount}",
                format_address(*ring),
                format_address(*mint),
            );
        }
    }
    Ok(())
}
