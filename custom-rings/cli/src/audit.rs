//! `audit`, the ring's transactions opened with the auditor key, read from the indexer.

use std::fmt;

use anyhow::{Context as _, Result};
use solana_address::Address;
use zolana_ring_client::{AuditedTransaction, OutputOpening, RingScan};

use crate::{
    controls::ring_auditor_key,
    line,
    ui::{self, icon},
    AuditArgs, Context,
};

pub(crate) struct OpenedSlot<'a> {
    pub slot: u32,
    pub kind: &'a str,
    pub owner: Address,
    pub asset: String,
    pub amount: u64,
}

pub fn run(ctx: &Context, args: AuditArgs) -> Result<()> {
    let config = ctx.ring_config()?;
    let auditor = ring_auditor_key(ctx, &args.auditor_key)?;
    let assets = ctx.rpc().asset_registry()?;
    let mut scan = RingScan::new(ctx.ring.program_id(), auditor.pubkey()).with_mode(config.mode);
    if let Some(cursor) = &args.cursor {
        scan = scan.with_cursor(hex::decode(cursor).context("the cursor is not hex")?);
    }
    let chain = ctx.chain();
    let page = ctx.block(scan.audit(&auditor, chain.indexer(), chain.rpc(), &assets))?;
    for transaction in &page.transactions {
        print(transaction);
    }
    line("transactions", page.transactions.len());
    if let Some(cursor) = page.next_cursor {
        line("next cursor", hex::encode(cursor));
    }
    Ok(())
}

impl fmt::Display for OpenedSlot<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let OpenedSlot {
            slot,
            kind,
            owner,
            asset,
            amount,
        } = self;
        write!(
            f,
            "  slot {slot}  {kind} to {owner}  asset {asset}  amount {amount}"
        )
    }
}

fn print(transaction: &AuditedTransaction) {
    let heading = format!("{} at slot {}", transaction.tx_signature, transaction.slot);
    ui::heading(icon::AUDITOR, &heading);
    if let Some(sender) = &transaction.sender {
        println!(
            "  hidden sender {}",
            Address::new_from_array(sender.owner_key)
        );
    }
    println!("  nullifiers {}", transaction.inputs.len());
    for output in &transaction.outputs {
        let (kind, utxo) = match &output.opening {
            OutputOpening::Ring { utxo, .. } => ("ring", utxo),
            OutputOpening::Exit(utxo) => ("exit", utxo),
            OutputOpening::Dummy => {
                println!("  slot {}  dummy", output.slot_index);
                continue;
            }
        };
        let opened = OpenedSlot {
            slot: output.slot_index,
            kind,
            owner: Address::new_from_array(utxo.owner_key),
            asset: utxo
                .mint
                .map_or_else(|| hex::encode(utxo.asset), |mint| mint.to_string()),
            amount: utxo.amount,
        };
        println!("{opened}");
    }
    for error in &transaction.payload_errors {
        println!("  slot {} payload {:?}", error.slot_index, error.kind);
    }
}
