use anyhow::Result;
use solana_signer::Signer;
use zolana_client::{create_deposit, SolanaRpc, ZolanaIndexer};

use crate::args::DepositOptions;

use super::material::{load_recipient_wallet, load_sender_from_sync};
use super::sync::wait_for_indexed_utxo;
use super::transaction::maybe_airdrop;
use super::util::{ensure_positive, ensure_sol, parse_pubkey};

pub(super) fn run_deposit(opts: DepositOptions) -> Result<()> {
    ensure_sol(&opts.mint)?;
    ensure_positive(opts.amount)?;
    let mut rpc = SolanaRpc::new(opts.network.sync.rpc_url.clone());
    let indexer = ZolanaIndexer::new(opts.network.sync.indexer_url.clone());
    let material = load_sender_from_sync(&opts.network.sync)?;
    maybe_airdrop(&mut rpc, &material, opts.network.airdrop_lamports)?;
    let recipient = load_recipient_wallet(&opts.to)?;
    let tree = parse_pubkey(&opts.network.tree)?;

    let deposit = create_deposit(&recipient.keypair, opts.amount)?;
    let signature = deposit.send(&rpc, &material.funding, tree, &material.funding)?;
    wait_for_indexed_utxo(&indexer, deposit.view_tag(), signature)?;
    println!(
        "ok deposit amount={} mint=SOL to={} utxo_hash={} signature={}",
        opts.amount,
        recipient.funding.pubkey(),
        hex::encode(deposit.utxo_hash),
        signature
    );
    Ok(())
}
