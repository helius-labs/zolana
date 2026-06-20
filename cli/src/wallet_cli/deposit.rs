use anyhow::Result;
use solana_signer::Signer;
use zolana_client::{create_deposit, SolanaRpc, ZolanaIndexer};

use crate::args::DepositOptions;

use super::material::{load_recipient_wallet, load_sender_from_sync};
use super::resolve::get_network;
use super::sync::wait_for_indexed_utxo;
use super::transaction::maybe_airdrop;
use super::util::{ensure_positive, ensure_sol};

pub(super) fn run_deposit(opts: DepositOptions) -> Result<()> {
    ensure_sol(&opts.mint)?;
    ensure_positive(opts.amount)?;
    let network = get_network(&opts.network)?;
    let mut rpc = SolanaRpc::new(network.sync.rpc_url.clone());
    let indexer = ZolanaIndexer::new(network.sync.indexer_url.clone());
    let material = load_sender_from_sync(&opts.network.sync)?;
    maybe_airdrop(&mut rpc, &material, network.airdrop_lamports)?;
    let recipient = opts.to.as_deref().map(load_recipient_wallet).transpose()?;
    let tree = network.tree;

    let recipient_keypair = recipient
        .as_ref()
        .map(|recipient| &recipient.keypair)
        .unwrap_or(&material.keypair);
    let recipient_pubkey = recipient
        .as_ref()
        .map(|recipient| recipient.funding.pubkey())
        .unwrap_or_else(|| material.funding.pubkey());

    let deposit = create_deposit(recipient_keypair, opts.amount)?;
    let signature = deposit.send(&rpc, &material.funding, tree, &material.funding)?;
    wait_for_indexed_utxo(&indexer, deposit.view_tag(), signature)?;
    println!(
        "ok deposit amount={} mint=SOL to={} utxo_hash={} signature={}",
        opts.amount,
        recipient_pubkey,
        hex::encode(deposit.utxo_hash),
        signature
    );
    Ok(())
}
