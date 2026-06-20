use anyhow::Result;
use solana_signer::Signer;
use zolana_client::{
    create_deposit, validate_registered_keypair, CreateDeposit, SolanaRpc, ZolanaIndexer,
};

use crate::args::DepositOptions;
use crate::cli_config::CliConfigFile;

use super::material::{load_recipient_wallet, load_sender_from_sync};
use super::resolve::get_network;
use super::sync::wait_for_indexed_utxo;
use super::transaction::maybe_airdrop;
use super::util::{configured_spl_token_account, ensure_positive, format_address, parse_address};

pub(super) fn run_deposit(opts: DepositOptions) -> Result<()> {
    ensure_positive(opts.amount)?;
    let asset = parse_address(&opts.mint)?;
    let config = CliConfigFile::load()?;
    let spl_token_account = configured_spl_token_account(&config, asset)?;
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

    validate_registered_keypair(&rpc, recipient_pubkey, recipient_keypair)?;
    let deposit = create_deposit(CreateDeposit {
        recipient: recipient_keypair,
        asset,
        amount: opts.amount,
        spl_token_account,
    })?;
    let signature = deposit.send(&rpc, &material.funding, tree, &material.funding)?;
    wait_for_indexed_utxo(&indexer, deposit.view_tag(), signature)?;
    println!(
        "ok deposit amount={} mint={} to={} utxo_hash={} signature={}",
        opts.amount,
        format_address(asset),
        recipient_pubkey,
        hex::encode(deposit.utxo_hash),
        signature
    );
    Ok(())
}
