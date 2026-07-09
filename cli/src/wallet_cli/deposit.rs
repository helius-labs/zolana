use anyhow::Result;
use rings_client::{
    create_deposit, resolve_registered_address, CreateDeposit, RingsIndexer, SolanaRpc,
};
use solana_signer::Signer;

use super::{
    material::load_sender_from_resolved_sync,
    resolve::get_network_with_config,
    sync::wait_for_indexed_utxo,
    transaction::maybe_airdrop,
    util::{
        configured_spl_token_account, ensure_positive, format_address, parse_address, parse_pubkey,
    },
};
use crate::{args::DepositOptions, cli_config::CliConfigFile};

pub(super) fn run_deposit(opts: DepositOptions) -> Result<()> {
    ensure_positive(opts.amount)?;
    let asset = parse_address(&opts.mint)?;
    let config = CliConfigFile::load()?;
    let spl_token_account = configured_spl_token_account(&config, asset)?;
    let network = get_network_with_config(&opts.network, &config)?;
    let mut rpc = SolanaRpc::new(network.sync.rpc_url.clone());
    let indexer = RingsIndexer::new(network.sync.indexer_url.clone());
    let material = load_sender_from_resolved_sync(&network.sync)?;
    maybe_airdrop(&mut rpc, &material, network.airdrop_lamports)?;
    let tree = network.tree;
    let recipient_pubkey = opts
        .to
        .as_deref()
        .map(parse_pubkey)
        .transpose()?
        .unwrap_or_else(|| material.funding.pubkey());
    let recipient = resolve_registered_address(&rpc, recipient_pubkey)?;
    let deposit = create_deposit(CreateDeposit {
        recipient: &recipient.address,
        asset,
        amount: opts.amount,
        spl_token_account,
        memo: None,
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
