use anyhow::Result;
use solana_signer::Signer;
use zolana_client::{create_deposit, CreateDeposit, SolanaRpc, ZolanaIndexer};

use super::{
    material::load_sender_from_resolved_sync,
    resolve::get_network_with_config,
    sync::wait_for_indexed_output,
    transaction::maybe_airdrop,
    util::{
        ensure_owner_spl_token_account, ensure_positive, format_address, owner_spl_token_account,
        parse_address, parse_amount_for_asset, parse_shielded_address,
    },
};
use crate::{args::DepositOptions, cli_config::CliConfigFile};

pub(super) fn run_deposit(opts: DepositOptions) -> Result<()> {
    let asset = parse_address(&opts.mint)?;
    let amount = parse_amount_for_asset(&opts.amount, asset)?;
    ensure_positive(amount)?;
    let config = CliConfigFile::load()?;
    config.local_asset_registry()?.asset_id(&asset)?;
    let network = get_network_with_config(&opts.network, &config)?;
    let mut rpc = SolanaRpc::new(network.sync.rpc_url.clone());
    let indexer = ZolanaIndexer::new(network.sync.indexer_url.clone());
    let material = load_sender_from_resolved_sync(&network.sync)?;
    let tree = network.tree;
    let recipient = match opts.to.as_deref() {
        None => material.keypair.shielded_address()?,
        Some(to) => parse_shielded_address(to)?,
    };
    let spl_token_account = owner_spl_token_account(material.funding.pubkey(), asset);
    let deposit = create_deposit(CreateDeposit {
        recipient: &recipient,
        asset,
        amount,
        spl_token_account,
        memo: None,
    })?;
    maybe_airdrop(&mut rpc, &material, network.airdrop_lamports)?;
    ensure_owner_spl_token_account(&rpc, &material.funding, material.funding.pubkey(), asset)?;
    let signature = deposit.send(&rpc, &material.funding, tree, &material.funding)?;
    let outcome = wait_for_indexed_output(&indexer, &rpc, tree, deposit.utxo_hash, signature)?;
    println!(
        "ok deposit amount={} mint={} to={} utxo_hash={} signature={}{}",
        opts.amount,
        format_address(asset),
        recipient,
        hex::encode(deposit.utxo_hash),
        signature,
        outcome.pending_suffix(),
    );
    Ok(())
}
