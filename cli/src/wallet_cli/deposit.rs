use anyhow::Result;
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use zolana_client::{create_deposit, CreateDeposit, SolanaRpc, ZolanaIndexer};

use super::{
    material::load_sender_from_resolved_sync,
    resolve::get_network_with_config,
    sync::wait_for_indexed_output,
    transaction::maybe_airdrop,
    util::{
        configured_or_owner_spl_token_account, ensure_owner_spl_token_account, ensure_positive,
        format_address, parse_address, parse_shielded_address,
    },
};
use crate::{args::DepositOptions, cli_config::CliConfigFile};

pub(super) fn run_deposit(opts: DepositOptions) -> Result<()> {
    ensure_positive(opts.amount)?;
    let asset = parse_address(&opts.mint)?;
    let recipient_override = opts.to.as_deref().map(parse_shielded_address).transpose()?;
    let config = CliConfigFile::load()?;
    config.local_asset_registry()?.asset_id(&asset)?;
    let network = get_network_with_config(&opts.network, &config)?;
    let mut rpc = SolanaRpc::new(network.sync.rpc_url.clone());
    let indexer = ZolanaIndexer::new(network.sync.indexer_url.clone());
    let material = load_sender_from_resolved_sync(&network.sync)?;
    let owner = material.funding.pubkey();
    let configured_spl_account = if asset == zolana_transaction::SOL_MINT {
        None
    } else {
        config.token_account_for_mint(Pubkey::new_from_array(asset.to_bytes()))?
    };
    let spl_token_account = configured_or_owner_spl_token_account(&config, owner, asset)?;
    let tree = network.tree;
    let recipient = match recipient_override {
        None => material.keypair.shielded_address()?,
        Some(recipient) => recipient,
    };
    let deposit = create_deposit(CreateDeposit {
        recipient: &recipient,
        asset,
        amount: opts.amount,
        spl_token_account,
        memo: None,
    })?;
    maybe_airdrop(&mut rpc, &material, network.airdrop_lamports)?;
    if configured_spl_account.is_none() {
        ensure_owner_spl_token_account(&rpc, &material.funding, owner, asset)?;
    }
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
