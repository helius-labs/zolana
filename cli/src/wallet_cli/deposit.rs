use anyhow::{Context, Result};
use solana_signer::Signer;
use zolana_client::{
    user_registry::resolve_registered_address, ComputeBudgetConfig, Rpc, SolanaRpc, ZolanaIndexer,
};
use zolana_program::instruction::{Deposit, DepositAsset, DepositSplAccounts};
use zolana_transaction::{instructions::deposit::deposit_to, Address};

use super::{
    material::load_sender_from_resolved_sync,
    resolve::get_network_with_config,
    sync::wait_for_indexed_utxo,
    transaction::maybe_airdrop,
    util::{
        configured_spl_token_account, ensure_positive, format_address, parse_address, parse_pubkey,
        resolve_spl_token_program,
    },
};
use crate::{args::DepositOptions, cli_config::CliConfigFile};

pub(crate) fn run_deposit(opts: DepositOptions) -> Result<()> {
    ensure_positive(opts.amount)?;
    let asset = parse_address(&opts.mint)?;
    let config = CliConfigFile::load()?;
    let spl_token_account = configured_spl_token_account(&config, asset)?;
    let network = get_network_with_config(&opts.network, &config)?;
    let mut rpc = SolanaRpc::new(network.sync.rpc_url.clone());
    let indexer = ZolanaIndexer::new(network.sync.indexer_url.clone());
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
    let deposit_asset = if asset == zolana_transaction::SOL_MINT {
        DepositAsset::Sol
    } else {
        let mint = solana_pubkey::Pubkey::new_from_array(asset.to_bytes());
        DepositAsset::Spl(DepositSplAccounts {
            mint,
            user_token: spl_token_account.context("SPL deposit needs a token account")?,
            token_program: resolve_spl_token_program(&rpc, &mint)?,
        })
    };
    let entry = deposit_to(deposit_asset, opts.amount, &recipient.address)?;
    let view_tag = entry.view_tag;
    let deposit = Deposit {
        tree,
        depositor: material.funding.pubkey(),
        deposits: vec![entry],
    }
    .instruction()?;
    let signature = rpc.create_and_send_transaction(
        &[deposit],
        Address::new_from_array(material.funding.pubkey().to_bytes()),
        &[&material.funding],
        ComputeBudgetConfig::for_instruction_count(1),
    )?;
    let indexed = wait_for_indexed_utxo(&indexer, view_tag, signature)?;
    println!(
        "ok deposit amount={} mint={} to={} utxo_hash={} signature={}",
        opts.amount,
        format_address(asset),
        recipient_pubkey,
        hex::encode(indexed.output_slot.output_context.hash),
        signature
    );
    Ok(())
}
