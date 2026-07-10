use anyhow::Result;
use solana_signer::Signer;
use zolana_client::{
    create_deposit, resolve_registered_address, CreateDeposit, SolanaRpc, ZolanaIndexer,
};

use super::{
    material::load_sender_from_resolved_sync,
    resolve::get_network_with_config,
    sync::wait_for_indexed_output,
    transaction::maybe_airdrop,
    util::{
        ensure_owner_spl_token_account, ensure_positive, format_address, owner_spl_token_account,
        parse_address, parse_amount_for_asset, resolve_recipient_pubkey,
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
    // A self-deposit (no --to) targets the wallet's own shielded address, so it
    // needs no user-registry lookup. Depositing to someone else still resolves
    // their registered address on-chain.
    let (recipient_pubkey, recipient_address) = match opts.to.as_deref() {
        None => (
            material.funding.pubkey(),
            material.keypair.shielded_address()?,
        ),
        Some(to) => {
            let pubkey = resolve_recipient_pubkey(to)?;
            (pubkey, resolve_registered_address(&rpc, pubkey)?.address())
        }
    };
    let spl_token_account = owner_spl_token_account(material.funding.pubkey(), asset);
    let deposit = create_deposit(CreateDeposit {
        recipient: &recipient_address,
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
        recipient_pubkey,
        hex::encode(deposit.utxo_hash),
        signature,
        outcome.pending_suffix(),
    );
    Ok(())
}
