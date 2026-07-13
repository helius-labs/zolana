use anyhow::Result;
use zolana_client::{
    create_deposit, resolve_registered_address, CreateDeposit, SolanaRpc, ZolanaIndexer,
};

use super::{
    material::load_sender_from_resolved_sync,
    resolve::get_network_with_config,
    sync::wait_for_indexed_utxo,
    transaction::maybe_airdrop,
    util::{
        configured_spl_token_account, ensure_positive, format_address, parse_address,
        parse_recipient, RecipientInput,
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
    let indexer = ZolanaIndexer::new(network.sync.indexer_url.clone());
    let material = load_sender_from_resolved_sync(&network.sync)?;
    maybe_airdrop(&mut rpc, &material, network.airdrop_lamports)?;
    let tree = network.tree;
    // A shielded address is used directly; a Solana pubkey must have a user
    // registry record (a deposit has no public fallback). Defaults to self.
    let recipient = match opts.to.as_deref() {
        None => material.keypair.shielded_address()?,
        Some(to) => match parse_recipient(to)? {
            RecipientInput::Shielded(address) => address,
            RecipientInput::Pubkey(owner) => resolve_registered_address(&rpc, owner)?,
        },
    };
    let deposit = create_deposit(CreateDeposit {
        recipient: &recipient,
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
        recipient,
        hex::encode(deposit.utxo_hash),
        signature
    );
    Ok(())
}
