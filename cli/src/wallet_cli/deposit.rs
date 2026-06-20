use anyhow::Result;
use solana_signer::Signer;
use zolana_client::{Rpc, SolanaRpc, ZolanaIndexer};
use zolana_interface::instruction::Deposit;
use zolana_keypair::random_salt;
use zolana_transaction::{owner_utxo_hash, utxo_hash, Address, SOL_MINT};

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

    let salt = random_salt();
    let blinding = recipient
        .keypair
        .viewing_key
        .derive_proofless_blinding(&salt)?;
    let owner_hash = recipient.keypair.owner_hash()?;
    let owner_utxo_hash = owner_utxo_hash(&owner_hash, &blinding)?;
    let view_tag = recipient.keypair.recipient_bootstrap_view_tag();
    let deposit_hash = utxo_hash(
        SOL_MINT,
        opts.amount,
        &[0u8; 32],
        &[0u8; 32],
        None,
        &owner_utxo_hash,
    )?;
    let ix = Deposit {
        tree,
        depositor: material.funding.pubkey(),
        spl: None,
        view_tag,
        owner_utxo_hash,
        salt,
        public_amount: Some(opts.amount),
        program_data_hash: None,
        program_data: None,
        cpi_signer: None,
    }
    .instruction();
    let signature = rpc.create_and_send_transaction(
        &[ix],
        Address::new_from_array(material.funding.pubkey().to_bytes()),
        &[&material.funding],
    )?;
    wait_for_indexed_utxo(&indexer, view_tag, signature)?;
    println!(
        "ok deposit amount={} mint=SOL to={} utxo_hash={} signature={}",
        opts.amount,
        recipient.funding.pubkey(),
        hex::encode(deposit_hash),
        signature
    );
    Ok(())
}
