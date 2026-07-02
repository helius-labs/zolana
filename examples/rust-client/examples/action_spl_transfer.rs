//! Private SPL transfer with the ergonomic `create_transfer_sync` action.
//!
//! A transfer spends the asset UTXO plus a SOL fee UTXO (the 2-in shape), so
//! sender is seeded with both an SPL note and a SOL note before sending.

use anyhow::{anyhow, Result};
use rust_client_example::{
    ensure_spl_asset, new_party, register, setup, shield_sol, shield_spl, wait_for_indexed,
};
use solana_address::Address;
use solana_signer::Signer;
use zolana_client::{
    create_transfer_sync, get_private_token_balances, sync_wallet, CreateTransfer,
};

fn main() -> Result<()> {
    let mut context = setup()?;
    let asset = ensure_spl_asset(&mut context)?;
    let (sender_keypair, sender_funding, mut sender_wallet) = new_party(&mut context)?;
    let (recipient_keypair, recipient_funding, mut recipient_wallet) = new_party(&mut context)?;
    register(&context, &recipient_keypair, &recipient_funding)?;

    shield_spl(
        &mut context,
        &sender_keypair,
        &mut sender_wallet,
        &asset,
        10_000,
    )?;
    shield_sol(&mut context, &sender_keypair, &mut sender_wallet, 5_000_000)?;

    let transfer = create_transfer_sync(CreateTransfer {
        rpc: &context.rpc,
        wallet: &sender_wallet,
        authority: &sender_keypair,
        owner_pubkey: sender_funding.pubkey(),
        payer: Address::new_from_array(context.payer.pubkey().to_bytes()),
        recipient_owner: recipient_funding.pubkey(),
        asset: Address::new_from_array(asset.mint.to_bytes()),
        amount: 4_000,
    })?;
    if transfer.recipient.is_public_withdrawal() {
        return Err(anyhow!(
            "recipient is not registered: transfer fell back to a public withdrawal"
        ));
    }

    let wait_tag = transfer.wait_tag;
    let signature = transfer.submit(
        &context.rpc,
        &context.prover,
        &context.payer,
        context.tree,
        None,
    )?;

    // `submit` returns once the transaction is confirmed on-chain; wait for the
    // indexer to catch up before syncing the recipient, or the sync races Photon.
    wait_for_indexed(&context, wait_tag, signature);
    sync_wallet(&mut recipient_wallet, &context.indexer)?;
    let balances = get_private_token_balances(&recipient_wallet)?;

    println!("ok spl transfer signature={signature} recipient_balances={balances:?}");
    Ok(())
}
