//! Unshield an SPL token with the ergonomic `create_withdrawal_sync` action.
//!
//! The withdrawal settles into the recipient's associated token account, which
//! must exist first. Alice is seeded with an SPL note and a SOL fee note.

use anyhow::Result;
use rust_client_example::{
    ensure_associated_token_account, ensure_spl_asset, new_party, setup, shield_sol, shield_spl,
    wait_for_indexed,
};
use solana_address::Address;
use solana_keypair::Keypair;
use solana_signer::Signer;
use zolana_client::{create_withdrawal_sync, sync_wallet, CreateWithdrawal};

fn main() -> Result<()> {
    let mut context = setup()?;
    let asset = ensure_spl_asset(&mut context)?;
    let (sender_keypair, sender_funding, mut sender_wallet) = new_party(&mut context)?;

    shield_spl(
        &mut context,
        &sender_keypair,
        &mut sender_wallet,
        &asset,
        10_000,
    )?;
    shield_sol(&mut context, &sender_keypair, &mut sender_wallet, 5_000_000)?;

    let recipient = Keypair::new();
    context.rpc.airdrop(&recipient.pubkey(), 1_000_000)?;
    let ata = ensure_associated_token_account(&context, &recipient.pubkey(), &asset.mint)?;

    let withdrawal = create_withdrawal_sync(CreateWithdrawal {
        wallet: &sender_wallet,
        authority: &sender_keypair,
        owner_pubkey: sender_funding.pubkey(),
        payer: Address::new_from_array(context.payer.pubkey().to_bytes()),
        recipient: recipient.pubkey(),
        asset: Address::new_from_array(asset.mint.to_bytes()),
        amount: 4_000,
    })?;

    let wait_tag = withdrawal.wait_tag;
    let signature = withdrawal.submit(
        &context.rpc,
        &context.prover,
        &context.payer,
        context.tree,
        None,
    )?;

    wait_for_indexed(&context, wait_tag, signature);
    sync_wallet(&mut sender_wallet, &context.indexer)?;

    println!("ok spl withdraw signature={signature} recipient_ata={ata}");
    Ok(())
}
