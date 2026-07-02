//! Private SPL transfer with the raw transaction path.
//!
//! Selects one SPL note and one SOL fee note, then builds and submits the
//! transfer by hand.

use anyhow::Result;
use rust_client_example::{
    client_transaction, ensure_spl_asset, new_party, register, setup, shield_sol, shield_spl,
    submit_private_transaction,
};
use solana_address::Address;
use zolana_client::{get_private_token_balances, sync_wallet};
use zolana_transaction::{Utxo, SOL_MINT};

fn main() -> Result<()> {
    let mut context = setup()?;
    let asset = ensure_spl_asset(&mut context)?;
    let asset_address = Address::new_from_array(asset.mint.to_bytes());
    let (sender_keypair, _sender_funding, mut sender_wallet) = new_party(&mut context)?;
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

    // Spend one SPL note plus one SOL fee note.
    let mut inputs: Vec<Utxo> = Vec::new();
    for want in [asset_address, SOL_MINT] {
        let utxo = sender_wallet
            .utxos
            .iter()
            .find(|w| !w.spent && w.utxo.asset == want)
            .map(|w| w.utxo.clone())
            .expect("seeded note present");
        inputs.push(utxo);
    }

    let mut tx = client_transaction(&context, &sender_keypair, &inputs)?;
    tx.send(&recipient_keypair.shielded_address()?, asset_address, 4_000)?;
    let signed = tx.sign(&sender_keypair, &sender_wallet.registry)?;
    let wait_tag = recipient_keypair.signing_pubkey().confidential_view_tag()?;

    let signature = submit_private_transaction(&mut context, signed, None, wait_tag)?;

    sync_wallet(&mut recipient_wallet, &context.indexer)?;
    let balances = get_private_token_balances(&recipient_wallet)?;

    println!("ok spl transfer signature={signature} recipient_balances={balances:?}");
    Ok(())
}
