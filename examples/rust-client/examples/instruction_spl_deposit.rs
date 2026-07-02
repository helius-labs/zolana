//! Shield an SPL token with the raw deposit instruction.
//!
//! Same SPL deposit as `action_spl_deposit`, sent at the instruction level via
//! `Deposit::instruction` + `create_and_send_transaction`.

use anyhow::Result;
use rust_client_example::{ensure_spl_asset, new_party, setup};
use solana_address::Address;
use solana_signer::Signer;
use zolana_client::{create_deposit, get_private_token_balances, sync_wallet, CreateDeposit, Rpc};
use zolana_test_utils::{spl::mint_to, test_validator_asserts::wait_for_indexed_transaction};

fn main() -> Result<()> {
    let mut context = setup()?;
    let asset = ensure_spl_asset(&mut context)?;
    let (sender_keypair, _sender_funding, mut sender_wallet) = new_party(&mut context)?;

    let payer = context.payer.insecure_clone();
    mint_to(&context.rpc, &payer, &asset.mint, &asset.user_token, 10_000)?;

    let prepared = create_deposit(CreateDeposit {
        recipient: &sender_keypair.shielded_address()?,
        asset: Address::new_from_array(asset.mint.to_bytes()),
        amount: 10_000,
        spl_token_account: Some(asset.user_token),
        memo: None,
    })?;
    let ix = prepared.instruction(context.tree, payer.pubkey());
    let payer_address = Address::new_from_array(payer.pubkey().to_bytes());
    let signature = context
        .rpc
        .create_and_send_transaction(&[ix], payer_address, &[&payer])?;

    // A transaction confirming on-chain does not mean Photon has indexed it yet;
    // wait for the deposit's view tag before syncing, or the sync races the
    // indexer and reads an empty balance.
    wait_for_indexed_transaction(&context.indexer, prepared.view_tag(), signature);
    sync_wallet(&mut sender_wallet, &context.indexer)?;
    let balances = get_private_token_balances(&sender_wallet)?;

    println!("ok spl deposit signature={signature} balances={balances:?}");
    Ok(())
}
