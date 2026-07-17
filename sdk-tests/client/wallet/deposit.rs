use anyhow::Result;
use client_example::{setup, SetupContext, DEPOSIT_AMOUNT};
use solana_signer::Signer;
use zolana_client::Rpc;
use zolana_interface::instruction::Deposit;
use zolana_keypair::random_blinding;
use zolana_transaction::SOL_MINT;

fn main() -> Result<()> {
    let SetupContext {
        rpc,
        indexer,
        tree,
        mut alice,
        ..
    } = setup()?;

    let solana_keypair = alice.funding()?;
    let recipient = alice.address()?;

    let instruction = Deposit {
        tree,
        depositor: solana_keypair.pubkey(),
        spl: None,
        view_tag: recipient.viewing_pubkey.x(),
        owner: recipient.owner_hash()?,
        blinding: random_blinding(),
        public_amount: Some(DEPOSIT_AMOUNT),
        utxo_data: None,
        memo: None,
    }
    .instruction();

    let signature = rpc.create_and_send_transaction(
        &[instruction],
        solana_keypair.pubkey(),
        &[&solana_keypair],
    )?;

    alice.sync(&indexer)?;

    let balance = alice.balance(SOL_MINT, None)?.amount;
    println!("deposit shielded_balance={balance} tx={signature}");
    Ok(())
}
