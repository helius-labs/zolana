//! Unshield an SPL token with the raw transaction path.
//!
//! Builds the SPL withdrawal target by hand: `WithdrawalTarget::Spl` for the
//! client transaction and the matching `TransactWithdrawal::Spl` (vault, CPI
//! authority, recipient ATA, token program) for the instruction.

use anyhow::Result;
use rust_client_example::{
    client_transaction, ensure_associated_token_account, ensure_spl_asset, new_party, setup,
    shield_sol, shield_spl, submit_private_transaction,
};
use solana_address::Address;
use solana_keypair::Keypair;
use solana_signer::Signer;
use zolana_client::{sync_wallet, WithdrawalTarget};
use zolana_interface::{
    instruction::{TransactSplWithdrawal, TransactWithdrawal},
    pda, SPL_TOKEN_PROGRAM_ID,
};
use zolana_transaction::{Utxo, SOL_MINT};

fn main() -> Result<()> {
    let mut context = setup()?;
    let asset = ensure_spl_asset(&mut context)?;
    let asset_address = Address::new_from_array(asset.mint.to_bytes());
    let (sender_keypair, _sender_funding, mut sender_wallet) = new_party(&mut context)?;

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
    let vault = pda::spl_asset_vault(&asset.mint);

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
    tx.withdraw(
        asset_address,
        4_000,
        WithdrawalTarget::Spl {
            user_spl_token: Address::new_from_array(ata.to_bytes()),
            spl_token_interface: Address::new_from_array(vault.to_bytes()),
        },
    )?;
    let signed = tx.sign(&sender_keypair, &sender_wallet.registry)?;
    let wait_tag = sender_keypair.signing_pubkey().confidential_view_tag()?;

    let withdrawal = TransactWithdrawal::Spl(TransactSplWithdrawal {
        cpi_authority: Some(pda::shielded_pool_cpi_authority()),
        vault,
        recipient: recipient.pubkey(),
        user_token_account: ata,
        token_program: solana_pubkey::Pubkey::new_from_array(SPL_TOKEN_PROGRAM_ID),
    });
    let signature = submit_private_transaction(&mut context, signed, Some(withdrawal), wait_tag)?;

    sync_wallet(&mut sender_wallet, &context.indexer)?;

    println!("ok spl withdraw signature={signature} recipient_ata={ata}");
    Ok(())
}
