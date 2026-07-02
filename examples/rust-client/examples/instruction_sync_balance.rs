//! Query the indexer for a wallet's encrypted UTXOs by view tag.
//!
//! The raw layer under `sync_wallet`: build the wallet's view tags, then call
//! `get_encrypted_utxos_by_tags` to fetch the ciphertext matches the indexer
//! holds for those tags. `sync_wallet` wraps this and the HPKE decryption that
//! turns the matches into spendable notes.

use anyhow::Result;
use rust_client_example::{new_party, setup, shield_sol};
use zolana_client::Rpc;

fn main() -> Result<()> {
    let mut context = setup()?;
    let (sender_keypair, _sender_funding, mut sender_wallet) = new_party(&mut context)?;

    shield_sol(&mut context, &sender_keypair, &mut sender_wallet, 5_000_000)?;
    shield_sol(&mut context, &sender_keypair, &mut sender_wallet, 2_000_000)?;

    // A deposit is tagged with the recipient's bootstrap view tag.
    let tags = vec![sender_keypair.recipient_bootstrap_view_tag()];
    let response = context
        .indexer
        .get_encrypted_utxos_by_tags(tags, None, None)?;

    println!("ok query encrypted_matches={}", response.matches.len());
    Ok(())
}
