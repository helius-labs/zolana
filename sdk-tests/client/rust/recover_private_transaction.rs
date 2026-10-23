//! Resume an application checkpoint without signing, proving or sending again.
use std::{env, str::FromStr};

use anyhow::{Context, Result};
use solana_signature::Signature;
use zolana_client::{ClientError, SolanaRpc, ZolanaClient};

fn main() -> Result<()> {
    let mut args = env::args().skip(1);
    let signature =
        Signature::from_str(&args.next().context(
            "usage: recover_private_transaction <signature> [last-valid-block-height]",
        )?)?;
    let last_valid_block_height = args
        .next()
        .map(|height| height.parse::<u64>())
        .transpose()?;
    let rpc_url =
        env::var("ZOLANA_LOCALNET_URL").unwrap_or_else(|_| "http://127.0.0.1:8899".into());
    let indexer_url =
        env::var("ZOLANA_INDEXER_URL").unwrap_or_else(|_| "http://127.0.0.1:8784".into());
    // Recovery does not contact the prover; the constructor still takes its URL.
    let client = ZolanaClient::from_urls(
        SolanaRpc::new(rpc_url),
        indexer_url,
        "http://127.0.0.1:3001",
    )?;
    match client.wait_for_private_transaction_sync(signature, last_valid_block_height) {
        Ok(()) => println!("Indexed. Sync and persist the wallet before clearing the checkpoint."),
        Err(ClientError::TransactionExpired { .. }) => {
            println!("Expired without private effects. Sync before building a replacement.");
        }
        Err(ClientError::TransactionNotIndexed { .. }) => {
            println!("Confirmed, waiting for indexing. Keep the checkpoint and wait again.");
        }
        Err(ClientError::TransactionOutcomeUnknown { .. }) => {
            println!("Unknown. Keep the checkpoint and input reservations; wait again.");
        }
        Err(error) => return Err(error.into()),
    }
    Ok(())
}
