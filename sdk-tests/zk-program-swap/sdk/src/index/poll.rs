use std::time::{Duration, Instant};

use anyhow::{bail, Result};
use zolana_client::{sync_wallet, Rpc};
use zolana_keypair::ShieldedKeypair;
use zolana_transaction::{LocalWalletAuthority, ShieldedTransaction, Wallet};

use crate::err;

const INDEX_POLL: Duration = Duration::from_millis(500);

pub(crate) fn index_until<I: Rpc, T>(
    wallet: &mut Wallet,
    keypair: &ShieldedKeypair,
    indexer: &I,
    timeout: Duration,
    what: &str,
    mut collect: impl FnMut(&Wallet) -> Result<Vec<T>>,
) -> Result<Vec<T>> {
    let solana_pubkey = keypair
        .shielded_address()
        .and_then(|address| address.solana_address())
        .map_err(err)?;
    let authority = LocalWalletAuthority::new(solana_pubkey, keypair);
    let deadline = Instant::now() + timeout;
    loop {
        sync_wallet(wallet, &authority, indexer).map_err(err)?;
        let found = collect(wallet)?;
        if !found.is_empty() {
            return Ok(found);
        }
        if Instant::now() >= deadline {
            bail!("timed out discovering {what}");
        }
        std::thread::sleep(INDEX_POLL);
    }
}

pub(crate) fn collect_tagged<I: Rpc, T>(
    wallet: &Wallet,
    indexer: &I,
    mut scan: impl FnMut(&ShieldedTransaction) -> Result<Option<T>>,
) -> Result<Vec<T>> {
    let owner_tag = wallet
        .identity
        .signing_pubkey
        .confidential_view_tag()
        .map_err(err)?;
    let mut found = Vec::new();
    let mut cursor = None;
    loop {
        let page = indexer
            .get_shielded_transactions_by_tags(vec![owner_tag], cursor, None)
            .map_err(err)?;
        for tx in &page.transactions {
            if let Some(item) = scan(tx)? {
                found.push(item);
            }
        }
        let Some(next) = page.next_cursor else {
            return Ok(found);
        };
        cursor = Some(next);
    }
}
