use std::time::{Duration, Instant};

use anyhow::{bail, Result};
use zolana_client::Rpc;
use zolana_keypair::ShieldedKeypair;
use zolana_transaction::ShieldedTransaction;

use crate::err;

const INDEX_POLL: Duration = Duration::from_millis(500);

pub(crate) fn index_until<T>(
    timeout: Duration,
    what: &str,
    mut collect: impl FnMut() -> Result<Vec<T>>,
) -> Result<Vec<T>> {
    let deadline = Instant::now() + timeout;
    loop {
        let found = collect()?;
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
    keypair: &ShieldedKeypair,
    indexer: &I,
    mut scan: impl FnMut(&ShieldedTransaction) -> Result<Option<T>>,
) -> Result<Vec<T>> {
    let owner_tag = keypair
        .signing_pubkey()
        .confidential_view_tag()
        .map_err(err)?;
    let mut found = Vec::new();
    let mut cursor = None;
    loop {
        let page = indexer
            .get_shielded_transactions_by_tags(vec![owner_tag], cursor, None, None)
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
