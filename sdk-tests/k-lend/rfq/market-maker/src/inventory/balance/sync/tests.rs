use std::{
    io::{Read, Write},
    net::TcpListener,
    sync::atomic::{AtomicUsize, Ordering},
};

use anyhow::{anyhow, Result};

use super::*;
use zolana_keypair::{P256Pubkey, ShieldedAddress, ViewingKey};
use zolana_transaction::{
    keys::{DecryptRequest, DeriveRequest, TransactionKeyRequest},
    Data, Mint, TransactionError, Utxo, WalletUtxo,
};

struct CountingKeys {
    keys: Arc<ShieldedKeypair>,
    derived: AtomicUsize,
}

impl ShieldedKeys for CountingKeys {
    fn address(&self) -> Result<ShieldedAddress, TransactionError> {
        self.keys.address()
    }
    fn viewing_public_keys(&self) -> Vec<P256Pubkey> {
        self.keys.viewing_public_keys()
    }
    fn decrypt(&self, requests: &[DecryptRequest<'_>]) -> Result<Vec<Vec<u8>>, TransactionError> {
        self.keys.decrypt(requests)
    }
    fn derive(&self, requests: &[DeriveRequest]) -> Result<Vec<[u8; 32]>, TransactionError> {
        self.derived.fetch_add(requests.len(), Ordering::Relaxed);
        self.keys.derive(requests)
    }
    fn transaction_keys(
        &self,
        requests: &[TransactionKeyRequest],
    ) -> Result<Vec<ViewingKey>, TransactionError> {
        self.keys.transaction_keys(requests)
    }
}

const PAGE: &str = r#"{"jsonrpc":"2.0","id":"test-account","result":{"context":{"blockTime":0,"slot":1},"transactions":[],"nextCursor":"AQID"}}"#;
const LAST: &str = r#"{"jsonrpc":"2.0","id":"test-account","result":{"context":{"blockTime":0,"slot":1},"transactions":[],"scannedThrough":"BAUG"}}"#;
const DEPOSITS: &str = r#"{"jsonrpc":"2.0","id":"test-account","result":{"context":{"blockTime":0,"slot":1},"matches":[],"scannedThrough":"BwgJ"}}"#;
const FAILURE: &str = r#"{"jsonrpc":"2.0","id":"test-account","error":{"code":-32603,"message":"injected page failure"}}"#;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn failed_pages_and_deposits_preserve_both_cursors_for_retry() -> Result<()> {
    for failed_batch in [vec![PAGE, FAILURE], vec![PAGE, LAST, FAILURE]] {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let address = listener.local_addr()?;
        let replies: Vec<_> = failed_batch
            .into_iter()
            .chain([PAGE, LAST, DEPOSITS])
            .collect();
        let server = std::thread::spawn(move || -> std::io::Result<()> {
            for reply in replies {
                let (mut connection, _) = listener.accept()?;
                connection.set_read_timeout(Some(Duration::from_secs(5)))?;
                let mut request = [0; 8192];
                if connection.read(&mut request)? == 0 {
                    return Err(std::io::Error::other("empty request"));
                }
                write!(connection, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}", reply.len(), reply)?;
            }
            Ok(())
        });
        let mut account = AccountSync::new(
            Arc::new(ShieldedKeypair::new_ed25519()?),
            Arc::new(AsyncZolanaIndexer::new(format!("http://{address}"))),
            Arc::new(Reservations::default()),
            Arc::new(RwLock::new(AssetRegistry::default())),
        )?;
        assert!(account.run_once().await.is_err());
        assert_eq!(
            (
                account.transactions_cursor.clone(),
                account.deposits_cursor.clone(),
                account.decrypted.clone()
            ),
            (None, None, DecryptionResult::default())
        );
        assert_eq!(account.run_once().await?, SyncOutcome::default());
        assert_eq!(
            (account.transactions_cursor, account.deposits_cursor),
            (Some(vec![4, 5, 6]), Some(vec![7, 8, 9]))
        );
        server.join().map_err(|_| anyhow!("mock server failed"))??;
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unchanged_notes_are_not_rederived_and_spend_cursors_survive_ticks() -> Result<()> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let address = listener.local_addr()?;
    let server = std::thread::spawn(move || -> std::io::Result<Vec<String>> {
        let mut requests = Vec::new();
        for reply in [LAST, DEPOSITS, LAST, LAST, DEPOSITS, LAST, LAST, DEPOSITS] {
            let (mut connection, _) = listener.accept()?;
            connection.set_read_timeout(Some(Duration::from_secs(5)))?;
            let mut request = Vec::new();
            loop {
                let mut part = [0; 8192];
                let read = connection.read(&mut part)?;
                if read == 0 {
                    break;
                }
                request.extend_from_slice(
                    part.get(..read)
                        .ok_or_else(|| std::io::Error::other("invalid read"))?,
                );
                if let Some(header_end) =
                    request.windows(4).position(|window| window == b"\r\n\r\n")
                {
                    let headers = String::from_utf8_lossy(
                        request
                            .get(..header_end)
                            .ok_or_else(|| std::io::Error::other("missing headers"))?,
                    );
                    let length = headers
                        .lines()
                        .find_map(|line| {
                            line.split_once(':')
                                .filter(|(key, _)| key.eq_ignore_ascii_case("content-length"))
                                .and_then(|(_, value)| value.trim().parse::<usize>().ok())
                        })
                        .unwrap_or(0);
                    if request.len() >= header_end + 4 + length {
                        break;
                    }
                }
            }
            requests.push(String::from_utf8_lossy(&request).into_owned());
            write!(connection, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}", reply.len(), reply)?;
        }
        Ok(requests)
    });
    let keys = Arc::new(ShieldedKeypair::new_ed25519()?);
    let own = keys.shielded_address()?;
    let utxo = Utxo {
        owner: own.signing_pubkey,
        asset: Mint::SOL,
        amount: 100,
        blinding: [0; 32],
        ring_program_id: None,
        data: Data::default(),
    };
    let hash = utxo.hash(&own.nullifier_pubkey, &[0; 32], &[0; 32], 0)?;
    let nullifier = keys
        .derive(&[DeriveRequest::Nullifier {
            utxo_hash: hash,
            blinding: utxo.blinding,
        }])?
        .first()
        .copied()
        .ok_or_else(|| anyhow!("no nullifier"))?;
    let wallet = WalletUtxo {
        utxo,
        nullifier_pubkey: own.nullifier_pubkey,
        utxo_hash: hash,
        nullifier,
        data_hash: None,
        ring_data_hash: None,
        tree_id: 0,
        leaf_index: 0,
        slot: 0,
        tx_signature: solana_signature::Signature::default(),
        slot_index: 0,
    };
    let reservations = Arc::new(Reservations::default());
    reservations.insert(TrackedUtxo {
        wallet: wallet.clone(),
        leaf_index: Some(0),
    });
    let mut account = AccountSync::new(
        keys.clone(),
        Arc::new(AsyncZolanaIndexer::new(format!("http://{address}"))),
        reservations.clone(),
        Arc::new(RwLock::new(AssetRegistry::default())),
    )?;
    account.decrypted.utxos.push(wallet);
    let counting = Arc::new(CountingKeys {
        keys,
        derived: AtomicUsize::new(0),
    });
    account.keys = counting.clone();
    assert_eq!(account.run_once().await?, SyncOutcome::default());
    assert_eq!(account.run_once().await?, SyncOutcome::default());
    assert_eq!(counting.derived.load(Ordering::Relaxed), 0);
    assert_eq!(
        account.spend_cursors.get(&nullifier),
        Some(&Some(vec![4, 5, 6]))
    );
    reservations.remove_spent_nullifiers([nullifier]);
    account.run_once().await?;
    assert!(account.decrypted.utxos.is_empty());
    assert!(account.decrypted.spent_nullifiers.is_empty());
    assert!(account.spend_cursors.is_empty());
    let requests = server.join().map_err(|_| anyhow!("mock server failed"))??;
    assert!(requests
        .get(5)
        .is_some_and(|request| request.contains("BAUG")));
    Ok(())
}
