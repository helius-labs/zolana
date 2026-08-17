//! Top up the shielded balances of the load-test wallets.
//!
//! The load generator spends shielded value; a wallet that runs out fails with
//! `insufficient balance for asset`, and the run then measures depletion rather
//! than capacity.
//!
//! One funder pays for everything. A deposit names its recipient by shielded
//! address and needs no shared secret — see `DepositParams` — so the funder both
//! signs and sources every deposit, and the wallets themselves are never
//! touched. That removes the step this used to need: a SOL transfer to each
//! wallet so it could afford to deposit to itself.
//!
//! It also removes the second wallet format. The load generator reads plain
//! `solana-keygen` keypairs and derives the shielded keypair from the funding
//! key, so this reads exactly the same directory rather than a parallel set of
//! CLI wallet files holding the same secrets.

use std::{
    path::Path,
    sync::atomic::{AtomicU64, AtomicUsize, Ordering},
    thread,
    time::Instant,
};

use anyhow::{bail, Context, Result};
use solana_keypair::Keypair;
use solana_signer::Signer;
use zolana_client::{Rpc, SolanaRpc};
use zolana_keypair::ShieldedKeypair;
use zolana_transaction::Address;
use zolana_wallet::{create_deposit, DepositParams};

/// Deposits in flight at once.
const CONCURRENCY: usize = 16;

fn read_keypair(path: &Path) -> Result<Keypair> {
    let bytes = std::fs::read(path).with_context(|| format!("read {}", path.display()))?;
    let raw: Vec<u8> = serde_json::from_slice(&bytes)
        .with_context(|| format!("{} is not a keypair array", path.display()))?;
    let array: [u8; 64] = raw
        .try_into()
        .map_err(|_| anyhow::anyhow!("{} is not 64 bytes", path.display()))?;
    Keypair::try_from(&array[..]).context("bad funder keypair")
}

/// Bring every wallet up by `amount`, paid for by one funder.
///
/// Runs as part of `loadtest` rather than as its own command: a run against
/// empty wallets still produces a throughput number, and that number measures
/// how fast the pool can refuse a transfer.
pub fn top_up(
    rpc_url: &str,
    tree: &str,
    wallets: &[Keypair],
    funder_path: &Path,
    amount: u64,
) -> Result<()> {
    let funder = read_keypair(funder_path)?;
    let tree: Address = tree.parse().context("--tree is not an address")?;
    let asset = Address::default();

    let rpc = SolanaRpc::new(rpc_url.to_string());
    let funder_address = Address::new_from_array(funder.pubkey().to_bytes());
    let balance = rpc.get_balance(funder_address)?;
    let required = amount.saturating_mul(wallets.len() as u64);
    println!(
        "funding {} wallets with {} lamports each ({:.3} SOL total)\nfunder {} holds {:.3} SOL",
        wallets.len(),
        amount,
        required as f64 / 1e9,
        funder.pubkey(),
        balance as f64 / 1e9,
    );
    if balance < required {
        bail!(
            "funder holds {:.3} SOL but {:.3} SOL is needed; airdrop first or lower --amount",
            balance as f64 / 1e9,
            required as f64 / 1e9,
        );
    }

    let next = AtomicUsize::new(0);
    let funded = AtomicU64::new(0);
    let failed = AtomicU64::new(0);
    let started = Instant::now();

    thread::scope(|scope| {
        for _ in 0..CONCURRENCY.min(wallets.len()) {
            scope.spawn(|| {
                // Each worker holds its own RPC client; they are cheap and not
                // shared state.
                let rpc = SolanaRpc::new(rpc_url.to_string());
                loop {
                    let index = next.fetch_add(1, Ordering::Relaxed);
                    let Some(wallet) = wallets.get(index) else {
                        return;
                    };
                    match fund_one(&rpc, &funder, wallet, tree, asset, amount) {
                        Ok(()) => {
                            let done = funded.fetch_add(1, Ordering::Relaxed) + 1;
                            if done.is_multiple_of(25) {
                                println!(
                                    "  {done} funded ({:.0}s)",
                                    started.elapsed().as_secs_f64()
                                );
                            }
                        }
                        Err(error) => {
                            failed.fetch_add(1, Ordering::Relaxed);
                            eprintln!("  wallet {index} failed: {error:#}");
                        }
                    }
                }
            });
        }
    });

    let funded = funded.into_inner();
    let failed = failed.into_inner();
    println!(
        "\nfunded {funded}, failed {failed}, in {:.0}s",
        started.elapsed().as_secs_f64()
    );
    if funded == 0 {
        bail!("no wallet was funded");
    }
    Ok(())
}

/// Deposit into one wallet's shielded address, paid for by the funder.
fn fund_one(
    rpc: &SolanaRpc,
    funder: &Keypair,
    wallet: &Keypair,
    tree: Address,
    asset: Address,
    amount: u64,
) -> Result<()> {
    let shielded = ShieldedKeypair::from_keypair(wallet)?;
    let recipient = shielded.shielded_address()?;
    let built = create_deposit(DepositParams {
        recipient: &recipient,
        asset,
        amount,
        spl_token_account: None,
        spl_token_program: None,
        memo: None,
    })?;
    // Funder is both payer and depositor: the deposited SOL comes from it, so
    // the recipient needs no balance of its own.
    let tree = solana_pubkey::Pubkey::new_from_array(tree.to_bytes());
    built.send(rpc, funder, tree, funder)?;
    Ok(())
}
