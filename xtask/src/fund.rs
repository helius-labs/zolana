//! Top up the shielded balances of a directory of load-test wallets.
//!
//! The load generator spends shielded value; when a wallet runs out it fails
//! with `insufficient balance for asset` and the run measures depletion rather
//! than capacity. One 220-worker run ended with 209 such failures.
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
    path::PathBuf,
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

use crate::loadtest::load_keypairs;

pub struct Options {
    pub rpc_url: String,
    pub tree: String,
    /// Directory of `solana-keygen` keypairs — the same one `loadtest` takes.
    pub keypairs: PathBuf,
    /// Funder: signs and pays for every deposit.
    pub funder: PathBuf,
    /// Lamports to deposit into each wallet.
    pub amount: u64,
    /// Deposits in flight at once.
    pub concurrency: usize,
}

impl Options {
    pub fn parse(args: Vec<String>) -> Result<Self> {
        let mut rpc_url = None;
        let mut tree = None;
        let mut keypairs = None;
        let mut funder = None;
        let mut amount = 60_000_000u64;
        let mut concurrency = 16usize;

        let mut iter = args.into_iter();
        while let Some(arg) = iter.next() {
            let mut value = || iter.next().context("missing value");
            match arg.as_str() {
                "--rpc" => rpc_url = Some(value()?),
                "--tree" => tree = Some(value()?),
                "--keypairs" => keypairs = Some(PathBuf::from(value()?)),
                "--funder" => funder = Some(PathBuf::from(value()?)),
                "--amount" => amount = value()?.parse().context("--amount")?,
                "--concurrency" => concurrency = value()?.parse().context("--concurrency")?,
                other => bail!("unknown flag {other}"),
            }
        }

        Ok(Self {
            rpc_url: rpc_url.context("--rpc is required")?,
            tree: tree.context("--tree is required")?,
            keypairs: keypairs.context("--keypairs <dir> is required")?,
            funder: funder.context("--funder <keypair.json> is required")?,
            amount,
            concurrency: concurrency.max(1),
        })
    }
}

fn read_keypair(path: &PathBuf) -> Result<Keypair> {
    let bytes = std::fs::read(path).with_context(|| format!("read {}", path.display()))?;
    let raw: Vec<u8> = serde_json::from_slice(&bytes)
        .with_context(|| format!("{} is not a keypair array", path.display()))?;
    let array: [u8; 64] = raw
        .try_into()
        .map_err(|_| anyhow::anyhow!("{} is not 64 bytes", path.display()))?;
    Keypair::try_from(&array[..]).context("bad funder keypair")
}

pub fn run(options: Options) -> Result<()> {
    let funder = read_keypair(&options.funder)?;
    let wallets = load_keypairs(&options.keypairs)?;
    let tree: Address = options.tree.parse().context("--tree is not an address")?;
    let asset = Address::default();

    let rpc = SolanaRpc::new(options.rpc_url.clone());
    let funder_address = Address::new_from_array(funder.pubkey().to_bytes());
    let balance = rpc.get_balance(funder_address)?;
    let required = options.amount.saturating_mul(wallets.len() as u64);
    println!(
        "funding {} wallets with {} lamports each ({:.3} SOL total)\nfunder {} holds {:.3} SOL",
        wallets.len(),
        options.amount,
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
        for _ in 0..options.concurrency.min(wallets.len()) {
            scope.spawn(|| {
                // Each worker holds its own RPC client; they are cheap and not
                // shared state.
                let rpc = SolanaRpc::new(options.rpc_url.clone());
                loop {
                    let index = next.fetch_add(1, Ordering::Relaxed);
                    let Some(wallet) = wallets.get(index) else {
                        return;
                    };
                    match fund_one(&rpc, &funder, wallet, tree, asset, options.amount) {
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
    let shielded = ShieldedKeypair::from_solana_keypair(wallet)?;
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
