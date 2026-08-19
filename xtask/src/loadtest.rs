//! Load generator for a deployed Zolana environment.
//!
//! Replaces driving the CLI in a shell loop, which could not measure anything
//! useful: it forks a process per transfer, so a meaningful fraction of the
//! observed ~59s per transfer was `zolana` starting up and re-reading its config
//! rather than the protocol doing work. This drives the SDK in-process, holds a
//! wallet across iterations, and records where the time actually goes.
//!
//! The phase breakdown is the point. "Transfers per second" alone cannot tell you
//! whether you are bound by proving, by the indexer, or by your own client, and
//! those have completely different fixes.
//!
//! Threads, not async: the whole SDK transfer path (`create_transfer_sync`,
//! `sign_private_transaction_sync`, `confirm_private_transaction_sync`) is
//! blocking, and wrapping blocking calls in an async runtime would add a layer
//! that measures itself.

use std::{
    fs,
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc, Mutex,
    },
    thread,
    time::{Duration, Instant},
};

use anyhow::{bail, Context, Result};
use solana_keypair::Keypair;
use solana_signer::Signer;
// `Rpc` is in scope for send_transaction, which is a trait method rather than
// an inherent one on SolanaRpc.
use zolana_client::{SolanaRpc, ZolanaClient};
use zolana_keypair::ShieldedKeypair;
use zolana_transaction::{Address, AssetRegistry, LocalWalletAuthority, Wallet};
use zolana_wallet::{
    create_transfer_sync, sign_private_transaction_sync, sync_wallet, TransferParams,
};

/// One completed transfer, broken into the phases that can each be slow for a
/// different reason.
#[derive(Clone, Copy, Default)]
struct Timing {
    sync_ms: u64,
    /// Build + prove. The prover call dominates this.
    prove_ms: u64,
    send_ms: u64,
    /// Confirmation plus waiting for the indexer to catch up.
    confirm_ms: u64,
    total_ms: u64,
}

#[derive(Default)]
struct Stats {
    timings: Vec<Timing>,
    ok: u64,
    failed: u64,
    throttled: u64,
    /// Distinct error messages and how often each occurred.
    ///
    /// Counting failures without recording them makes a run unactionable: "43
    /// failed" says nothing about whether the prover is down, the wallet is
    /// empty, or the indexer is behind.
    errors: std::collections::BTreeMap<String, u64>,
    /// This worker's first sync, before it sent anything.
    ///
    /// Stands in for how much history its wallet already carried. Sync cost
    /// scales with that, and every run leaves hundreds more transfers behind on
    /// the same wallets, so throughput is only comparable between runs at
    /// similar depth. Recorded so a reader can tell rather than assume.
    warmup_sync_ms: Option<u64>,
}

pub struct Options {
    pub rpc_url: String,
    pub indexer_url: String,
    pub prover_url: String,
    pub tree: String,
    pub keypairs: PathBuf,
    pub duration: Duration,
    pub amount: u64,
    pub asset: String,
    /// Where to write the machine-readable summary, if anywhere.
    pub json_out: Option<PathBuf>,
}

impl Options {
    pub fn parse(args: Vec<String>) -> Result<Self> {
        let mut rpc_url = None;
        let mut indexer_url = None;
        let mut prover_url = None;
        let mut tree = None;
        let mut keypairs = None;
        let mut json_out = None;
        let mut duration = 300u64;
        let mut amount = 200_000u64;
        let mut asset = "SOL".to_string();

        let mut iter = args.into_iter();
        while let Some(arg) = iter.next() {
            let mut value = || iter.next().context("missing value");
            match arg.as_str() {
                "--rpc" => rpc_url = Some(value()?),
                "--indexer" => indexer_url = Some(value()?),
                "--prover" => prover_url = Some(value()?),
                "--tree" => tree = Some(value()?),
                "--keypairs" => keypairs = Some(PathBuf::from(value()?)),
                "--duration" => duration = value()?.parse().context("--duration")?,
                "--amount" => amount = value()?.parse().context("--amount")?,
                "--asset" => asset = value()?,
                "--json" => json_out = Some(PathBuf::from(value()?)),
                other => bail!("unknown flag {other}"),
            }
        }

        Ok(Self {
            rpc_url: rpc_url.context("--rpc is required")?,
            indexer_url: indexer_url.context("--indexer is required")?,
            prover_url: prover_url.context("--prover is required")?,
            tree: tree.context("--tree is required")?,
            keypairs: keypairs.context("--keypairs <dir> is required")?,
            json_out,
            duration: Duration::from_secs(duration),
            amount,
            asset,
        })
    }
}

/// Load every `*.json` Solana keypair in a directory, sorted for determinism.
///
/// Plain solana-keygen files, not the CLI's wallet format: on the ed25519 rail
/// the shielded keypair is derived from the funding key, so the funding key is
/// the only secret needed and there is no reason to reimplement the CLI's file
/// parsing here.
fn load_keypairs(dir: &Path) -> Result<Vec<Keypair>> {
    let mut paths: Vec<PathBuf> = fs::read_dir(dir)
        .with_context(|| format!("read {}", dir.display()))?
        .filter_map(|entry| entry.ok().map(|e| e.path()))
        .filter(|p| p.extension().is_some_and(|e| e == "json"))
        .collect();
    paths.sort();

    let mut keypairs = Vec::new();
    for path in &paths {
        let bytes = fs::read(path)?;
        let raw: Vec<u8> = serde_json::from_slice(&bytes)
            .with_context(|| format!("{} is not a keypair array", path.display()))?;
        let array: [u8; 64] = raw
            .try_into()
            .map_err(|_| anyhow::anyhow!("{} is not 64 bytes", path.display()))?;
        keypairs.push(Keypair::try_from(&array[..]).context("bad keypair")?);
    }

    if keypairs.len() < 2 {
        bail!(
            "need at least 2 keypairs in {} (transfers go round a ring)",
            dir.display()
        );
    }
    Ok(keypairs)
}

fn percentile(sorted: &[u64], p: f64) -> u64 {
    if sorted.is_empty() {
        return 0;
    }
    let index = ((sorted.len() as f64 - 1.0) * p).round() as usize;
    sorted[index.min(sorted.len() - 1)]
}

fn report_phase(label: &str, mut values: Vec<u64>) {
    if values.is_empty() {
        println!("  {label:<10} no samples");
        return;
    }
    values.sort_unstable();
    let mean = values.iter().sum::<u64>() as f64 / values.len() as f64;
    println!(
        "  {label:<10} p50 {:>7}ms  p95 {:>7}ms  p99 {:>7}ms  max {:>7}ms  mean {:>8.0}ms",
        percentile(&values, 0.50),
        percentile(&values, 0.95),
        percentile(&values, 0.99),
        values[values.len() - 1],
        mean,
    );
}

/// The percentiles the printed report shows, as data.
fn phase_summary(mut values: Vec<u64>) -> Option<(u64, u64, u64, u64, f64)> {
    if values.is_empty() {
        return None;
    }
    values.sort_unstable();
    let mean = values.iter().sum::<u64>() as f64 / values.len() as f64;
    Some((
        percentile(&values, 0.50),
        percentile(&values, 0.95),
        percentile(&values, 0.99),
        values[values.len() - 1],
        mean,
    ))
}

/// Write the run as JSON so two runs can be diffed instead of eyeballed.
///
/// `warmup_sync_ms` is the point of this: a wallet's sync cost scales with how
/// much history it already has, and every run adds hundreds of transfers to the
/// same wallets. Two runs at different history depths are not comparable, and
/// reporting tps without it invites exactly that mistake -- comparing an early
/// run against a later one and concluding something about the code.
fn write_json(
    path: &Path,
    options: &Options,
    workers: usize,
    stats: &Stats,
    elapsed: f64,
    warmup_sync_ms: &[u64],
) -> Result<()> {
    let phase = |label: &str, values: Vec<u64>| match phase_summary(values) {
        Some((p50, p95, p99, max, mean)) => format!(
            r#""{label}":{{"p50":{p50},"p95":{p95},"p99":{p99},"max":{max},"mean":{mean:.1}}}"#
        ),
        None => format!(r#""{label}":null"#),
    };
    let warmup = phase_summary(warmup_sync_ms.to_vec());
    let body = format!(
        concat!(
            r#"{{"workers":{},"duration_secs":{},"amount":{},"ok":{},"failed":{},"#,
            r#""throttled":{},"elapsed_secs":{:.1},"tps":{:.3},"#,
            r#""warmup_sync_ms_mean":{},"phases":{{{},{},{},{},{}}}}}"#,
            "\n"
        ),
        workers,
        options.duration.as_secs(),
        options.amount,
        stats.ok,
        stats.failed,
        stats.throttled,
        elapsed,
        stats.ok as f64 / elapsed.max(1.0),
        warmup.map_or("null".to_string(), |w| format!("{:.1}", w.4)),
        phase("sync", stats.timings.iter().map(|t| t.sync_ms).collect()),
        phase("prove", stats.timings.iter().map(|t| t.prove_ms).collect()),
        phase("send", stats.timings.iter().map(|t| t.send_ms).collect()),
        phase(
            "confirm",
            stats.timings.iter().map(|t| t.confirm_ms).collect()
        ),
        phase("total", stats.timings.iter().map(|t| t.total_ms).collect()),
    );
    std::fs::write(path, body).with_context(|| format!("write {}", path.display()))?;
    Ok(())
}

pub fn run(options: Options) -> Result<()> {
    let keypairs = load_keypairs(&options.keypairs)?;
    let workers = keypairs.len();
    let tree = Address::new_from_array(
        bs58::decode(&options.tree)
            .into_vec()
            .context("--tree is not base58")?
            .try_into()
            .map_err(|_| anyhow::anyhow!("--tree is not 32 bytes"))?,
    );
    let asset = Address::new_from_array(
        bs58::decode(&options.asset)
            .into_vec()
            .unwrap_or_else(|_| vec![0u8; 32])
            .try_into()
            .unwrap_or([0u8; 32]),
    );

    println!(
        "loadtest: {workers} workers, {}s, {} lamports/transfer",
        options.duration.as_secs(),
        options.amount
    );

    // Recipients form a ring, so value circulates and no wallet drains.
    let recipients: Vec<_> = keypairs.iter().map(|k| k.pubkey()).collect();

    let stop = Arc::new(AtomicBool::new(false));
    let completed = Arc::new(AtomicU64::new(0));
    let stats = Arc::new(Mutex::new(Stats::default()));
    let warmups: Arc<Mutex<Vec<u64>>> = Arc::new(Mutex::new(Vec::new()));
    let started = Instant::now();

    thread::scope(|scope| -> Result<()> {
        // Progress reporter, so a long run is observable while it runs rather
        // than only in the summary.
        {
            let stop = Arc::clone(&stop);
            let completed = Arc::clone(&completed);
            let duration = options.duration;
            scope.spawn(move || {
                let mut last = 0u64;
                // Exits on its own deadline. Waiting only on `stop` deadlocks:
                // `stop` is set after thread::scope joins every thread, and this
                // thread is one of them.
                while !stop.load(Ordering::Relaxed) && started.elapsed() < duration {
                    // Short sleeps so the thread notices the deadline promptly
                    // rather than up to 30s late.
                    for _ in 0..30 {
                        if stop.load(Ordering::Relaxed) || started.elapsed() >= duration {
                            return;
                        }
                        thread::sleep(Duration::from_secs(1));
                    }
                    let now = completed.load(Ordering::Relaxed);
                    let elapsed = started.elapsed().as_secs_f64();
                    println!(
                        "  [{:>5.0}s] {now} ok, {:.2} tps overall, {:.2} tps last 30s",
                        elapsed,
                        now as f64 / elapsed.max(1.0),
                        (now - last) as f64 / 30.0,
                    );
                    last = now;
                }
            });
        }

        for (index, funding) in keypairs.iter().enumerate() {
            let peer = recipients[(index + 1) % workers];
            let options = &options;
            let stats = Arc::clone(&stats);
            let warmups = Arc::clone(&warmups);
            let completed = Arc::clone(&completed);
            let stop = Arc::clone(&stop);

            scope.spawn(move || {
                let mut local = Stats::default();
                if let Err(error) = worker(
                    index, funding, peer, tree, asset, options, &mut local, &completed, &stop,
                    started,
                ) {
                    eprintln!("  w{index} aborted: {error:#}");
                }
                if let Some(warmup) = local.warmup_sync_ms {
                    warmups.lock().expect("warmups poisoned").push(warmup);
                }
                let mut shared = stats.lock().expect("stats poisoned");
                shared.timings.extend(local.timings);
                shared.ok += local.ok;
                shared.failed += local.failed;
                shared.throttled += local.throttled;
                for (message, count) in local.errors {
                    *shared.errors.entry(message).or_insert(0) += count;
                }
            });
        }
        Ok(())
    })?;

    stop.store(true, Ordering::Relaxed);
    let elapsed = started.elapsed();
    let stats = stats.lock().expect("stats poisoned");

    println!("\n─────────────────────────────────────────────────────────────");
    println!(
        "ok {}  failed {}  throttled {}  in {:.0}s",
        stats.ok,
        stats.failed,
        stats.throttled,
        elapsed.as_secs_f64()
    );
    println!(
        "throughput {:.2} transfers/sec ({:.1}/min)",
        stats.ok as f64 / elapsed.as_secs_f64(),
        stats.ok as f64 / elapsed.as_secs_f64() * 60.0
    );
    if !stats.errors.is_empty() {
        println!("\nerrors:");
        let mut ranked: Vec<_> = stats.errors.iter().collect();
        ranked.sort_by(|a, b| b.1.cmp(a.1));
        for (message, count) in ranked.into_iter().take(5) {
            println!("  {count:>5}x  {message}");
        }
    }

    println!("\nphase latency:");
    report_phase("sync", stats.timings.iter().map(|t| t.sync_ms).collect());
    report_phase("prove", stats.timings.iter().map(|t| t.prove_ms).collect());
    report_phase("send", stats.timings.iter().map(|t| t.send_ms).collect());
    report_phase(
        "confirm",
        stats.timings.iter().map(|t| t.confirm_ms).collect(),
    );
    report_phase("total", stats.timings.iter().map(|t| t.total_ms).collect());

    let warmups = warmups.lock().expect("warmups poisoned").clone();
    if let Some((_, _, _, _, mean)) = phase_summary(warmups.clone()) {
        println!("\nwallet depth:");
        println!(
            "  first sync   mean {mean:>8.0}ms   across {} wallets",
            warmups.len()
        );
        println!("  Sync cost scales with a wallet's history, and every run leaves more");
        println!("  behind on these wallets. Compare runs only at similar first-sync cost.");
    }

    if let Some(path) = options.json_out.as_deref() {
        write_json(
            path,
            &options,
            workers,
            &stats,
            elapsed.as_secs_f64(),
            &warmups,
        )?;
        println!("\nwrote {}", path.display());
    }

    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn worker(
    index: usize,
    funding: &Keypair,
    peer: solana_pubkey::Pubkey,
    tree: Address,
    asset: Address,
    options: &Options,
    stats: &mut Stats,
    completed: &AtomicU64,
    stop: &AtomicBool,
    started: Instant,
) -> Result<()> {
    let shielded = ShieldedKeypair::from_keypair(funding)?;
    let mut wallet = Wallet::new(shielded.shielded_address()?, AssetRegistry::default())?;

    // Explicitly insecure: devnet's ALB has no certificate yet, so the indexer
    // and prover are plain http. That is a real exposure -- the wallet's UTXO
    // set and every proof witness cross the network in the clear -- and it is
    // spelled out here rather than defaulted, so it disappears the moment the
    // certificate is issued.
    let client = ZolanaClient::from_urls_allowing_insecure_http(
        SolanaRpc::new(options.rpc_url.clone()),
        options.indexer_url.clone(),
        options.prover_url.clone(),
        tree,
    );
    // LocalWalletAuthority is the canonical implementation of the signing and
    // viewing surface the sync and transfer paths need. The CLI wraps it in its
    // own type only to add file loading; there is nothing to add here.
    let authority = LocalWalletAuthority::new(
        Address::new_from_array(funding.pubkey().to_bytes()),
        &shielded,
    );

    let mut backoff = Duration::from_secs(1);

    while started.elapsed() < options.duration && !stop.load(Ordering::Relaxed) {
        let iteration = Instant::now();
        let mut timing = Timing::default();

        // The wallet is held across iterations, but each transfer spends a note
        // and creates change, so it still has to re-sync to see the change note.
        // This phase is the one that grows with the wallet's note count.
        let mark = Instant::now();
        if let Err(error) = sync_wallet(&mut wallet, &authority, &client) {
            classify(&error.to_string(), stats, &mut backoff);
            continue;
        }
        timing.sync_ms = mark.elapsed().as_millis() as u64;
        if stats.warmup_sync_ms.is_none() {
            stats.warmup_sync_ms = Some(timing.sync_ms);
        }

        let mark = Instant::now();
        let transfer = match create_transfer_sync(TransferParams {
            rpc: &client,
            wallet: &wallet,
            payer: Address::new_from_array(funding.pubkey().to_bytes()),
            recipient: peer,
            asset,
            amount: options.amount,
        })
        .and_then(|transfer| {
            sign_private_transaction_sync(
                transfer.transaction,
                &wallet,
                &authority,
                &client,
                funding,
            )
        }) {
            Ok(signed) => signed,
            Err(error) => {
                classify(&error.to_string(), stats, &mut backoff);
                continue;
            }
        };
        timing.prove_ms = mark.elapsed().as_millis() as u64;

        let mark = Instant::now();
        let signature = match client.submit_private_transaction_sync(&transfer) {
            Ok(signature) => signature,
            Err(error) => {
                classify(&error.to_string(), stats, &mut backoff);
                continue;
            }
        };
        timing.send_ms = mark.elapsed().as_millis() as u64;

        let mark = Instant::now();
        if let Err(error) = client.confirm_private_transaction_sync(signature) {
            classify(&error.to_string(), stats, &mut backoff);
            continue;
        }
        timing.confirm_ms = mark.elapsed().as_millis() as u64;

        timing.total_ms = iteration.elapsed().as_millis() as u64;
        stats.timings.push(timing);
        stats.ok += 1;
        completed.fetch_add(1, Ordering::Relaxed);
        backoff = Duration::from_secs(1);

        let _ = index;
    }
    Ok(())
}

/// Separate upstream throttling from real failures, and back off on the former.
///
/// A load generator without backoff measures the rate limiter rather than the
/// system under test: an earlier shell-driven run lost 101 of 220 transfers to
/// Helius 403s and reported it as protocol failure.
fn classify(message: &str, stats: &mut Stats, backoff: &mut Duration) {
    // Truncated: these carry request ids and addresses that would make every
    // occurrence look distinct and defeat the grouping.
    let key: String = message.chars().take(160).collect();
    *stats.errors.entry(key).or_insert(0) += 1;

    let lowered = message.to_ascii_lowercase();
    if lowered.contains("403") || lowered.contains("429") || lowered.contains("rate") {
        stats.throttled += 1;
        thread::sleep(*backoff);
        *backoff = (*backoff * 2).min(Duration::from_secs(30));
    } else {
        stats.failed += 1;
        thread::sleep(Duration::from_millis(250));
    }
}
