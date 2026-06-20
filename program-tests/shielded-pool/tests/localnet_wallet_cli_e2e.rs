//! Wallet CLI commands against a local validator + Photon indexer.
//!
//! Run with `just test-localnet-e2e-photon`.

use std::env;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, bail, Context, Result};
use serde::Deserialize;
use serial_test::serial;

#[path = "common/transact.rs"]
#[allow(dead_code)]
mod transact_common;

use transact_common::start_prover;

const RPC_URL_ENV: &str = "ZOLANA_LOCALNET_URL";
const INDEXER_URL_ENV: &str = "ZOLANA_INDEXER_URL";
const DEFAULT_RPC_URL: &str = "http://127.0.0.1:8899";
const DEFAULT_INDEXER_URL: &str = "http://127.0.0.1:8784";
const DEFAULT_PROVER_URL: &str = "http://127.0.0.1:3001";

#[derive(Deserialize)]
struct WalletFile {
    funding_pubkey: String,
}

fn restart_localnet() {
    let script = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../tools/restart-localnet.sh"
    );
    let status = Command::new("bash")
        .arg(script)
        .status()
        .expect("run restart-localnet.sh");
    assert!(status.success(), "restart-localnet.sh failed");
}

fn cli_bin() -> PathBuf {
    std::env::var("ZOLANA_CLI_BIN")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            PathBuf::from(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../target/debug/zolana"
            ))
        })
}

fn run_cli(args: &[&str]) -> Result<String> {
    let output = Command::new(cli_bin())
        .args(args)
        .output()
        .with_context(|| format!("spawn zolana {}", args.join(" ")))?;
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    if !output.status.success() {
        bail!(
            "zolana {} failed (status={}):\nstdout:{stdout}\nstderr:{stderr}",
            args.join(" "),
            output.status
        );
    }
    Ok(stdout)
}

fn wallet_init(path: &Path) -> Result<()> {
    run_cli(&["wallet", "init", "--path", &path.display().to_string()])?;
    Ok(())
}

fn funding_pubkey(path: &Path) -> Result<String> {
    let file: WalletFile =
        serde_json::from_slice(&std::fs::read(path).with_context(|| path.display().to_string())?)?;
    Ok(file.funding_pubkey)
}

fn temp_wallet_dir() -> Result<PathBuf> {
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("time")?
        .as_nanos();
    let dir = env::temp_dir().join(format!(
        "zolana-wallet-cli-e2e-{}-{stamp}",
        std::process::id()
    ));
    std::fs::create_dir_all(&dir).with_context(|| dir.display().to_string())?;
    Ok(dir)
}

fn parse_tree_pubkey(output: &str) -> Result<String> {
    output
        .lines()
        .find_map(|line| line.strip_prefix("ok tree "))
        .map(str::trim)
        .map(str::to_owned)
        .ok_or_else(|| anyhow!("create-tree output missing tree pubkey:\n{output}"))
}

#[test]
#[serial]
fn wallet_cli_sol_cycle() -> Result<()> {
    restart_localnet();
    start_prover()?;

    let rpc_url = std::env::var(RPC_URL_ENV).unwrap_or_else(|_| DEFAULT_RPC_URL.to_owned());
    let indexer_url =
        std::env::var(INDEXER_URL_ENV).unwrap_or_else(|_| DEFAULT_INDEXER_URL.to_owned());

    let root = temp_wallet_dir()?;
    let alice = root.join("alice.pid.json");
    let bob = root.join("bob.pid.json");
    let tree_keypair = root.join("tree.json");

    wallet_init(&alice)?;
    wallet_init(&bob)?;

    let create_tree_out = run_cli(&[
        "wallet",
        "create-tree",
        "--keypair",
        &alice.display().to_string(),
        "--tree-keypair",
        &tree_keypair.display().to_string(),
        "--rpc-url",
        &rpc_url,
        "--indexer-url",
        &indexer_url,
        "--airdrop-lamports",
        "20000000000",
    ])?;
    let tree = parse_tree_pubkey(&create_tree_out)?;

    let deposit_amount = "500000000";
    for _ in 0..2 {
        run_cli(&[
            "wallet",
            "deposit",
            "--keypair",
            &alice.display().to_string(),
            "--tree",
            &tree,
            "--to",
            &bob.display().to_string(),
            "--amount",
            deposit_amount,
            "--mint",
            "SOL",
            "--rpc-url",
            &rpc_url,
            "--indexer-url",
            &indexer_url,
            "--airdrop-lamports",
            "2000000000",
        ])?;
    }

    let sync_out = run_cli(&[
        "wallet",
        "sync",
        "--keypair",
        &bob.display().to_string(),
        "--rpc-url",
        &rpc_url,
        "--indexer-url",
        &indexer_url,
    ])?;
    assert!(sync_out.contains("ok sync"), "sync failed: {sync_out}");

    let balance_out = run_cli(&[
        "wallet",
        "balance",
        "--keypair",
        &bob.display().to_string(),
        "--rpc-url",
        &rpc_url,
        "--indexer-url",
        &indexer_url,
    ])?;
    assert!(
        balance_out.contains("ok balance"),
        "balance failed: {balance_out}"
    );
    assert!(
        balance_out.contains("1000000000"),
        "expected 1B lamports balance, got: {balance_out}"
    );

    let alice_funding = funding_pubkey(&alice)?;
    run_cli(&[
        "wallet",
        "transfer",
        "--keypair",
        &bob.display().to_string(),
        "--tree",
        &tree,
        "--to",
        &alice_funding,
        "--amount",
        "400000000",
        "--mint",
        "SOL",
        "--rpc-url",
        &rpc_url,
        "--indexer-url",
        &indexer_url,
        "--prover-url",
        DEFAULT_PROVER_URL,
        "--airdrop-lamports",
        "2000000000",
    ])?;

    run_cli(&[
        "wallet",
        "sync",
        "--keypair",
        &alice.display().to_string(),
        "--rpc-url",
        &rpc_url,
        "--indexer-url",
        &indexer_url,
    ])?;

    let bob_funding = funding_pubkey(&bob)?;
    run_cli(&[
        "wallet",
        "withdraw",
        "--keypair",
        &alice.display().to_string(),
        "--tree",
        &tree,
        "--to",
        &bob_funding,
        "--amount",
        "200000000",
        "--mint",
        "SOL",
        "--rpc-url",
        &rpc_url,
        "--indexer-url",
        &indexer_url,
        "--prover-url",
        DEFAULT_PROVER_URL,
        "--airdrop-lamports",
        "2000000000",
    ])?;

    Ok(())
}
