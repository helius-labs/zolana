//! Wallet CLI commands against a local validator + Photon indexer.
//!
//! Run with `just test-localnet-e2e-photon`.

use std::{
    env,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    time::{SystemTime, UNIX_EPOCH},
};

use anyhow::{anyhow, bail, Context, Result};
use serde::Deserialize;
use serial_test::serial;
use solana_keypair::Keypair;
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use zolana_client::{Rpc, SolanaRpc};
use zolana_interface::{pda, SPL_TOKEN_ACCOUNT_AMOUNT_END, SPL_TOKEN_ACCOUNT_AMOUNT_OFFSET};
use zolana_keypair::ShieldedAddress;
use zolana_transaction::Address;

#[path = "common/transact.rs"]
#[allow(dead_code)]
mod transact_common;

use transact_common::start_prover;

const RPC_URL_ENV: &str = "ZOLANA_LOCALNET_URL";
const INDEXER_URL_ENV: &str = "ZOLANA_INDEXER_URL";
const PROVER_URL_ENV: &str = "ZOLANA_PROVER_URL";
const DEFAULT_RPC_URL: &str = "http://127.0.0.1:8899";
const DEFAULT_INDEXER_URL: &str = "http://127.0.0.1:8784";
const DEFAULT_PROVER_URL: &str = "http://127.0.0.1:3001";
const PARALLEL_TRANSFER_WIDTH: usize = 2;

#[derive(Deserialize)]
struct WalletFile {
    funding_pubkey: String,
}

fn spl_token_account_amount(rpc: &SolanaRpc, token_account: &Pubkey) -> Result<u64> {
    let account = rpc
        .get_account(Address::new_from_array(token_account.to_bytes()))?
        .ok_or_else(|| anyhow!("token account {token_account} not found"))?;
    if account.data.len() < SPL_TOKEN_ACCOUNT_AMOUNT_END {
        bail!(
            "token account {token_account} data too short: {}",
            account.data.len()
        );
    }
    let mut amount_bytes = [0u8; 8];
    amount_bytes.copy_from_slice(
        &account.data[SPL_TOKEN_ACCOUNT_AMOUNT_OFFSET..SPL_TOKEN_ACCOUNT_AMOUNT_END],
    );
    Ok(u64::from_le_bytes(amount_bytes))
}

/// Restart a fresh local validator + Photon through the `zolana` CLI (the same
/// launcher the other photon e2e tests use; it owns the validator/photon
/// orchestration and readiness checks). Deploys the shielded-pool program;
/// direct shielded addresses keep this payment cycle independent of the user
/// registry. `--skip-prover` leaves the persistent prover server untouched so
/// its proving keys stay loaded.
fn restart_localnet() {
    let root = concat!(env!("CARGO_MANIFEST_DIR"), "/../..");
    let cli =
        std::env::var("ZOLANA_CLI_BIN").unwrap_or_else(|_| format!("{root}/target/debug/zolana"));
    let program_id =
        std::env::var("SHIELDED_POOL_PROGRAM_ID").expect("SHIELDED_POOL_PROGRAM_ID must be set");
    let rpc_port = std::env::var("ZOLANA_LOCALNET_RPC_PORT").unwrap_or_else(|_| "8899".to_string());
    let photon_port =
        std::env::var("ZOLANA_LOCALNET_PHOTON_PORT").unwrap_or_else(|_| "8784".to_string());
    let program_so = format!("{root}/target/deploy/shielded_pool_program.so");

    let status = Command::new(&cli)
        .current_dir(root)
        .args([
            "test-validator",
            "--no-use-surfpool",
            "--with-photon",
            "--skip-prover",
            "--rpc-port",
            &rpc_port,
            "--photon-port",
            &photon_port,
            "--ledger",
            "/tmp/zolana-photon-test-ledger",
            "--sbf-program",
            &program_id,
            &program_so,
        ])
        .status()
        .expect("run zolana test-validator");
    assert!(status.success(), "zolana test-validator restart failed");
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

fn cli_command(config_path: &Path) -> Command {
    let mut command = Command::new(cli_bin());
    command.arg("-C").arg(config_path);
    command
}

fn run_cli(config_path: &Path, args: &[&str]) -> Result<String> {
    let mut command = cli_command(config_path);
    let output = command
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

fn run_cli_failure(config_path: &Path, args: &[&str]) -> Result<String> {
    let output = cli_command(config_path)
        .args(args)
        .output()
        .with_context(|| format!("spawn zolana {}", args.join(" ")))?;
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    if output.status.success() {
        bail!(
            "zolana {} unexpectedly succeeded:\nstdout:{stdout}\nstderr:{stderr}",
            args.join(" ")
        );
    }
    Ok(format!("{stdout}\n{stderr}"))
}

fn run_cli_batch(config_path: &Path, invocations: &[Vec<String>]) -> Result<Vec<String>> {
    let mut children = Vec::with_capacity(invocations.len());
    for args in invocations {
        let command_line = args.join(" ");
        let child = cli_command(config_path)
            .args(args)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .with_context(|| format!("spawn zolana {command_line}"))?;
        children.push((command_line, child));
    }

    children
        .into_iter()
        .map(|(command_line, child)| {
            let output = child
                .wait_with_output()
                .with_context(|| format!("wait for zolana {command_line}"))?;
            let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
            let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
            if !output.status.success() {
                bail!(
                    "zolana {command_line} failed (status={}):\nstdout:{stdout}\nstderr:{stderr}",
                    output.status
                );
            }
            Ok(stdout)
        })
        .collect()
}

fn wallet_new(config_path: &Path, path: &Path) -> Result<()> {
    run_cli(
        config_path,
        &["wallet", "new", "--outfile", &path.display().to_string()],
    )?;
    Ok(())
}

fn wallet_address(config_path: &Path, path: Option<&Path>) -> Result<String> {
    let mut args = vec!["wallet", "address"];
    let path_string;
    if let Some(path) = path {
        path_string = path.display().to_string();
        args.extend(["-k", path_string.as_str()]);
    }
    let output = run_cli(config_path, &args)?;
    let address = output.trim();
    address
        .parse::<ShieldedAddress>()
        .with_context(|| format!("wallet address returned an invalid value: {address}"))?;
    Ok(address.to_owned())
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

fn parse_field(output: &str, field: &str) -> Result<String> {
    output
        .split_whitespace()
        .find_map(|part| part.strip_prefix(&format!("{field}=")))
        .map(str::to_owned)
        .ok_or_else(|| anyhow!("output missing {field}=...:\n{output}"))
}

fn parse_utxo_hashes(output: &str) -> Result<Vec<String>> {
    let hashes = output
        .lines()
        .filter(|line| line.starts_with("ok utxo "))
        .map(|line| parse_field(line, "hash"))
        .collect::<Result<Vec<_>>>()?;
    if hashes.is_empty() {
        bail!("utxos output contained no spendable notes:\n{output}");
    }
    Ok(hashes)
}

#[test]
#[serial]
fn wallet_cli_sol_and_spl_cycle() -> Result<()> {
    restart_localnet();
    start_prover()?;

    let rpc_url = std::env::var(RPC_URL_ENV).unwrap_or_else(|_| DEFAULT_RPC_URL.to_owned());
    let indexer_url =
        std::env::var(INDEXER_URL_ENV).unwrap_or_else(|_| DEFAULT_INDEXER_URL.to_owned());
    let prover_url =
        std::env::var(PROVER_URL_ENV).unwrap_or_else(|_| DEFAULT_PROVER_URL.to_owned());

    let root = temp_wallet_dir()?;
    let alice = root.join("alice.json");
    let bob = root.join("bob.json");
    let tree_keypair = root.join("tree.json");
    let config_path = root.join("config.json");
    let alice_path = alice.display().to_string();
    let bob_path = bob.display().to_string();

    wallet_new(&config_path, &alice)?;
    run_cli(
        &config_path,
        &[
            "config",
            "set",
            "--keypair",
            &alice_path,
            "--rpc-url",
            &rpc_url,
            "--indexer-url",
            &indexer_url,
            "--prover-url",
            &prover_url,
        ],
    )?;
    let alice_address = wallet_address(&config_path, None)?;

    wallet_new(&config_path, &bob)?;
    let bob_address = wallet_address(&config_path, Some(&bob))?;

    let config_out = run_cli(&config_path, &["config", "get"])?;
    assert!(
        config_out.contains(&alice_path),
        "isolated config does not select Alice: {config_out}"
    );

    let create_tree_out = run_cli(
        &config_path,
        &[
            "create-tree",
            "--tree-keypair",
            &tree_keypair.display().to_string(),
            "--airdrop-lamports",
            "20000000000",
        ],
    )?;
    let _tree = parse_tree_pubkey(&create_tree_out)?;

    let test_mint_out = run_cli(
        &config_path,
        &[
            "test-mint",
            "--amount",
            "1000000",
            "--airdrop-lamports",
            "2000000000",
        ],
    )?;
    let spl_mint = parse_field(&test_mint_out, "mint")?;
    let spl_mint_pubkey = spl_mint.parse::<Pubkey>()?;
    let alice_token_account = parse_field(&test_mint_out, "token_account")?.parse::<Pubkey>()?;
    let alice_funding = funding_pubkey(&alice)?;
    let alice_owner = alice_funding.parse::<Pubkey>()?;
    assert_eq!(
        alice_token_account,
        pda::associated_token_address(&alice_owner, &spl_mint_pubkey),
        "test-mint must fund the selected owner's ATA"
    );

    let bob_funding = funding_pubkey(&bob)?;
    let bob_owner = bob_funding.parse::<Pubkey>()?;
    let bob_ata = pda::associated_token_address(&bob_owner, &spl_mint_pubkey);
    let public_recipient = Keypair::new();
    let public_recipient_ata =
        pda::associated_token_address(&public_recipient.pubkey(), &spl_mint_pubkey);
    let mut rpc = SolanaRpc::new(&rpc_url);
    rpc.airdrop(&bob_owner, 1_000_000_000)?;
    assert!(
        rpc.get_account(Address::new_from_array(public_recipient_ata.to_bytes()))?
            .is_none(),
        "public recipient ATA should not exist before withdrawal"
    );

    let asset_registry_out = run_cli(&config_path, &["config", "asset-registry"])?;
    assert!(
        asset_registry_out.contains(&spl_mint),
        "asset registry missing SPL mint: {asset_registry_out}"
    );

    for _ in 0..2 {
        run_cli(
            &config_path,
            &[
                "wallet",
                "deposit",
                "0.5",
                "--to",
                &bob_address,
                "--mint",
                "SOL",
            ],
        )?;
    }

    let balance_out = run_cli(&config_path, &["wallet", "balance", "-k", &bob_path])?;
    assert!(
        balance_out.contains("amount=1000000000"),
        "expected 1 SOL private balance, got: {balance_out}"
    );

    let bob_utxos_out = run_cli(&config_path, &["wallet", "utxos", "-k", &bob_path])?;
    let bob_input_hashes = parse_utxo_hashes(&bob_utxos_out)?;
    assert!(
        bob_input_hashes.len() >= PARALLEL_TRANSFER_WIDTH,
        "expected two deposited notes: {bob_utxos_out}"
    );
    assert_ne!(
        bob_input_hashes[0], bob_input_hashes[1],
        "parallel sends need distinct input notes"
    );

    let parallel_transfers = bob_input_hashes
        .iter()
        .take(PARALLEL_TRANSFER_WIDTH)
        .map(|input| {
            vec![
                "wallet".to_string(),
                "transfer".to_string(),
                "0.1".to_string(),
                alice_address.clone(),
                "-k".to_string(),
                bob_path.clone(),
                "--input".to_string(),
                input.clone(),
            ]
        })
        .collect::<Vec<_>>();
    for output in run_cli_batch(&config_path, &parallel_transfers)? {
        assert!(
            output.contains("ok transfer") && output.contains("mode=shielded"),
            "parallel transfer was not shielded: {output}"
        );
    }

    for _ in 0..2 {
        let alice_to_bob = run_cli(&config_path, &["wallet", "transfer", "0.025", &bob_address])?;
        assert!(alice_to_bob.contains("mode=shielded"), "{alice_to_bob}");

        let bob_to_alice = run_cli(
            &config_path,
            &[
                "wallet",
                "transfer",
                "0.025",
                &alice_address,
                "-k",
                &bob_path,
            ],
        )?;
        assert!(bob_to_alice.contains("mode=shielded"), "{bob_to_alice}");
    }

    let bob_sol_balance = run_cli(&config_path, &["wallet", "balance", "-k", &bob_path])?;
    assert!(
        bob_sol_balance.contains("amount=800000000"),
        "parallel private sends produced the wrong Bob balance: {bob_sol_balance}"
    );
    let alice_sol_balance = run_cli(&config_path, &["wallet", "balance"])?;
    assert!(
        alice_sol_balance.contains("amount=200000000"),
        "bidirectional private sends produced the wrong Alice balance: {alice_sol_balance}"
    );

    run_cli(
        &config_path,
        &[
            "wallet",
            "deposit",
            "600000",
            "--to",
            &bob_address,
            "--mint",
            &spl_mint,
        ],
    )?;
    assert_eq!(
        spl_token_account_amount(&rpc, &alice_token_account)?,
        400_000,
        "deposit must debit Alice's derived ATA"
    );

    let spl_balance_out = run_cli(
        &config_path,
        &["wallet", "balance", "-k", &bob_path, "--mint", &spl_mint],
    )?;
    assert!(
        spl_balance_out.contains("amount=600000"),
        "expected 600000 SPL balance, got: {spl_balance_out}"
    );

    let bob_spl_utxos = run_cli(
        &config_path,
        &["wallet", "utxos", "-k", &bob_path, "--mint", &spl_mint],
    )?;
    let bob_spl_input = parse_utxo_hashes(&bob_spl_utxos)?
        .into_iter()
        .next()
        .ok_or_else(|| anyhow!("Bob has no spendable SPL input"))?;

    let bob_to_alice_spl = run_cli(
        &config_path,
        &[
            "wallet",
            "transfer",
            "250000",
            &alice_address,
            "-k",
            &bob_path,
            "--mint",
            &spl_mint,
            "--input",
            &bob_spl_input,
        ],
    )?;
    assert!(
        bob_to_alice_spl.contains("mode=shielded"),
        "{bob_to_alice_spl}"
    );

    let alice_to_bob_spl = run_cli(
        &config_path,
        &[
            "wallet",
            "transfer",
            "50000",
            &bob_address,
            "--mint",
            &spl_mint,
        ],
    )?;
    assert!(
        alice_to_bob_spl.contains("mode=shielded"),
        "{alice_to_bob_spl}"
    );

    let public_withdraw_amount = 50_000u64;
    let transfer_error = run_cli_failure(
        &config_path,
        &[
            "wallet",
            "transfer",
            &public_withdraw_amount.to_string(),
            &public_recipient.pubkey().to_string(),
            "-k",
            &bob_path,
            "--mint",
            &spl_mint,
        ],
    )?;
    assert!(
        transfer_error.contains("invalid shielded address"),
        "{transfer_error}"
    );
    assert!(
        rpc.get_account(Address::new_from_array(public_recipient_ata.to_bytes()))?
            .is_none(),
        "failed private transfer must not create or fund a public ATA"
    );

    let bob_balance_after_failure = run_cli(
        &config_path,
        &["wallet", "balance", "-k", &bob_path, "--mint", &spl_mint],
    )?;
    assert!(
        bob_balance_after_failure.contains("amount=400000"),
        "failed transfer changed Bob's private balance: {bob_balance_after_failure}"
    );

    run_cli(
        &config_path,
        &[
            "wallet",
            "withdraw",
            &public_withdraw_amount.to_string(),
            &public_recipient.pubkey().to_string(),
            "-k",
            &bob_path,
            "--mint",
            &spl_mint,
        ],
    )?;
    assert_eq!(
        spl_token_account_amount(&rpc, &public_recipient_ata)?,
        public_withdraw_amount,
        "explicit SPL withdrawal should settle to the public ATA"
    );

    let alice_utxos_out = run_cli(&config_path, &["wallet", "utxos"])?;
    assert!(
        alice_utxos_out.contains("ok utxos mint=SOL count="),
        "utxos failed: {alice_utxos_out}"
    );

    run_cli(
        &config_path,
        &["wallet", "withdraw", "0.1", &bob_funding, "--mint", "SOL"],
    )?;

    let alice_spl_balance_out = run_cli(&config_path, &["wallet", "balance", "--mint", &spl_mint])?;
    assert!(
        alice_spl_balance_out.contains("amount=200000"),
        "expected 200000 SPL balance, got: {alice_spl_balance_out}"
    );

    let spl_withdraw_amount = 100_000u64;
    assert!(
        rpc.get_account(Address::new_from_array(bob_ata.to_bytes()))?
            .is_none(),
        "Bob ATA should not exist before withdrawal"
    );
    run_cli(
        &config_path,
        &[
            "wallet",
            "withdraw",
            &spl_withdraw_amount.to_string(),
            &bob_funding,
            "--mint",
            &spl_mint,
        ],
    )?;
    assert_eq!(
        spl_token_account_amount(&rpc, &bob_ata)?,
        spl_withdraw_amount,
        "SPL withdraw should settle to recipient ATA"
    );

    let final_alice_spl = run_cli(&config_path, &["wallet", "balance", "--mint", &spl_mint])?;
    assert!(
        final_alice_spl.contains("amount=100000"),
        "unexpected final Alice SPL balance: {final_alice_spl}"
    );

    Ok(())
}
