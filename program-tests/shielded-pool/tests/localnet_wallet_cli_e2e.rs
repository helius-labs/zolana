//! Wallet CLI commands against a local validator + Photon indexer.
//!
//! Run with `just test-localnet-e2e-photon`.

use std::{
    env,
    path::{Path, PathBuf},
    process::Command,
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

#[derive(Deserialize)]
struct WalletFundingKey {
    funding_secret_hex: String,
    funding_pubkey: String,
}

fn load_funding_keypair(path: &Path) -> Result<Keypair> {
    let bytes = std::fs::read(path).with_context(|| path.display().to_string())?;
    let file: WalletFundingKey = serde_json::from_slice(&bytes)
        .with_context(|| format!("parse wallet {}", path.display()))?;
    let secret = hex::decode(&file.funding_secret_hex).context("decode funding secret")?;
    if secret.len() != 32 {
        bail!(
            "wallet {} funding secret has invalid length {}",
            path.display(),
            secret.len()
        );
    }
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&secret);
    let keypair = Keypair::new_from_array(seed);
    if keypair.pubkey().to_string() != file.funding_pubkey {
        bail!(
            "wallet {} funding pubkey does not match secret",
            path.display()
        );
    }
    Ok(keypair)
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

fn ensure_associated_token_account(
    rpc_url: &str,
    payer: &Keypair,
    owner: &Pubkey,
    mint: &Pubkey,
) -> Result<Pubkey> {
    let rpc = SolanaRpc::new(rpc_url);
    let (_signature, account) =
        zolana_client::create_associated_token_account(&rpc, payer, owner, mint)?;
    Ok(account)
}

/// Restart a fresh local validator + Photon through the `zolana` CLI (the same
/// launcher the other photon e2e tests use; it owns the validator/photon
/// orchestration and readiness checks). Deploys the shielded-pool and
/// user-registry programs the wallet CLI needs (the latter backs pay-by-pubkey
/// recipient resolution); `--skip-prover` leaves the persistent prover server
/// untouched so its proving keys stay loaded.
fn restart_localnet() {
    let root = concat!(env!("CARGO_MANIFEST_DIR"), "/../..");
    let cli =
        std::env::var("ZOLANA_CLI_BIN").unwrap_or_else(|_| format!("{root}/target/debug/zolana"));
    let program_id =
        std::env::var("SHIELDED_POOL_PROGRAM_ID").expect("SHIELDED_POOL_PROGRAM_ID must be set");
    let user_registry_program_id =
        std::env::var("USER_REGISTRY_PROGRAM_ID").expect("USER_REGISTRY_PROGRAM_ID must be set");
    let rpc_port = std::env::var("ZOLANA_LOCALNET_RPC_PORT").unwrap_or_else(|_| "8899".to_string());
    let photon_port =
        std::env::var("ZOLANA_LOCALNET_PHOTON_PORT").unwrap_or_else(|_| "8784".to_string());
    let program_so = format!("{root}/target/deploy/shielded_pool_program.so");
    let user_registry_so = format!("{root}/target/deploy/zolana_user_registry.so");

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
            "--sbf-program",
            &user_registry_program_id,
            &user_registry_so,
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

fn run_cli_with_env(args: &[&str], env: &[(&str, &str)]) -> Result<String> {
    let mut command = Command::new(cli_bin());
    for (key, value) in env {
        command.env(key, value);
    }
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

fn wallet_new(path: &Path, config: &Path, cli_env: &[(&str, &str)]) -> Result<()> {
    run_cli_with_env(
        &[
            "-C",
            &config.display().to_string(),
            "wallet",
            "new",
            "--outfile",
            &path.display().to_string(),
        ],
        cli_env,
    )?;
    Ok(())
}

fn wallet_address(path: &Path, config: &Path, cli_env: &[(&str, &str)]) -> Result<ShieldedAddress> {
    run_cli_with_env(
        &[
            "-C",
            &config.display().to_string(),
            "wallet",
            "address",
            "-k",
            &path.display().to_string(),
        ],
        cli_env,
    )?
    .trim()
    .parse::<ShieldedAddress>()
    .context("parse wallet shielded address")
}

fn funding_pubkey(path: &Path, config: &Path, cli_env: &[(&str, &str)]) -> Result<String> {
    Ok(run_cli_with_env(
        &[
            "-C",
            &config.display().to_string(),
            "wallet",
            "address",
            "-k",
            &path.display().to_string(),
            "--funding",
        ],
        cli_env,
    )?
    .trim()
    .to_string())
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
    let alice = root.join("alice.pid.json");
    let bob = root.join("bob.pid.json");
    let tree_keypair = root.join("tree.json");
    let config_path = root.join("config.json");
    let config_path_str = config_path.to_string_lossy().into_owned();
    let cli_env = [("ZOLANA_CONFIG", config_path_str.as_str())];

    wallet_new(&alice, &config_path, &cli_env)?;
    wallet_new(&bob, &config_path, &cli_env)?;
    let alice_address = wallet_address(&alice, &config_path, &cli_env)?;
    let bob_address = wallet_address(&bob, &config_path, &cli_env)?;

    let create_tree_out = run_cli_with_env(
        &[
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
        ],
        &cli_env,
    )?;
    let _tree = parse_tree_pubkey(&create_tree_out)?;

    let test_mint_out = run_cli_with_env(
        &[
            "wallet",
            "test-mint",
            "--keypair",
            &alice.display().to_string(),
            "--amount",
            "1000000",
            "--rpc-url",
            &rpc_url,
            "--indexer-url",
            &indexer_url,
            "--airdrop-lamports",
            "2000000000",
        ],
        &cli_env,
    )?;
    let spl_mint = parse_field(&test_mint_out, "mint")?;
    let spl_mint_pubkey = spl_mint.parse::<Pubkey>()?;
    let public_recipient = Keypair::new();
    let bob_funding = funding_pubkey(&bob, &config_path, &cli_env)?;
    let bob_owner = bob_funding.parse::<Pubkey>()?;
    let bob_funding_keypair = load_funding_keypair(&bob)?;
    let bob_ata = pda::associated_token_address(&bob_owner, &spl_mint_pubkey);
    let public_ata = pda::associated_token_address(&public_recipient.pubkey(), &spl_mint_pubkey);
    let mut rpc = SolanaRpc::new(&rpc_url);
    rpc.airdrop(&bob_owner, 2_000_000_000)?;
    assert_eq!(
        ensure_associated_token_account(
            &rpc_url,
            &bob_funding_keypair,
            &bob_owner,
            &spl_mint_pubkey,
        )?,
        bob_ata
    );
    assert!(
        rpc.get_account(Address::new_from_array(public_ata.to_bytes()))?
            .is_none(),
        "public recipient ATA should not exist before withdrawal"
    );

    let asset_registry_out = run_cli_with_env(&["config", "asset-registry"], &cli_env)?;
    assert!(
        asset_registry_out.contains(&spl_mint),
        "asset registry missing SPL mint: {asset_registry_out}"
    );

    let deposit_amount = "500000000";
    for _ in 0..2 {
        run_cli_with_env(
            &[
                "wallet",
                "deposit",
                "--keypair",
                &alice.display().to_string(),
                "--to",
                &bob_address.to_string(),
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
            ],
            &cli_env,
        )?;
    }

    let balance_out = run_cli_with_env(
        &[
            "wallet",
            "balance",
            "--keypair",
            &bob.display().to_string(),
            "--rpc-url",
            &rpc_url,
            "--indexer-url",
            &indexer_url,
        ],
        &cli_env,
    )?;
    assert!(
        balance_out.contains("ok balance"),
        "balance failed: {balance_out}"
    );
    assert!(
        balance_out.contains("1000000000"),
        "expected 1B lamports balance, got: {balance_out}"
    );

    run_cli_with_env(
        &[
            "wallet",
            "deposit",
            "--keypair",
            &alice.display().to_string(),
            "--to",
            &bob_address.to_string(),
            "--amount",
            "600000",
            "--mint",
            &spl_mint,
            "--rpc-url",
            &rpc_url,
            "--indexer-url",
            &indexer_url,
            "--airdrop-lamports",
            "2000000000",
        ],
        &cli_env,
    )?;

    let spl_balance_out = run_cli_with_env(
        &[
            "wallet",
            "balance",
            "--keypair",
            &bob.display().to_string(),
            "--mint",
            &spl_mint,
            "--rpc-url",
            &rpc_url,
            "--indexer-url",
            &indexer_url,
        ],
        &cli_env,
    )?;
    assert!(
        spl_balance_out.contains("amount=600000"),
        "expected 600000 SPL balance, got: {spl_balance_out}"
    );

    run_cli_with_env(
        &[
            "wallet",
            "transfer",
            "--keypair",
            &bob.display().to_string(),
            "--to",
            &alice_address.to_string(),
            "--amount",
            "400000000",
            "--mint",
            "SOL",
            "--rpc-url",
            &rpc_url,
            "--indexer-url",
            &indexer_url,
            "--prover-url",
            &prover_url,
        ],
        &cli_env,
    )?;

    run_cli_with_env(
        &[
            "wallet",
            "transfer",
            "--keypair",
            &bob.display().to_string(),
            "--to",
            &alice_address.to_string(),
            "--amount",
            "250000",
            "--mint",
            &spl_mint,
            "--rpc-url",
            &rpc_url,
            "--indexer-url",
            &indexer_url,
            "--prover-url",
            &prover_url,
        ],
        &cli_env,
    )?;

    // An unregistered Solana pubkey has no user-registry record, so `transfer`
    // silently falls back to a public withdrawal (spec Single Player,
    // lookup-negative): the CLI reports mode=withdraw and the lamports land in
    // the recipient's public account.
    let fallback_recipient = Keypair::new().pubkey();
    let fallback_amount = 2_000_000u64;
    let fallback_before = rpc
        .get_account(Address::new_from_array(fallback_recipient.to_bytes()))?
        .map_or(0, |account| account.lamports);
    let fallback_out = run_cli_with_env(
        &[
            "wallet",
            "transfer",
            "--keypair",
            &bob.display().to_string(),
            "--to",
            &fallback_recipient.to_string(),
            "--amount",
            &fallback_amount.to_string(),
            "--mint",
            "SOL",
            "--rpc-url",
            &rpc_url,
            "--indexer-url",
            &indexer_url,
            "--prover-url",
            &prover_url,
        ],
        &cli_env,
    )?;
    assert!(
        fallback_out.contains("mode=withdraw"),
        "unregistered pubkey transfer must fall back to a public withdrawal: {fallback_out}"
    );
    let fallback_after = rpc
        .get_account(Address::new_from_array(fallback_recipient.to_bytes()))?
        .map_or(0, |account| account.lamports);
    assert_eq!(
        fallback_after,
        fallback_before + fallback_amount,
        "silent public fallback should credit the recipient's SOL balance"
    );

    // Prepare the public SPL recipient used by the explicit `withdraw` below.
    let public_withdraw_amount = 50_000u64;
    assert_eq!(
        ensure_associated_token_account(
            &rpc_url,
            &bob_funding_keypair,
            &public_recipient.pubkey(),
            &spl_mint_pubkey,
        )?,
        public_ata
    );
    assert_eq!(spl_token_account_amount(&rpc, &public_ata)?, 0);

    run_cli_with_env(
        &[
            "wallet",
            "withdraw",
            "--keypair",
            &bob.display().to_string(),
            "--to",
            &public_recipient.pubkey().to_string(),
            "--amount",
            &public_withdraw_amount.to_string(),
            "--mint",
            &spl_mint,
            "--rpc-url",
            &rpc_url,
            "--indexer-url",
            &indexer_url,
            "--prover-url",
            &prover_url,
        ],
        &cli_env,
    )?;
    assert_eq!(
        spl_token_account_amount(&rpc, &public_ata)?,
        public_withdraw_amount,
        "explicit withdrawal should fund the public recipient ATA"
    );

    run_cli_with_env(
        &[
            "wallet",
            "withdraw",
            "--keypair",
            &alice.display().to_string(),
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
            &prover_url,
            "--airdrop-lamports",
            "2000000000",
        ],
        &cli_env,
    )?;

    let alice_spl_balance_out = run_cli_with_env(
        &[
            "wallet",
            "balance",
            "--keypair",
            &alice.display().to_string(),
            "--mint",
            &spl_mint,
            "--rpc-url",
            &rpc_url,
            "--indexer-url",
            &indexer_url,
        ],
        &cli_env,
    )?;
    assert!(
        alice_spl_balance_out.contains("amount=250000"),
        "expected 250000 SPL balance, got: {alice_spl_balance_out}"
    );

    let spl_withdraw_amount = 100_000u64;
    assert_eq!(spl_token_account_amount(&rpc, &bob_ata)?, 0);
    run_cli_with_env(
        &[
            "wallet",
            "withdraw",
            "--keypair",
            &alice.display().to_string(),
            "--to",
            &bob_funding,
            "--amount",
            &spl_withdraw_amount.to_string(),
            "--mint",
            &spl_mint,
            "--rpc-url",
            &rpc_url,
            "--indexer-url",
            &indexer_url,
            "--prover-url",
            &prover_url,
            "--airdrop-lamports",
            "2000000000",
        ],
        &cli_env,
    )?;
    assert_eq!(
        spl_token_account_amount(&rpc, &bob_ata)?,
        spl_withdraw_amount,
        "SPL withdraw should settle to recipient ATA"
    );

    // Pay-by-Solana-pubkey: registering bob (via `merge --enable`) publishes his
    // shielded keys to the user registry, so `transfer --to <bob pubkey>`
    // resolves the recipient and stays shielded (mode=shielded) instead of
    // falling back to a public withdrawal.
    run_cli_with_env(
        &[
            "wallet",
            "merge",
            "--enable",
            "--keypair",
            &bob.display().to_string(),
            "--rpc-url",
            &rpc_url,
            "--indexer-url",
            &indexer_url,
        ],
        &cli_env,
    )?;
    let registered_transfer_out = run_cli_with_env(
        &[
            "wallet",
            "transfer",
            "--keypair",
            &alice.display().to_string(),
            "--to",
            &bob_funding,
            "--amount",
            "1000000",
            "--mint",
            "SOL",
            "--rpc-url",
            &rpc_url,
            "--indexer-url",
            &indexer_url,
            "--prover-url",
            &prover_url,
        ],
        &cli_env,
    )?;
    assert!(
        registered_transfer_out.contains("mode=shielded"),
        "transfer to a registered Solana pubkey must resolve via the registry and stay shielded: {registered_transfer_out}"
    );

    Ok(())
}
