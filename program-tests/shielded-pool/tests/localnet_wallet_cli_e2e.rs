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
use solana_instruction::{AccountMeta, Instruction};
use solana_keypair::Keypair;
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use zolana_client::{Rpc, SolanaRpc};
use zolana_interface::{pda, SPL_TOKEN_ACCOUNT_AMOUNT_END, SPL_TOKEN_ACCOUNT_AMOUNT_OFFSET};
use zolana_transaction::Address;

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

fn create_associated_token_account_ix(
    payer: &Pubkey,
    owner: &Pubkey,
    mint: &Pubkey,
) -> Instruction {
    let ata = pda::associated_token_address(owner, mint);
    Instruction {
        program_id: pda::associated_token_program_id(),
        accounts: vec![
            AccountMeta::new(*payer, true),
            AccountMeta::new(ata, false),
            AccountMeta::new_readonly(*owner, false),
            AccountMeta::new_readonly(*mint, false),
            AccountMeta::new_readonly(Pubkey::default(), false),
            AccountMeta::new_readonly(pda::spl_token_program_id(), false),
        ],
        data: Vec::new(),
    }
}

fn ensure_associated_token_account(
    rpc_url: &str,
    payer: &Keypair,
    owner: &Pubkey,
    mint: &Pubkey,
) -> Result<Pubkey> {
    let mint = *mint;
    let ata = pda::associated_token_address(owner, &mint);
    let rpc = SolanaRpc::new(rpc_url);
    if rpc
        .get_account(Address::new_from_array(ata.to_bytes()))?
        .is_some()
    {
        return Ok(ata);
    }
    let ix = create_associated_token_account_ix(&payer.pubkey(), owner, &mint);
    let payer_address = Address::new_from_array(payer.pubkey().to_bytes());
    rpc.create_and_send_transaction(&[ix], payer_address, &[payer])?;
    Ok(ata)
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

fn wallet_init(path: &Path, rpc_url: &str, cli_env: &[(&str, &str)]) -> Result<()> {
    run_cli_with_env(
        &[
            "wallet",
            "init",
            "--path",
            &path.display().to_string(),
            "--rpc-url",
            rpc_url,
            "--airdrop-lamports",
            "1000000000",
        ],
        cli_env,
    )?;
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

    let root = temp_wallet_dir()?;
    let alice = root.join("alice.pid.json");
    let bob = root.join("bob.pid.json");
    let tree_keypair = root.join("tree.json");
    let config_path = root.join("config.json");
    let config_path_str = config_path.to_string_lossy().into_owned();
    let cli_env = [("ZOLANA_CONFIG", config_path_str.as_str())];

    wallet_init(&alice, &rpc_url, &cli_env)?;
    wallet_init(&bob, &rpc_url, &cli_env)?;

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
    let alice_token_account = parse_field(&test_mint_out, "token_account")?;
    let spl_mint_pubkey = spl_mint.parse::<Pubkey>()?;
    let alice_funding_keypair = load_funding_keypair(&alice)?;
    let unregistered_recipient = Keypair::new();
    let bob_funding = funding_pubkey(&bob)?;
    let bob_owner = bob_funding.parse::<Pubkey>()?;
    let bob_ata = ensure_associated_token_account(
        &rpc_url,
        &alice_funding_keypair,
        &bob_owner,
        &spl_mint_pubkey,
    )?;
    let unregistered_ata = ensure_associated_token_account(
        &rpc_url,
        &alice_funding_keypair,
        &unregistered_recipient.pubkey(),
        &spl_mint_pubkey,
    )?;
    let rpc = SolanaRpc::new(&rpc_url);
    assert_eq!(
        spl_token_account_amount(&rpc, &unregistered_ata)?,
        0,
        "unregistered ATA should start empty"
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
            ],
            &cli_env,
        )?;
    }

    let sync_out = run_cli_with_env(
        &[
            "wallet",
            "sync",
            "--keypair",
            &bob.display().to_string(),
            "--rpc-url",
            &rpc_url,
            "--indexer-url",
            &indexer_url,
        ],
        &cli_env,
    )?;
    assert!(sync_out.contains("ok sync"), "sync failed: {sync_out}");

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
            &bob.display().to_string(),
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

    let alice_funding = funding_pubkey(&alice)?;
    run_cli_with_env(
        &[
            "wallet",
            "transfer",
            "--keypair",
            &bob.display().to_string(),
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
            &alice_funding,
            "--amount",
            "250000",
            "--mint",
            &spl_mint,
            "--rpc-url",
            &rpc_url,
            "--indexer-url",
            &indexer_url,
            "--prover-url",
            DEFAULT_PROVER_URL,
            "--airdrop-lamports",
            "2000000000",
        ],
        &cli_env,
    )?;

    let unregistered_transfer_amount = 50_000u64;
    let alice_token_before_unregistered =
        spl_token_account_amount(&rpc, &alice_token_account.parse()?)?;
    run_cli_with_env(
        &[
            "wallet",
            "transfer",
            "--keypair",
            &bob.display().to_string(),
            "--to",
            &unregistered_recipient.pubkey().to_string(),
            "--amount",
            &unregistered_transfer_amount.to_string(),
            "--mint",
            &spl_mint,
            "--rpc-url",
            &rpc_url,
            "--indexer-url",
            &indexer_url,
            "--prover-url",
            DEFAULT_PROVER_URL,
            "--airdrop-lamports",
            "2000000000",
        ],
        &cli_env,
    )?;
    assert_eq!(
        spl_token_account_amount(&rpc, &unregistered_ata)?,
        unregistered_transfer_amount,
        "unregistered SPL transfer should settle to recipient ATA"
    );
    assert_eq!(
        spl_token_account_amount(&rpc, &alice_token_account.parse()?)?,
        alice_token_before_unregistered,
        "sender-configured deposit token account must not receive unregistered transfer"
    );

    run_cli_with_env(
        &[
            "wallet",
            "sync",
            "--keypair",
            &alice.display().to_string(),
            "--rpc-url",
            &rpc_url,
            "--indexer-url",
            &indexer_url,
        ],
        &cli_env,
    )?;

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
            DEFAULT_PROVER_URL,
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
    assert_eq!(
        spl_token_account_amount(&rpc, &bob_ata)?,
        0,
        "bob ATA should start empty"
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
            &spl_withdraw_amount.to_string(),
            "--mint",
            &spl_mint,
            "--rpc-url",
            &rpc_url,
            "--indexer-url",
            &indexer_url,
            "--prover-url",
            DEFAULT_PROVER_URL,
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

    Ok(())
}
