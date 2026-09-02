//! Wallet CLI commands against a local validator + Photon indexer.
//!
//! Run with `just test-localnet-e2e-photon`.

use std::{
    collections::HashMap,
    env,
    path::{Path, PathBuf},
    process::Command,
    str::FromStr,
    time::{SystemTime, UNIX_EPOCH},
};

use anyhow::{anyhow, bail, Context, Result};
use serial_test::serial;
use solana_keypair::Keypair;
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use zolana_client::{Rpc, SolanaRpc};
use zolana_interface::{pda, SPL_TOKEN_ACCOUNT_AMOUNT_END, SPL_TOKEN_ACCOUNT_AMOUNT_OFFSET};
use zolana_test_utils::{localnet::start_shielded_pool_localnet, prover::spawn_workspace_prover};
use zolana_transaction::Address;

const RPC_URL_ENV: &str = "ZOLANA_LOCALNET_URL";
const INDEXER_URL_ENV: &str = "ZOLANA_INDEXER_URL";
const PROVER_URL_ENV: &str = "ZOLANA_PROVER_URL";
const DEFAULT_RPC_URL: &str = "http://127.0.0.1:8899";
const DEFAULT_INDEXER_URL: &str = "http://127.0.0.1:8784";
const DEFAULT_PROVER_URL: &str = "http://127.0.0.1:3001";

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
/// orchestration and readiness checks). Deploys the shielded-pool and
/// user-registry programs the wallet CLI needs (the latter backs pay-by-pubkey
/// recipient resolution); `--skip-prover` leaves the persistent prover server
/// untouched so its proving keys stay loaded.
fn restart_localnet() {
    start_shielded_pool_localnet("zolana-wallet-cli", &[]);
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

/// One captured `zolana` CLI invocation: exit status plus lossy stdout/stderr.
struct CliOutput {
    status: std::process::ExitStatus,
    stdout: String,
    stderr: String,
}

/// Spawn `zolana args` with `env` and capture its output; the wrappers below
/// judge the exit status.
fn run_cli(args: &[&str], env: &[(&str, &str)]) -> Result<CliOutput> {
    let mut command = Command::new(cli_bin());
    for (key, value) in env {
        command.env(key, value);
    }
    let output = command
        .args(args)
        .output()
        .with_context(|| format!("spawn zolana {}", args.join(" ")))?;
    Ok(CliOutput {
        status: output.status,
        stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
    })
}

fn run_cli_with_env(args: &[&str], env: &[(&str, &str)]) -> Result<String> {
    let output = run_cli(args, env)?;
    if !output.status.success() {
        bail!(
            "zolana {} failed (status={}):\nstdout:{}\nstderr:{}",
            args.join(" "),
            output.status,
            output.stdout,
            output.stderr
        );
    }
    Ok(output.stdout)
}

fn run_cli_expect_failure(args: &[&str], env: &[(&str, &str)]) -> Result<String> {
    let output = run_cli(args, env)?;
    if output.status.success() {
        bail!("zolana {} unexpectedly succeeded", args.join(" "));
    }
    Ok(format!("{}{}", output.stdout, output.stderr))
}

fn wallet_new(path: &Path, cli_env: &[(&str, &str)]) -> Result<()> {
    run_cli_with_env(
        &["wallet", "new", "--outfile", &path.display().to_string()],
        cli_env,
    )?;
    Ok(())
}

/// The ported `wallet address` prints the bare hex owner hash (no shielded-address
/// wrapper), so the helper returns that string verbatim.
fn wallet_address(path: &Path, cli_env: &[(&str, &str)]) -> Result<String> {
    Ok(run_cli_with_env(
        &[
            "wallet",
            "address",
            "--keypair",
            &path.display().to_string(),
        ],
        cli_env,
    )?
    .trim()
    .to_string())
}

fn funding_pubkey(path: &Path, cli_env: &[(&str, &str)]) -> Result<String> {
    Ok(run_cli_with_env(
        &[
            "wallet",
            "address",
            "--keypair",
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

/// One parsed `ok <verb> key=value ...` CLI status line. The per-command typed
/// views below read their fields from this, so assertions compare typed values
/// (`out.count == 4`, `out.mode == TransferMode::Shielded`) rather than fragile
/// substrings (`contains("count=1")` also accepts `count=10`). A wrong field or
/// enum variant in an assertion is then a compile error, and the `key=` / value
/// spellings live once, inside each `parse`.
struct StatusLine<'a> {
    fields: HashMap<&'a str, &'a str>,
}

impl<'a> StatusLine<'a> {
    fn parse(output: &'a str, verb: &str) -> Result<Self> {
        let line = output
            .lines()
            .map(str::trim)
            .find(|line| {
                let mut tokens = line.split_whitespace();
                tokens.next() == Some("ok") && tokens.next() == Some(verb)
            })
            .ok_or_else(|| anyhow!("no `ok {verb}` line in output:\n{output}"))?;
        let fields = line
            .split_whitespace()
            .skip(2)
            .filter_map(|token| token.split_once('='))
            .collect();
        Ok(Self { fields })
    }

    fn field<T: FromStr>(&self, key: &str) -> Result<T>
    where
        T::Err: std::fmt::Display,
    {
        let raw = *self
            .fields
            .get(key)
            .ok_or_else(|| anyhow!("status line missing `{key}=`"))?;
        raw.parse()
            .map_err(|err| anyhow!("field `{key}={raw}` did not parse: {err}"))
    }
}

#[derive(Debug, PartialEq, Eq)]
enum TransferMode {
    Shielded,
    Withdraw,
}

impl FromStr for TransferMode {
    type Err = anyhow::Error;
    fn from_str(value: &str) -> Result<Self> {
        match value {
            "shielded" => Ok(Self::Shielded),
            "withdraw" => Ok(Self::Withdraw),
            other => bail!("unknown transfer mode `{other}`"),
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
enum RecordStatus {
    Written,
    Current,
}

impl FromStr for RecordStatus {
    type Err = anyhow::Error;
    fn from_str(value: &str) -> Result<Self> {
        match value {
            "written" => Ok(Self::Written),
            "current" => Ok(Self::Current),
            other => bail!("unknown record status `{other}`"),
        }
    }
}

struct RegisterOutput {
    record: RecordStatus,
}

impl RegisterOutput {
    fn parse(output: &str) -> Result<Self> {
        Ok(Self {
            record: StatusLine::parse(output, "register")?.field("record")?,
        })
    }
}

struct BalanceOutput {
    amount: u64,
}

impl BalanceOutput {
    fn parse(output: &str) -> Result<Self> {
        Ok(Self {
            amount: StatusLine::parse(output, "balance")?.field("amount")?,
        })
    }
}

struct SetMergingOutput {
    enabled: bool,
}

impl SetMergingOutput {
    fn parse(output: &str) -> Result<Self> {
        Ok(Self {
            enabled: StatusLine::parse(output, "set_merging")?.field("enabled")?,
        })
    }
}

struct MergeOutput {
    inputs: u64,
}

impl MergeOutput {
    fn parse(output: &str) -> Result<Self> {
        Ok(Self {
            inputs: StatusLine::parse(output, "merge")?.field("inputs")?,
        })
    }
}

struct SplitOutput {
    parts: u64,
}

impl SplitOutput {
    fn parse(output: &str) -> Result<Self> {
        Ok(Self {
            parts: StatusLine::parse(output, "split")?.field("parts")?,
        })
    }
}

struct UtxosOutput {
    count: u64,
}

impl UtxosOutput {
    fn parse(output: &str) -> Result<Self> {
        Ok(Self {
            count: StatusLine::parse(output, "utxos")?.field("count")?,
        })
    }
}

struct TransferOutput {
    mode: TransferMode,
}

impl TransferOutput {
    fn parse(output: &str) -> Result<Self> {
        Ok(Self {
            mode: StatusLine::parse(output, "transfer")?.field("mode")?,
        })
    }
}

/// Shared state for the `wallet_cli_sol_and_spl_cycle` story: the CLI endpoints,
/// the wallet keypair paths, and the config file every `zolana` invocation
/// reads.
struct CycleEnv {
    rpc_url: String,
    indexer_url: String,
    prover_url: String,
    alice_keypair: PathBuf,
    bob_keypair: PathBuf,
    config_path: String,
}

impl CycleEnv {
    fn cli_env(&self) -> [(&str, &str); 1] {
        [("ZOLANA_CONFIG", self.config_path.as_str())]
    }
}

/// The pool state `phase_create_tree_and_spl_mint` publishes for the later phases.
struct PoolState {
    spl_mint: String,
    alice_owner: Pubkey,
    bob_funding: String,
    bob_ata: Pubkey,
    public_recipient: Keypair,
    public_ata: Pubkey,
}

/// Phase 1: boot the localnet + prover, create both wallets, and persist the CLI
/// config (endpoints + selected keypair).
fn phase_setup_environment() -> Result<CycleEnv> {
    restart_localnet();
    spawn_workspace_prover();

    let rpc_url = std::env::var(RPC_URL_ENV).unwrap_or_else(|_| DEFAULT_RPC_URL.to_owned());
    let indexer_url =
        std::env::var(INDEXER_URL_ENV).unwrap_or_else(|_| DEFAULT_INDEXER_URL.to_owned());
    let prover_url =
        std::env::var(PROVER_URL_ENV).unwrap_or_else(|_| DEFAULT_PROVER_URL.to_owned());

    let root = temp_wallet_dir()?;
    let alice_keypair = root.join("alice.pid.json");
    let bob_keypair = root.join("bob.pid.json");
    let config_path = root.join("config.json").to_string_lossy().into_owned();
    let cli_env = [("ZOLANA_CONFIG", config_path.as_str())];

    wallet_new(&alice_keypair, &cli_env)?;
    wallet_new(&bob_keypair, &cli_env)?;
    run_cli_with_env(
        &[
            "config",
            "set",
            "--keypair",
            &alice_keypair.display().to_string(),
            "--rpc-url",
            &rpc_url,
            "--indexer-url",
            &indexer_url,
            "--prover-url",
            &prover_url,
        ],
        &cli_env,
    )?;
    let alice_address = wallet_address(&alice_keypair, &cli_env)?;
    let selected_address = run_cli_with_env(&["wallet", "address"], &cli_env)?;
    assert_eq!(selected_address.trim(), alice_address.as_str());
    let config_out = run_cli_with_env(&["config", "get"], &cli_env)?;
    assert!(
        config_out.contains(&alice_keypair.display().to_string())
            && config_out.contains(&rpc_url)
            && config_out.contains(&indexer_url)
            && config_out.contains(&prover_url),
        "persisted config is incomplete: {config_out}"
    );

    Ok(CycleEnv {
        rpc_url,
        indexer_url,
        prover_url,
        alice_keypair,
        bob_keypair,
        config_path,
    })
}

/// Phase 2: create the Merkle tree and a test SPL mint, and prove the recipient
/// ATAs do not exist yet.
fn phase_create_tree_and_spl_mint(env: &CycleEnv, rpc: &mut SolanaRpc) -> Result<PoolState> {
    let cli_env = env.cli_env();
    let create_tree_out = run_cli_with_env(
        &[
            "dev",
            "pool",
            "create-tree",
            "--airdrop-lamports",
            "20000000000",
        ],
        &cli_env,
    )?;
    let tree = parse_tree_pubkey(&create_tree_out)?;
    let config_out = run_cli_with_env(&["config", "get"], &cli_env)?;
    assert!(
        config_out.contains(&tree),
        "create-tree did not persist the selected tree: {config_out}"
    );

    let test_mint_out = run_cli_with_env(
        &[
            "dev",
            "pool",
            "test-mint",
            "--amount",
            "1000000",
            "--airdrop-lamports",
            "2000000000",
        ],
        &cli_env,
    )?;
    let spl_mint = parse_field(&test_mint_out, "mint")?;
    let alice_token_account = parse_field(&test_mint_out, "token_account")?.parse::<Pubkey>()?;
    let spl_mint_pubkey = spl_mint.parse::<Pubkey>()?;
    let alice_owner = funding_pubkey(&env.alice_keypair, &cli_env)?.parse::<Pubkey>()?;
    assert_eq!(
        alice_token_account,
        pda::associated_token_address(&alice_owner, &spl_mint_pubkey),
        "test-mint must fund the selected owner's associated token account"
    );
    let public_recipient = Keypair::new();
    let bob_funding = funding_pubkey(&env.bob_keypair, &cli_env)?;
    let bob_owner = bob_funding.parse::<Pubkey>()?;
    let bob_ata = pda::associated_token_address(&bob_owner, &spl_mint_pubkey);
    let public_ata = pda::associated_token_address(&public_recipient.pubkey(), &spl_mint_pubkey);
    rpc.airdrop(&bob_owner, 2_000_000_000)?;
    assert!(
        rpc.get_account(Address::new_from_array(bob_ata.to_bytes()))?
            .is_none(),
        "bob ATA should not exist before a public withdrawal"
    );
    assert!(
        rpc.get_account(Address::new_from_array(public_ata.to_bytes()))?
            .is_none(),
        "public recipient ATA should not exist before withdrawal"
    );

    let asset_registry_out = run_cli_with_env(&["config", "asset", "list"], &cli_env)?;
    assert!(
        asset_registry_out.contains(&spl_mint),
        "asset registry missing SPL mint: {asset_registry_out}"
    );

    Ok(PoolState {
        spl_mint,
        alice_owner,
        bob_funding,
        bob_ata,
        public_recipient,
        public_ata,
    })
}

/// Phase 3: publish both wallets' shielded keys to the user registry.
fn phase_register_wallets(env: &CycleEnv) -> Result<()> {
    let cli_env = env.cli_env();
    // #108 pays by registered Solana pubkey: a recipient must publish its
    // shielded keys before it can receive a shielded deposit or transfer. Register
    // both wallets up front so the deposits and bob->alice transfers below resolve
    // to shielded notes. The dedicated unregistered-fallback check further down
    // uses a fresh, never-registered pubkey, so it still exercises the withdrawal
    // path.
    let register_bob = run_cli_with_env(
        &[
            "wallet",
            "register",
            "--keypair",
            &env.bob_keypair.display().to_string(),
            "--rpc-url",
            &env.rpc_url,
        ],
        &cli_env,
    )?;
    assert_eq!(
        RegisterOutput::parse(&register_bob)?.record,
        RecordStatus::Written
    );
    let register_alice = run_cli_with_env(
        &[
            "wallet",
            "register",
            "--keypair",
            &env.alice_keypair.display().to_string(),
            "--rpc-url",
            &env.rpc_url,
        ],
        &cli_env,
    )?;
    assert_eq!(
        RegisterOutput::parse(&register_alice)?.record,
        RecordStatus::Written
    );
    let register_alice_again = run_cli_with_env(
        &[
            "wallet",
            "register",
            "--keypair",
            &env.alice_keypair.display().to_string(),
            "--rpc-url",
            &env.rpc_url,
        ],
        &cli_env,
    )?;
    assert_eq!(
        RegisterOutput::parse(&register_alice_again)?.record,
        RecordStatus::Current
    );
    Ok(())
}

/// Phase 4: shield two SOL deposits from alice to bob, sync bob, and check the total.
fn phase_shield_sol_deposits(env: &CycleEnv, pool: &PoolState) -> Result<()> {
    let cli_env = env.cli_env();
    let deposit_amount = "500000000";
    for _ in 0..2 {
        run_cli_with_env(
            &[
                "deposit",
                "--keypair",
                &env.alice_keypair.display().to_string(),
                "--to",
                &pool.bob_funding,
                "--amount",
                deposit_amount,
                "--mint",
                "SOL",
                "--rpc-url",
                &env.rpc_url,
                "--indexer-url",
                &env.indexer_url,
                "--airdrop-lamports",
                "2000000000",
            ],
            &cli_env,
        )?;
    }

    let sync_out = run_cli_with_env(
        &[
            "sync",
            "--keypair",
            &env.bob_keypair.display().to_string(),
            "--rpc-url",
            &env.rpc_url,
            "--indexer-url",
            &env.indexer_url,
        ],
        &cli_env,
    )?;
    assert!(sync_out.contains("ok sync"), "sync failed: {sync_out}");

    let balance_out = run_cli_with_env(
        &[
            "balance",
            "--keypair",
            &env.bob_keypair.display().to_string(),
            "--rpc-url",
            &env.rpc_url,
            "--indexer-url",
            &env.indexer_url,
        ],
        &cli_env,
    )?;
    assert_eq!(BalanceOutput::parse(&balance_out)?.amount, 1_000_000_000);
    Ok(())
}

/// Phase 5: bob's note housekeeping — merge opt-in, split into parts, re-merge.
fn phase_merge_split_notes(env: &CycleEnv) -> Result<()> {
    let cli_env = env.cli_env();
    // Bob is registered but has not opted into merging yet, so the merge is
    // rejected client-side before any proof: merging is a deliberate opt-in.
    let merge_before_opt_in = run_cli_expect_failure(
        &["merge", "--keypair", &env.bob_keypair.display().to_string()],
        &cli_env,
    )?;
    assert!(
        merge_before_opt_in.contains("has not enabled the merge service"),
        "merge should require explicit opt-in: {merge_before_opt_in}"
    );

    let set_merging_out = run_cli_with_env(
        &[
            "set-merging",
            "--enable",
            "--keypair",
            &env.bob_keypair.display().to_string(),
        ],
        &cli_env,
    )?;
    assert!(SetMergingOutput::parse(&set_merging_out)?.enabled);

    let merge_out = run_cli_with_env(
        &["merge", "--keypair", &env.bob_keypair.display().to_string()],
        &cli_env,
    )?;
    assert_eq!(MergeOutput::parse(&merge_out)?.inputs, 2);

    let split_out = run_cli_with_env(
        &[
            "split",
            "--parts",
            "4",
            "--keypair",
            &env.bob_keypair.display().to_string(),
        ],
        &cli_env,
    )?;
    assert_eq!(SplitOutput::parse(&split_out)?.parts, 4);
    let split_utxos = run_cli_with_env(
        &["utxos", "--keypair", &env.bob_keypair.display().to_string()],
        &cli_env,
    )?;
    assert_eq!(UtxosOutput::parse(&split_utxos)?.count, 4);

    let merge_split_out = run_cli_with_env(
        &["merge", "--keypair", &env.bob_keypair.display().to_string()],
        &cli_env,
    )?;
    assert_eq!(MergeOutput::parse(&merge_split_out)?.inputs, 4);
    let merged_utxos = run_cli_with_env(
        &["utxos", "--keypair", &env.bob_keypair.display().to_string()],
        &cli_env,
    )?;
    assert_eq!(UtxosOutput::parse(&merged_utxos)?.count, 1);
    Ok(())
}

/// Phase 6: shield an SPL deposit, then exercise shielded transfers — including
/// the unregistered-recipient public fallback and pay-by-registered-pubkey.
fn phase_spl_deposit_and_transfers(
    env: &CycleEnv,
    pool: &PoolState,
    rpc: &mut SolanaRpc,
) -> Result<()> {
    let cli_env = env.cli_env();
    run_cli_with_env(
        &[
            "deposit",
            "--keypair",
            &env.alice_keypair.display().to_string(),
            "--to",
            &pool.bob_funding,
            "--amount",
            "600000",
            "--mint",
            &pool.spl_mint,
            "--rpc-url",
            &env.rpc_url,
            "--indexer-url",
            &env.indexer_url,
            "--airdrop-lamports",
            "2000000000",
        ],
        &cli_env,
    )?;

    let spl_balance_out = run_cli_with_env(
        &[
            "balance",
            "--keypair",
            &env.bob_keypair.display().to_string(),
            "--mint",
            &pool.spl_mint,
            "--rpc-url",
            &env.rpc_url,
            "--indexer-url",
            &env.indexer_url,
        ],
        &cli_env,
    )?;
    assert_eq!(BalanceOutput::parse(&spl_balance_out)?.amount, 600_000);

    run_cli_with_env(
        &[
            "transfer",
            "--keypair",
            &env.bob_keypair.display().to_string(),
            "--to",
            &pool.alice_owner.to_string(),
            "--amount",
            "600000000",
            "--mint",
            "SOL",
            "--rpc-url",
            &env.rpc_url,
            "--indexer-url",
            &env.indexer_url,
            "--prover-url",
            &env.prover_url,
        ],
        &cli_env,
    )?;

    // `utxos --mint <spl>` lists bob's spendable SPL notes; after the single SPL
    // deposit there is exactly one, and the SOL transfer above does not touch it.
    let bob_spl_utxos = run_cli_with_env(
        &[
            "utxos",
            "--keypair",
            &env.bob_keypair.display().to_string(),
            "--mint",
            &pool.spl_mint,
            "--rpc-url",
            &env.rpc_url,
            "--indexer-url",
            &env.indexer_url,
        ],
        &cli_env,
    )?;
    assert_eq!(UtxosOutput::parse(&bob_spl_utxos)?.count, 1);

    run_cli_with_env(
        &[
            "transfer",
            "--keypair",
            &env.bob_keypair.display().to_string(),
            "--to",
            &pool.alice_owner.to_string(),
            "--amount",
            "250000",
            "--mint",
            &pool.spl_mint,
            "--rpc-url",
            &env.rpc_url,
            "--indexer-url",
            &env.indexer_url,
            "--prover-url",
            &env.prover_url,
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
            "transfer",
            "--keypair",
            &env.bob_keypair.display().to_string(),
            "--to",
            &fallback_recipient.to_string(),
            "--amount",
            &fallback_amount.to_string(),
            "--mint",
            "SOL",
            "--rpc-url",
            &env.rpc_url,
            "--indexer-url",
            &env.indexer_url,
            "--prover-url",
            &env.prover_url,
        ],
        &cli_env,
    )?;
    assert_eq!(
        TransferOutput::parse(&fallback_out)?.mode,
        TransferMode::Withdraw
    );
    let fallback_after = rpc
        .get_account(Address::new_from_array(fallback_recipient.to_bytes()))?
        .map_or(0, |account| account.lamports);
    assert_eq!(
        fallback_after,
        fallback_before + fallback_amount,
        "silent public fallback should credit the recipient's SOL balance"
    );

    // Pay alice by her plain Solana pubkey: she was registered up front, so the
    // registry resolves it to her shielded address (owner_p256 = None -> ed25519
    // owner) and the same kind of input that just fell back for an unregistered
    // pubkey now lands as a confidential shielded transfer.
    let paid_by_pubkey = run_cli_with_env(
        &[
            "transfer",
            "--keypair",
            &env.bob_keypair.display().to_string(),
            "--to",
            &pool.alice_owner.to_string(),
            "--amount",
            "3000000",
            "--mint",
            "SOL",
            "--rpc-url",
            &env.rpc_url,
            "--indexer-url",
            &env.indexer_url,
            "--prover-url",
            &env.prover_url,
        ],
        &cli_env,
    )?;
    assert_eq!(
        TransferOutput::parse(&paid_by_pubkey)?.mode,
        TransferMode::Shielded
    );
    let alice_balance_out = run_cli_with_env(
        &[
            "balance",
            "--keypair",
            &env.alice_keypair.display().to_string(),
            "--mint",
            "SOL",
            "--rpc-url",
            &env.rpc_url,
            "--indexer-url",
            &env.indexer_url,
        ],
        &cli_env,
    )?;
    assert_eq!(
        BalanceOutput::parse(&alice_balance_out)?.amount,
        603_000_000
    );
    Ok(())
}

/// Phase 7: withdraw SOL and SPL to public recipients, and re-check the
/// registered-pubkey transfer path in the alice->bob direction.
fn phase_withdraw_to_public(env: &CycleEnv, pool: &PoolState, rpc: &mut SolanaRpc) -> Result<()> {
    let cli_env = env.cli_env();
    // Explicit `withdraw` to a public SPL recipient; the CLI creates the
    // recipient's associated token account itself.
    let public_withdraw_amount = 50_000u64;
    run_cli_with_env(
        &[
            "withdraw",
            "--keypair",
            &env.bob_keypair.display().to_string(),
            "--to",
            &pool.public_recipient.pubkey().to_string(),
            "--amount",
            &public_withdraw_amount.to_string(),
            "--mint",
            &pool.spl_mint,
            "--rpc-url",
            &env.rpc_url,
            "--indexer-url",
            &env.indexer_url,
            "--prover-url",
            &env.prover_url,
        ],
        &cli_env,
    )?;
    assert_eq!(
        spl_token_account_amount(rpc, &pool.public_ata)?,
        public_withdraw_amount,
        "explicit withdrawal should fund the public recipient ATA"
    );

    run_cli_with_env(
        &[
            "withdraw",
            "--keypair",
            &env.alice_keypair.display().to_string(),
            "--to",
            &pool.bob_funding,
            "--amount",
            "200000000",
            "--mint",
            "SOL",
            "--rpc-url",
            &env.rpc_url,
            "--indexer-url",
            &env.indexer_url,
            "--prover-url",
            &env.prover_url,
            "--airdrop-lamports",
            "2000000000",
        ],
        &cli_env,
    )?;

    let alice_spl_balance_out = run_cli_with_env(
        &[
            "balance",
            "--keypair",
            &env.alice_keypair.display().to_string(),
            "--mint",
            &pool.spl_mint,
            "--rpc-url",
            &env.rpc_url,
            "--indexer-url",
            &env.indexer_url,
        ],
        &cli_env,
    )?;
    assert_eq!(
        BalanceOutput::parse(&alice_spl_balance_out)?.amount,
        250_000
    );

    let spl_withdraw_amount = 100_000u64;
    assert!(
        rpc.get_account(Address::new_from_array(pool.bob_ata.to_bytes()))?
            .is_none(),
        "bob ATA should still be absent before withdrawal"
    );
    run_cli_with_env(
        &[
            "withdraw",
            "--keypair",
            &env.alice_keypair.display().to_string(),
            "--to",
            &pool.bob_funding,
            "--amount",
            &spl_withdraw_amount.to_string(),
            "--mint",
            &pool.spl_mint,
            "--rpc-url",
            &env.rpc_url,
            "--indexer-url",
            &env.indexer_url,
            "--prover-url",
            &env.prover_url,
            "--airdrop-lamports",
            "2000000000",
        ],
        &cli_env,
    )?;
    assert_eq!(
        spl_token_account_amount(rpc, &pool.bob_ata)?,
        spl_withdraw_amount,
        "SPL withdraw should settle to recipient ATA"
    );

    // Pay-by-Solana-pubkey in the other direction: `wallet register` publishes
    // bob's shielded keys to the user registry, so `transfer --to <bob pubkey>`
    // resolves the recipient and stays shielded (mode=shielded) instead of
    // falling back to a public withdrawal.
    run_cli_with_env(
        &[
            "wallet",
            "register",
            "--keypair",
            &env.bob_keypair.display().to_string(),
            "--rpc-url",
            &env.rpc_url,
        ],
        &cli_env,
    )?;
    let registered_transfer_out = run_cli_with_env(
        &[
            "transfer",
            "--keypair",
            &env.alice_keypair.display().to_string(),
            "--to",
            &pool.bob_funding,
            "--amount",
            "1000000",
            "--mint",
            "SOL",
            "--rpc-url",
            &env.rpc_url,
            "--indexer-url",
            &env.indexer_url,
            "--prover-url",
            &env.prover_url,
        ],
        &cli_env,
    )?;
    assert_eq!(
        TransferOutput::parse(&registered_transfer_out)?.mode,
        TransferMode::Shielded,
        "transfer to a registered Solana pubkey must resolve via the registry and stay shielded: {registered_transfer_out}"
    );
    Ok(())
}

#[test]
#[serial]
fn wallet_cli_sol_and_spl_cycle() -> Result<()> {
    let env = phase_setup_environment()?;
    let mut rpc = SolanaRpc::new(&env.rpc_url);
    let pool = phase_create_tree_and_spl_mint(&env, &mut rpc)?;
    phase_register_wallets(&env)?;
    phase_shield_sol_deposits(&env, &pool)?;
    phase_merge_split_notes(&env)?;
    phase_spl_deposit_and_transfers(&env, &pool, &mut rpc)?;
    phase_withdraw_to_public(&env, &pool, &mut rpc)?;
    Ok(())
}
