use std::{
    collections::BTreeMap,
    env,
    fs::{self, OpenOptions},
    io::{ErrorKind, Read, Write},
    net::{SocketAddr, TcpStream},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    str::FromStr,
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use anyhow::{anyhow, bail, Context, Result};
use hmac::{Hmac, Mac};
use light_hasher::{Hasher, Poseidon};
use light_prover_client::proof::{bsb22_proof_bytes_from_json_struct, GnarkProofJson};
use num_bigint::BigUint;
use num_traits::ToPrimitive;
use p256::{
    ecdsa::{
        signature::hazmat::PrehashSigner, Signature as P256Signature, SigningKey as P256SigningKey,
    },
    SecretKey as P256SecretKey,
};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::Sha256;
use shielded_pool_program::instructions::create_pool_tree::init::pool_tree_account_size;
use solana_commitment_config::CommitmentConfig;
use solana_compute_budget_interface::ComputeBudgetInstruction;
use solana_instruction::{AccountMeta, Instruction};
use solana_keypair::{read_keypair_file, write_keypair_file, Keypair};
use solana_message::Message;
use solana_program_pack::Pack;
use solana_pubkey::Pubkey;
use solana_rpc_client::rpc_client::RpcClient;
use solana_signer::Signer;
use solana_system_interface::instruction as system_instruction;
use solana_transaction::Transaction;
use spl_token::state::Account as TokenAccount;
use zolana_interface::{
    instruction::{
        encode_instruction, tag, InputUtxoSignerIndex, TransactData, PUBLIC_AMOUNT_DEPOSIT,
        PUBLIC_AMOUNT_NONE, PUBLIC_AMOUNT_WITHDRAW,
    },
    SHIELDED_POOL_CPI_AUTHORITY, SHIELDED_POOL_PROGRAM_ID,
};

const DEFAULT_RPC_URL: &str = "http://127.0.0.1:8899";
const DEFAULT_RPC_PORT: u16 = 8899;
const DEFAULT_INDEXER_PORT: u16 = 8784;
const DEFAULT_PROVER_PORT: u16 = 3001;
const DEFAULT_LIMIT_LEDGER_SIZE: u64 = 10_000;
const DEFAULT_GOSSIP_HOST: &str = "127.0.0.1";
const READINESS_TIMEOUT: Duration = Duration::from_secs(180);
// UTXO commitment domain separator; must equal protocol::UtxoDomain (Go) and
// UTXO_DOMAIN (program). The circuit asserts every real UTXO's domain == 2.
const POCKET_UTXO_DOMAIN: u64 = 2;
const POCKET_UTXO_ROOT_HISTORY_CAPACITY: u16 = 200;
// HKDF `info` for the nullifier secret; must match the spec (spec.md "Nullifier
// Key": nullifier_secret = HKDF-SHA256(IKM=signing_sk, info="TSPP/nullifier")).
const POCKET_NULLIFIER_HKDF_INFO: &[u8] = b"TSPP/nullifier";

const SPL_NOOP_ID: &str = "noopb9bkMVfRPU8AsbpTUg8AQkHtKwMYZiFUjNRtMmV";
const LIGHT_REGISTRY_ID: &str = "Lighton6oQpVkeewmo2mcPTQQp7kYHr4fWpAgJyEmDX";

// Programs auto-loaded into `zolana test-validator`. The shielded-pool program
// will be added here once it has a stable program ID and a compiled .so on
// the fixture release.
const SYSTEM_PROGRAMS: &[(&str, &str)] = &[
    (SPL_NOOP_ID, "spl_noop.so"),
    (LIGHT_REGISTRY_ID, "light_registry.so"),
];

#[derive(Debug)]
struct ProgramSpec {
    address: String,
    path: String,
}

#[derive(Debug)]
struct UpgradeableProgramSpec {
    address: String,
    path: String,
    upgrade_authority: String,
}

#[derive(Debug)]
struct TestValidatorOptions {
    skip_indexer: bool,
    skip_prover: bool,
    stop: bool,
    skip_system_accounts: bool,
    use_surfpool: bool,
    skip_reset: bool,
    rpc_port: u16,
    indexer_port: u16,
    prover_port: u16,
    gossip_host: String,
    limit_ledger_size: u64,
    indexer_db_url: Option<String>,
    sbf_programs: Vec<ProgramSpec>,
    upgradeable_programs: Vec<UpgradeableProgramSpec>,
    account_dirs: Vec<String>,
    validator_args: Vec<String>,
    geyser_config: Option<String>,
}

impl Default for TestValidatorOptions {
    fn default() -> Self {
        Self {
            skip_indexer: false,
            skip_prover: false,
            stop: false,
            skip_system_accounts: false,
            use_surfpool: true,
            skip_reset: false,
            rpc_port: DEFAULT_RPC_PORT,
            indexer_port: DEFAULT_INDEXER_PORT,
            prover_port: DEFAULT_PROVER_PORT,
            gossip_host: DEFAULT_GOSSIP_HOST.to_string(),
            limit_ledger_size: DEFAULT_LIMIT_LEDGER_SIZE,
            indexer_db_url: None,
            sbf_programs: Vec::new(),
            upgradeable_programs: Vec::new(),
            account_dirs: Vec::new(),
            validator_args: Vec::new(),
            geyser_config: None,
        }
    }
}

#[derive(Debug)]
struct StartProverOptions {
    prover_port: u16,
    redis_url: Option<String>,
}

impl Default for StartProverOptions {
    fn default() -> Self {
        Self {
            prover_port: DEFAULT_PROVER_PORT,
            redis_url: None,
        }
    }
}

fn main() {
    if let Err(error) = run() {
        eprintln!("error: {error:#}");
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let argv0 = env::args().next().unwrap_or_default();
    let args = env::args().skip(1).collect::<Vec<_>>();
    if Path::new(&argv0).file_stem().and_then(|name| name.to_str()) == Some("pocket") {
        return run_pocket(&args);
    }

    match args.first().map(String::as_str) {
        Some("pocket") => run_pocket(&args[1..]),
        Some("test-validator")
            if args
                .get(1)
                .is_some_and(|arg| arg == "--help" || arg == "-h") =>
        {
            print_help();
            Ok(())
        }
        Some("test-validator") => run_test_validator(parse_test_validator_args(&args[1..])?),
        Some("start-prover")
            if args
                .get(1)
                .is_some_and(|arg| arg == "--help" || arg == "-h") =>
        {
            print_help();
            Ok(())
        }
        Some("start-prover") => run_start_prover(parse_start_prover_args(&args[1..])?),
        Some("--help") | Some("-h") | None => {
            print_help();
            Ok(())
        }
        Some(command) => bail!("unknown command: {command}"),
    }
}

fn parse_test_validator_args(args: &[String]) -> Result<TestValidatorOptions> {
    let mut opts = TestValidatorOptions::default();
    let mut index = 0;

    while index < args.len() {
        let arg = &args[index];
        match arg.as_str() {
            "--skip-indexer" => opts.skip_indexer = true,
            "--skip-prover" => opts.skip_prover = true,
            "--stop" => opts.stop = true,
            "--skip-system-accounts" => opts.skip_system_accounts = true,
            "--use-surfpool" => opts.use_surfpool = true,
            "--no-use-surfpool" => opts.use_surfpool = false,
            "--skip-reset" => opts.skip_reset = true,
            "--relax-indexer-version-constraint" | "--verbose" | "-v" => {}
            "--devnet" | "--mainnet" => {
                bail!("{arg} is not supported by the reduced zolana test-validator")
            }
            "--rpc-port" => opts.rpc_port = parse_next(args, &mut index, arg)?,
            "--indexer-port" => opts.indexer_port = parse_next(args, &mut index, arg)?,
            "--prover-port" => opts.prover_port = parse_next(args, &mut index, arg)?,
            "--limit-ledger-size" => opts.limit_ledger_size = parse_next(args, &mut index, arg)?,
            "--gossip-host" => opts.gossip_host = take_next(args, &mut index, arg)?,
            "--indexer-db-url" => opts.indexer_db_url = Some(take_next(args, &mut index, arg)?),
            "--geyser-config" => opts.geyser_config = Some(take_next(args, &mut index, arg)?),
            "--validator-args" => {
                let value = take_next(args, &mut index, arg)?;
                opts.validator_args
                    .extend(value.split_whitespace().map(str::to_string));
            }
            "--account-dir" => opts.account_dirs.push(take_next(args, &mut index, arg)?),
            "--sbf-program" => {
                let (address, path) = take_program(args, &mut index, arg)?;
                opts.sbf_programs.push(ProgramSpec { address, path });
            }
            "--upgradeable-program" => {
                let (address, path, upgrade_authority) =
                    take_upgradeable_program(args, &mut index, arg)?;
                opts.upgradeable_programs.push(UpgradeableProgramSpec {
                    address,
                    path,
                    upgrade_authority,
                });
            }
            _ if arg.starts_with("--rpc-port=") => {
                opts.rpc_port = parse_value(&arg["--rpc-port=".len()..], arg)?;
            }
            _ if arg.starts_with("--indexer-port=") => {
                opts.indexer_port = parse_value(&arg["--indexer-port=".len()..], arg)?;
            }
            _ if arg.starts_with("--prover-port=") => {
                opts.prover_port = parse_value(&arg["--prover-port=".len()..], arg)?;
            }
            _ if arg.starts_with("--limit-ledger-size=") => {
                opts.limit_ledger_size = parse_value(&arg["--limit-ledger-size=".len()..], arg)?;
            }
            _ if arg.starts_with("--gossip-host=") => {
                opts.gossip_host = arg["--gossip-host=".len()..].to_string();
            }
            _ if arg.starts_with("--indexer-db-url=") => {
                opts.indexer_db_url = Some(arg["--indexer-db-url=".len()..].to_string());
            }
            _ if arg.starts_with("--geyser-config=") => {
                opts.geyser_config = Some(arg["--geyser-config=".len()..].to_string());
            }
            _ if arg.starts_with("--validator-args=") => {
                let value = &arg["--validator-args=".len()..];
                opts.validator_args
                    .extend(value.split_whitespace().map(str::to_string));
            }
            _ if arg.starts_with("--account-dir=") => {
                opts.account_dirs
                    .push(arg["--account-dir=".len()..].to_string());
            }
            other => opts.validator_args.push(other.to_string()),
        }
        index += 1;
    }

    Ok(opts)
}

fn parse_start_prover_args(args: &[String]) -> Result<StartProverOptions> {
    let mut opts = StartProverOptions::default();
    let mut index = 0;

    while index < args.len() {
        let arg = &args[index];
        match arg.as_str() {
            "--prover-port" | "--port" => opts.prover_port = parse_next(args, &mut index, arg)?,
            "--redisUrl" | "--redis-url" => {
                opts.redis_url = Some(take_next(args, &mut index, arg)?)
            }
            _ if arg.starts_with("--prover-port=") => {
                opts.prover_port = parse_value(&arg["--prover-port=".len()..], arg)?;
            }
            _ if arg.starts_with("--port=") => {
                opts.prover_port = parse_value(&arg["--port=".len()..], arg)?;
            }
            _ if arg.starts_with("--redisUrl=") => {
                opts.redis_url = Some(arg["--redisUrl=".len()..].to_string());
            }
            _ if arg.starts_with("--redis-url=") => {
                opts.redis_url = Some(arg["--redis-url=".len()..].to_string());
            }
            other => bail!("unknown start-prover argument: {other}"),
        }
        index += 1;
    }

    Ok(opts)
}

fn take_next(args: &[String], index: &mut usize, flag: &str) -> Result<String> {
    *index += 1;
    args.get(*index)
        .cloned()
        .ok_or_else(|| anyhow!("missing value for {flag}"))
}

fn parse_next<T>(args: &[String], index: &mut usize, flag: &str) -> Result<T>
where
    T: std::str::FromStr,
    T::Err: std::fmt::Display,
{
    let value = take_next(args, index, flag)?;
    parse_value(&value, flag)
}

fn parse_value<T>(value: &str, flag: &str) -> Result<T>
where
    T: std::str::FromStr,
    T::Err: std::fmt::Display,
{
    value
        .parse()
        .map_err(|error| anyhow!("invalid value for {flag}: {error}"))
}

fn take_program(args: &[String], index: &mut usize, flag: &str) -> Result<(String, String)> {
    let first = take_next(args, index, flag)?;
    let parts = first.split_whitespace().collect::<Vec<_>>();
    if parts.len() == 2 {
        return Ok((parts[0].to_string(), parts[1].to_string()));
    }

    let second = take_next(args, index, flag)?;
    Ok((first, second))
}

fn take_upgradeable_program(
    args: &[String],
    index: &mut usize,
    flag: &str,
) -> Result<(String, String, String)> {
    let first = take_next(args, index, flag)?;
    let parts = first.split_whitespace().collect::<Vec<_>>();
    if parts.len() == 3 {
        return Ok((
            parts[0].to_string(),
            parts[1].to_string(),
            parts[2].to_string(),
        ));
    }

    let second = take_next(args, index, flag)?;
    let third = take_next(args, index, flag)?;
    Ok((first, second, third))
}

fn run_test_validator(opts: TestValidatorOptions) -> Result<()> {
    if opts.stop {
        stop_test_env(&opts);
        return Ok(());
    }

    println!("Starting local validator with zolana fixtures");
    kill_test_validator(opts.rpc_port);
    thread::sleep(Duration::from_secs(1));

    let mut validator = if opts.use_surfpool {
        let surfpool = find_binary(&["SURFPOOL_BIN"], &["target/tools/surfpool"], &["surfpool"])?;
        let args = surfpool_args(&opts)?;
        println!(
            "Starting surfpool: {} {}",
            surfpool.display(),
            args.join(" ")
        );
        spawn_service(&surfpool, &args, "surfpool")?
    } else {
        let validator = find_binary(&[], &[], &["solana-test-validator"])?;
        let args = solana_validator_args(&opts)?;
        println!(
            "Starting solana-test-validator: {} {}",
            validator.display(),
            args.join(" ")
        );
        spawn_service(&validator, &args, "solana-test-validator")?
    };

    wait_for_rpc_with_child(
        opts.rpc_port,
        READINESS_TIMEOUT,
        &mut validator,
        "validator",
    )
    .with_context(|| {
        format!(
            "validator RPC on port {} did not become ready",
            opts.rpc_port
        )
    })?;

    if !opts.skip_prover {
        start_prover_service(opts.prover_port, None)?;
    }

    if !opts.skip_indexer {
        let start_slot = if opts.use_surfpool {
            Some(
                rpc_u64(opts.rpc_port, "getFirstAvailableBlock")
                    .context("failed to read surfpool first available block")?,
            )
        } else {
            None
        };
        let prover_url =
            (!opts.skip_prover).then(|| format!("http://127.0.0.1:{}", opts.prover_port));
        start_indexer_service(
            opts.rpc_port,
            opts.indexer_port,
            opts.indexer_db_url.as_deref(),
            prover_url.as_deref(),
            start_slot,
        )?;
    }

    println!("Local validator environment is ready");
    std::mem::forget(validator);
    Ok(())
}

fn run_start_prover(opts: StartProverOptions) -> Result<()> {
    start_prover_service(opts.prover_port, opts.redis_url.as_deref())
}

fn surfpool_args(opts: &TestValidatorOptions) -> Result<Vec<String>> {
    let mut args = vec![
        "start".to_string(),
        "--offline".to_string(),
        "--no-tui".to_string(),
        "--no-deploy".to_string(),
        "--no-studio".to_string(),
        "--port".to_string(),
        opts.rpc_port.to_string(),
        "--host".to_string(),
        opts.gossip_host.clone(),
    ];

    add_system_program_args(&mut args)?;
    add_additional_program_args(&mut args, opts);
    add_account_dir_args(&mut args, opts)?;
    Ok(args)
}

fn solana_validator_args(opts: &TestValidatorOptions) -> Result<Vec<String>> {
    let mut args = Vec::new();
    if !opts.skip_reset {
        args.push("--reset".to_string());
    }
    args.push(format!("--limit-ledger-size={}", opts.limit_ledger_size));
    args.push(format!("--rpc-port={}", opts.rpc_port));
    args.push(format!("--bind-address={}", opts.gossip_host));
    args.push("--quiet".to_string());

    add_system_program_args(&mut args)?;
    add_additional_program_args(&mut args, opts);
    add_account_dir_args(&mut args, opts)?;

    if let Some(geyser_config) = &opts.geyser_config {
        args.push("--geyser-plugin-config".to_string());
        args.push(geyser_config.clone());
    }
    args.extend(opts.validator_args.iter().cloned());
    Ok(args)
}

fn add_system_program_args(args: &mut Vec<String>) -> Result<()> {
    for (address, name) in SYSTEM_PROGRAMS {
        args.push("--bpf-program".to_string());
        args.push((*address).to_string());
        args.push(path_string(&program_file_path(name)?)?);
    }
    Ok(())
}

fn add_additional_program_args(args: &mut Vec<String>, opts: &TestValidatorOptions) {
    for program in &opts.sbf_programs {
        args.push("--bpf-program".to_string());
        args.push(program.address.clone());
        args.push(program.path.clone());
    }

    for program in &opts.upgradeable_programs {
        args.push("--upgradeable-program".to_string());
        args.push(program.address.clone());
        args.push(program.path.clone());
        args.push(program.upgrade_authority.clone());
    }
}

fn add_account_dir_args(args: &mut Vec<String>, opts: &TestValidatorOptions) -> Result<()> {
    if !opts.skip_system_accounts {
        args.push("--account-dir".to_string());
        args.push(path_string(&accounts_dir()?)?);
    }

    for account_dir in &opts.account_dirs {
        args.push("--account-dir".to_string());
        args.push(account_dir.clone());
    }

    Ok(())
}

fn program_file_path(name: &str) -> Result<PathBuf> {
    if let Ok(dir) = env::var("LIGHT_PROTOCOL_PROGRAMS_DIR") {
        let candidate = Path::new(&dir).join(name);
        if candidate.exists() {
            return Ok(candidate);
        }
    }

    let root = project_root()?;
    let target_candidate = root.join("target/deploy").join(name);
    if target_candidate.exists() {
        return Ok(target_candidate);
    }

    if let Ok(cache) = fixtures_cache_dir() {
        let cache_candidate = cache.join("bin").join(name);
        if cache_candidate.exists() {
            return Ok(cache_candidate);
        }
    }

    bail!("missing {name}; run `just fetch-fixtures` (or `just build-light-programs` for repo-built artifacts)")
}

fn accounts_dir() -> Result<PathBuf> {
    if let Ok(dir) = env::var("LIGHT_PROTOCOL_ACCOUNTS_DIR") {
        let path = PathBuf::from(dir);
        if path.exists() {
            return Ok(path);
        }
    }

    if let Ok(cache) = fixtures_cache_dir() {
        let path = cache.join("accounts");
        if path.exists() {
            return Ok(path);
        }
    }

    bail!("missing account fixtures; run `just fetch-fixtures`")
}

fn fixtures_cache_dir() -> Result<PathBuf> {
    let tag = fs::read_to_string(project_root()?.join(".fixtures-version"))
        .context("reading .fixtures-version")?
        .trim()
        .to_string();
    if tag.is_empty() {
        bail!(".fixtures-version is empty");
    }

    let cache_root = if let Some(dir) = env::var_os("ZOLANA_CACHE_DIR") {
        PathBuf::from(dir)
    } else {
        let home = env::var("HOME").context("HOME is not set; cannot resolve fixtures cache")?;
        PathBuf::from(home).join(".cache/zolana")
    };
    Ok(cache_root.join("fixtures").join(tag))
}

fn start_prover_service(prover_port: u16, redis_url: Option<&str>) -> Result<()> {
    kill_port(prover_port);

    let prover = find_binary(
        &["PROVER_BIN", "LIGHT_PROVER_BIN"],
        &["target/prover-server"],
        &["prover-server", "light-prover"],
    )?;
    let keys_dir = prover_keys_dir()?;
    fs::create_dir_all(&keys_dir)
        .with_context(|| format!("failed to create prover keys dir {}", keys_dir.display()))?;

    let mut args = vec![
        "start".to_string(),
        "--keys-dir".to_string(),
        path_string_with_trailing_separator(&keys_dir)?,
        "--prover-address".to_string(),
        format!("0.0.0.0:{prover_port}"),
        "--auto-download".to_string(),
        "true".to_string(),
    ];

    if let Some(redis_url) = redis_url {
        args.push("--redis-url".to_string());
        args.push(redis_url.to_string());
    }

    println!("Starting prover: {} {}", prover.display(), args.join(" "));
    let mut child = spawn_service(&prover, &args, "light-prover")?;
    wait_for_http_get_with_child(
        prover_port,
        "/health",
        READINESS_TIMEOUT,
        &mut child,
        "prover",
    )
    .with_context(|| format!("prover on port {prover_port} did not become ready"))?;
    thread::sleep(Duration::from_secs(5));
    println!("Prover started successfully");
    std::mem::forget(child);
    Ok(())
}

fn start_indexer_service(
    rpc_port: u16,
    indexer_port: u16,
    db_url: Option<&str>,
    prover_url: Option<&str>,
    start_slot: Option<u64>,
) -> Result<()> {
    kill_name("photon");
    kill_port(indexer_port);

    let photon = find_binary(&["PHOTON_BIN"], &["target/debug/photon"], &["photon"])?;
    let mut args = vec![
        "--port".to_string(),
        indexer_port.to_string(),
        "--rpc-url".to_string(),
        format!("http://127.0.0.1:{rpc_port}"),
    ];

    if let Some(db_url) = db_url {
        args.push("--db-url".to_string());
        args.push(db_url.to_string());
    }
    if let Some(prover_url) = prover_url {
        args.push("--prover-url".to_string());
        args.push(prover_url.to_string());
    }
    if let Some(start_slot) = start_slot {
        args.push("--start-slot".to_string());
        args.push(start_slot.to_string());
    }

    println!("Starting Photon: {} {}", photon.display(), args.join(" "));
    let mut child = spawn_service(&photon, &args, "photon")?;
    wait_for_photon_health_with_child(indexer_port, READINESS_TIMEOUT, &mut child)
        .with_context(|| format!("Photon on port {indexer_port} did not become ready"))?;
    println!("Photon started successfully");
    std::mem::forget(child);
    Ok(())
}

fn spawn_service(binary: &Path, args: &[String], log_name: &str) -> Result<Child> {
    fs::create_dir_all("test-ledger").context("failed to create test-ledger log directory")?;
    let log_path = Path::new("test-ledger").join(format!("{log_name}.log"));
    let log = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&log_path)
        .with_context(|| format!("failed to open {}", log_path.display()))?;
    let stderr = log
        .try_clone()
        .with_context(|| format!("failed to clone {}", log_path.display()))?;

    Command::new(binary)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::from(log))
        .stderr(Stdio::from(stderr))
        .spawn()
        .with_context(|| format!("failed to spawn {}", binary.display()))
}

fn wait_for_rpc_with_child(
    port: u16,
    timeout: Duration,
    child: &mut Child,
    label: &str,
) -> Result<()> {
    wait_until_with_child(timeout, child, label, || rpc_health(port))
}

fn wait_for_http_get_with_child(
    port: u16,
    path: &str,
    timeout: Duration,
    child: &mut Child,
    label: &str,
) -> Result<()> {
    wait_until_with_child(timeout, child, label, || {
        http_get_status(port, path)
            .map(|status| (200..300).contains(&status))
            .unwrap_or(false)
    })
}

fn wait_for_photon_health_with_child(
    port: u16,
    timeout: Duration,
    child: &mut Child,
) -> Result<()> {
    wait_until_with_child(timeout, child, "Photon", || photon_health(port))
}

fn wait_until_with_child<F>(
    timeout: Duration,
    child: &mut Child,
    label: &str,
    mut ready: F,
) -> Result<()>
where
    F: FnMut() -> bool,
{
    let start = Instant::now();
    while start.elapsed() < timeout {
        if let Some(status) = child.try_wait()? {
            bail!("{label} exited early with status {status}");
        }
        if ready() {
            return Ok(());
        }
        thread::sleep(Duration::from_secs(1));
    }
    bail!("timed out after {} seconds", timeout.as_secs())
}

fn rpc_health(port: u16) -> bool {
    rpc_request(port, "getHealth")
        .ok()
        .and_then(|value| value.get("result").cloned())
        .and_then(|value| value.as_str().map(str::to_string))
        .as_deref()
        == Some("ok")
}

fn photon_health(port: u16) -> bool {
    json_rpc_request(port, "/getIndexerHealth", "getIndexerHealth")
        .map(|value| value.get("result").and_then(Value::as_str) == Some("ok"))
        .unwrap_or(false)
}

fn rpc_u64(port: u16, method: &str) -> Result<u64> {
    let value = rpc_request(port, method)?;
    value
        .get("result")
        .and_then(Value::as_u64)
        .ok_or_else(|| anyhow!("JSON-RPC method {method} did not return a u64 result: {value}"))
}

fn rpc_request(port: u16, method: &str) -> Result<Value> {
    json_rpc_request(port, "/", method)
}

fn json_rpc_request(port: u16, path: &str, method: &str) -> Result<Value> {
    let body = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": method,
        "params": [],
    })
    .to_string();
    let response = http_request(
        port,
        "POST",
        path,
        Some(("application/json", body.as_bytes())),
    )?;
    let status = http_status(&response).ok_or_else(|| anyhow!("invalid HTTP response"))?;
    if !(200..300).contains(&status) {
        bail!("JSON-RPC HTTP status {status}");
    }
    serde_json::from_str(http_body(&response)).context("failed to parse JSON-RPC response")
}

fn http_get_status(port: u16, path: &str) -> Result<u16> {
    let response = http_request(port, "GET", path, None)?;
    http_status(&response).ok_or_else(|| anyhow!("invalid HTTP response"))
}

fn http_request(
    port: u16,
    method: &str,
    path: &str,
    body: Option<(&str, &[u8])>,
) -> Result<String> {
    let address = SocketAddr::from(([127, 0, 0, 1], port));
    let mut stream = TcpStream::connect_timeout(&address, Duration::from_secs(1))?;
    stream.set_read_timeout(Some(Duration::from_secs(2)))?;
    stream.set_write_timeout(Some(Duration::from_secs(2)))?;

    let body_len = body.map(|(_, body)| body.len()).unwrap_or(0);
    let content_type = body.map(|(content_type, _)| content_type);
    let mut request = format!(
        "{method} {path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nConnection: close\r\nContent-Length: {body_len}\r\n"
    );
    if let Some(content_type) = content_type {
        request.push_str(&format!("Content-Type: {content_type}\r\n"));
    }
    request.push_str("\r\n");

    stream.write_all(request.as_bytes())?;
    if let Some((_, body)) = body {
        stream.write_all(body)?;
    }

    let mut response = Vec::new();
    let mut buf = [0_u8; 4096];
    loop {
        match stream.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => response.extend_from_slice(&buf[..n]),
            Err(error)
                if matches!(error.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut)
                    && !response.is_empty() =>
            {
                break;
            }
            Err(error) => return Err(error.into()),
        }
    }

    String::from_utf8(response).context("HTTP response was not UTF-8")
}

fn http_status(response: &str) -> Option<u16> {
    response
        .lines()
        .next()?
        .split_whitespace()
        .nth(1)?
        .parse()
        .ok()
}

fn http_body(response: &str) -> &str {
    response.split_once("\r\n\r\n").map_or("", |(_, body)| body)
}

fn stop_test_env(opts: &TestValidatorOptions) {
    if !opts.skip_indexer {
        kill_name("photon");
        kill_port(opts.indexer_port);
    }
    if !opts.skip_prover {
        kill_name("light-prover");
        kill_name("prover-server");
        kill_port(opts.prover_port);
    }
    kill_test_validator(opts.rpc_port);
}

fn kill_test_validator(rpc_port: u16) {
    kill_name("solana-test-validator");
    kill_name("surfpool");
    kill_port(rpc_port);
}

fn kill_name(name: &str) {
    let _ = Command::new("pkill")
        .args(["-x", name])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
}

fn kill_port(port: u16) {
    let output = Command::new("lsof").arg(format!("-ti:{port}")).output();
    let Ok(output) = output else {
        return;
    };

    for pid in String::from_utf8_lossy(&output.stdout).lines() {
        if !pid.trim().is_empty() {
            let _ = Command::new("kill")
                .args(["-9", pid.trim()])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status();
        }
    }
}

fn find_binary(
    env_vars: &[&str],
    repo_relative_candidates: &[&str],
    path_candidates: &[&str],
) -> Result<PathBuf> {
    for env_var in env_vars {
        if let Ok(value) = env::var(env_var) {
            let value = value.trim();
            if !value.is_empty() {
                let path = PathBuf::from(value);
                if path.is_file() {
                    return Ok(path);
                }
                bail!(
                    "{env_var} points to {}, but that file does not exist",
                    path.display()
                );
            }
        }
    }

    if let Ok(root) = project_root() {
        for candidate in repo_relative_candidates {
            let path = root.join(candidate);
            if path.is_file() {
                return Ok(path);
            }
        }
    }

    for candidate in path_candidates {
        if let Some(path) = find_in_path(candidate) {
            return Ok(path);
        }
    }

    let hints = env_vars
        .iter()
        .chain(path_candidates.iter())
        .copied()
        .collect::<Vec<_>>()
        .join(", ");
    bail!("failed to find required binary ({hints})")
}

fn find_in_path(binary: &str) -> Option<PathBuf> {
    let paths = env::var_os("PATH")?;
    env::split_paths(&paths)
        .map(|dir| dir.join(binary))
        .find(|candidate| candidate.is_file())
}

fn project_root() -> Result<PathBuf> {
    let output = Command::new("git")
        .args(["rev-parse", "--show-toplevel"])
        .output()
        .context("failed to run git rev-parse --show-toplevel")?;
    if !output.status.success() {
        bail!("git rev-parse --show-toplevel failed");
    }
    let root = String::from_utf8(output.stdout)?.trim().to_string();
    Ok(PathBuf::from(root))
}

fn prover_keys_dir() -> Result<PathBuf> {
    if let Ok(path) = env::var("LIGHT_PROVER_KEYS_DIR") {
        return Ok(PathBuf::from(path));
    }

    let home = env::var("HOME").context("HOME is not set")?;
    Ok(Path::new(&home).join(".config/light/proving-keys"))
}

fn path_string(path: &Path) -> Result<String> {
    path.to_str()
        .map(str::to_string)
        .ok_or_else(|| anyhow!("path is not valid UTF-8: {}", path.display()))
}

fn path_string_with_trailing_separator(path: &Path) -> Result<String> {
    let mut value = path_string(path)?;
    if !value.ends_with(std::path::MAIN_SEPARATOR) {
        value.push(std::path::MAIN_SEPARATOR);
    }
    Ok(value)
}

#[derive(Debug, Default)]
struct PocketCreateWalletOptions {
    output: PathBuf,
    force: bool,
    rpc_url: String,
    airdrop_lamports: Option<u64>,
}

#[derive(Debug, Default)]
struct PocketCreateShieldedWalletOptions {
    output: PathBuf,
    force: bool,
}

#[derive(Debug, Default)]
struct PocketBalanceOptions {
    rpc_url: String,
    wallet: Option<PathBuf>,
    pubkey: Option<Pubkey>,
    token_account: Option<Pubkey>,
    state: Option<PathBuf>,
    asset_id: Option<String>,
}

#[derive(Debug, Default)]
struct PocketInitPoolTreeOptions {
    rpc_url: String,
    payer: PathBuf,
    output: PathBuf,
    force: bool,
    pubkey_only: bool,
}

#[derive(Debug, Default)]
struct PocketSubmitOptions {
    rpc_url: String,
    payer: PathBuf,
    tree: Pubkey,
    bundle: Option<PathBuf>,
    tx_name: String,
    state: Option<PathBuf>,
    owner_p256_wallet: Option<PathBuf>,
    recipient_wallet: Option<PathBuf>,
    recipient_p256_wallet: Option<PathBuf>,
    recipient_state: Option<PathBuf>,
    amount: Option<u64>,
    change_amount: Option<u64>,
    relayer_fee: u16,
    asset_id: Option<String>,
    spl_asset_pubkey: Option<Pubkey>,
    keys_file: Option<PathBuf>,
    prover_bin: Option<PathBuf>,
    output_proof_bundle: Option<PathBuf>,
    user_sol_account: Option<Pubkey>,
    user_spl_token: Option<Pubkey>,
    spl_vault: Option<Pubkey>,
    spl_asset_registry: Option<Pubkey>,
    token_program: Pubkey,
}

impl PocketSubmitOptions {
    fn has_spl_settlement(&self) -> bool {
        self.user_spl_token.is_some()
            || self.spl_vault.is_some()
            || self.spl_asset_registry.is_some()
    }
}

#[derive(Clone, Debug, Deserialize)]
struct PocketProofBundle {
    solana_signer_pubkey: String,
    #[serde(default, alias = "fixtures")]
    transactions: Vec<PocketProofTx>,
}

#[derive(Clone, Debug, Deserialize)]
struct PocketProofTx {
    name: String,
    expiry_unix_ts: u64,
    sender_view_tag: String,
    proof: serde_json::Value,
    relayer_fee: u16,
    nullifiers: Vec<String>,
    output_utxo_hashes: Vec<String>,
    utxo_tree_root_index: Vec<u16>,
    nullifier_tree_root_index: Vec<u16>,
    private_tx_hash: String,
    public_amount_mode: u8,
    public_sol_amount: Option<u64>,
    public_spl_amount: Option<u64>,
    #[serde(default)]
    public_spl_asset_pubkey: String,
    encrypted_utxos: String,
    #[serde(default)]
    output_utxos: Vec<PocketProofOutputUtxo>,
    #[serde(default)]
    user_sol_account: String,
    user_spl_token_account: String,
    spl_token_interface: String,
    #[serde(default)]
    solana_owner_input_indices: Option<Vec<u8>>,
    // Ownership rail (P256-capable vs Solana-only circuit). Defaults to the
    // Solana rail for older bundles that predate the field.
    #[serde(default)]
    requires_p256: bool,
}

#[derive(Clone, Debug, Deserialize)]
struct PocketProofOutputUtxo {
    utxo: PocketUtxo,
    hash: String,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
struct PocketState {
    #[serde(default)]
    utxo_root_index: u16,
    #[serde(default)]
    next_leaf_index: u64,
    #[serde(default)]
    known_leaves: Vec<PocketKnownLeaf>,
    #[serde(default)]
    notes: Vec<PocketNote>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct PocketKnownLeaf {
    index: u64,
    hash: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct PocketNote {
    id: String,
    owner_pubkey: String,
    leaf_index: u64,
    utxo: PocketUtxo,
    nullifier_secret: String,
    hash: String,
    #[serde(default)]
    spent: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct PocketUtxo {
    domain: String,
    owner: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    owner_solana_pubkey: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    owner_p256_pubkey: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    owner_nullifier_secret: String,
    asset_id: String,
    asset_amount: String,
    blinding: String,
    data_hash: String,
    #[serde(default, alias = "policy_data")]
    zone_data_hash: String,
    #[serde(default, alias = "policy_program_id")]
    zone_program_id: String,
}

#[derive(Clone, Debug, Serialize)]
struct PocketProofRequest {
    solana_signer_pubkey: String,
    transactions: Vec<PocketProofRequestTx>,
}

#[derive(Clone, Debug, Serialize)]
struct PocketProofRequestTx {
    name: String,
    instruction_discriminator: u8,
    expiry_unix_ts: u64,
    sender_view_tag: String,
    relayer_fee: u16,
    public_amount_mode: u8,
    public_sol_amount: Option<u64>,
    public_spl_amount: Option<u64>,
    public_spl_asset_pubkey: String,
    encrypted_utxos: String,
    user_sol_account: String,
    user_spl_token_account: String,
    spl_token_interface: String,
    state_entries: Vec<PocketStateEntry>,
    inputs: Vec<PocketProofInput>,
    outputs: Vec<PocketUtxo>,
    utxo_tree_root_index: Vec<u16>,
    nullifier_tree_root_index: Vec<u16>,
    program_id_hashchain: String,
    data_hash: String,
    zone_data_hash: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    p256_owner_pubkey: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    p256_signature_r: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    p256_signature_s: String,
}

#[derive(Clone, Debug, Deserialize)]
struct PocketSigningPayloadBundle {
    transactions: Vec<PocketSigningPayloadTx>,
}

#[derive(Clone, Debug, Deserialize)]
struct PocketSigningPayloadTx {
    name: String,
    private_tx_hash: String,
    requires_p256_signature: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct PocketP256Wallet {
    version: u8,
    scheme: String,
    p256_secret_key: String,
    p256_public_key: String,
    nullifier_secret: String,
}

#[derive(Clone, Debug, Serialize)]
struct PocketStateEntry {
    index: u64,
    hash: String,
}

#[derive(Clone, Debug, Serialize)]
struct PocketProofInput {
    utxo: PocketUtxo,
    leaf_index: u64,
    nullifier_secret: String,
}

#[derive(Debug)]
struct PocketDirectProof {
    bundle_path: PathBuf,
    tx_name: String,
    state_updates: PocketStateUpdates,
}

#[derive(Debug, Default)]
struct PocketStateUpdates {
    sender_state_path: Option<PathBuf>,
    sender_state: PocketState,
    recipient_state_path: Option<PathBuf>,
    recipient_state: Option<PocketState>,
}

fn run_pocket(args: &[String]) -> Result<()> {
    match args.first().map(String::as_str) {
        Some("create-wallet") => pocket_create_wallet(parse_pocket_create_wallet_args(&args[1..])?),
        Some("create-shielded-wallet") => {
            pocket_create_shielded_wallet(parse_pocket_create_shielded_wallet_args(&args[1..])?)
        }
        Some("balance") => pocket_balance(parse_pocket_balance_args(&args[1..])?),
        Some("init-pool-tree") => {
            pocket_init_pool_tree(parse_pocket_init_pool_tree_args(&args[1..])?)
        }
        Some("shield") => pocket_submit("shield", parse_pocket_submit_args("shield", &args[1..])?),
        Some("transfer") => pocket_submit(
            "transfer",
            parse_pocket_submit_args("transfer", &args[1..])?,
        ),
        Some("unshield") => pocket_submit(
            "unshield",
            parse_pocket_submit_args("unshield", &args[1..])?,
        ),
        Some("--help") | Some("-h") | None => {
            print_pocket_help();
            Ok(())
        }
        Some(command) => bail!("unknown pocket command: {command}"),
    }
}

fn parse_pocket_create_shielded_wallet_args(
    args: &[String],
) -> Result<PocketCreateShieldedWalletOptions> {
    let mut opts = PocketCreateShieldedWalletOptions::default();
    let mut index = 0;

    while index < args.len() {
        let arg = &args[index];
        match arg.as_str() {
            "--output" | "-o" => opts.output = PathBuf::from(take_next(args, &mut index, arg)?),
            "--force" => opts.force = true,
            _ if arg.starts_with("--output=") => {
                opts.output = PathBuf::from(&arg["--output=".len()..]);
            }
            other => bail!("unknown create-shielded-wallet argument: {other}"),
        }
        index += 1;
    }
    if opts.output.as_os_str().is_empty() {
        bail!("create-shielded-wallet requires --output");
    }
    Ok(opts)
}

fn parse_pocket_create_wallet_args(args: &[String]) -> Result<PocketCreateWalletOptions> {
    let mut opts = PocketCreateWalletOptions {
        rpc_url: DEFAULT_RPC_URL.to_string(),
        ..PocketCreateWalletOptions::default()
    };
    let mut index = 0;

    while index < args.len() {
        let arg = &args[index];
        match arg.as_str() {
            "--output" | "-o" => opts.output = PathBuf::from(take_next(args, &mut index, arg)?),
            "--force" => opts.force = true,
            "--rpc-url" => opts.rpc_url = take_next(args, &mut index, arg)?,
            "--airdrop-lamports" => {
                opts.airdrop_lamports = Some(parse_next(args, &mut index, arg)?)
            }
            _ if arg.starts_with("--output=") => {
                opts.output = PathBuf::from(&arg["--output=".len()..]);
            }
            _ if arg.starts_with("--rpc-url=") => {
                opts.rpc_url = arg["--rpc-url=".len()..].to_string();
            }
            _ if arg.starts_with("--airdrop-lamports=") => {
                opts.airdrop_lamports =
                    Some(parse_value(&arg["--airdrop-lamports=".len()..], arg)?);
            }
            other => bail!("unknown create-wallet argument: {other}"),
        }
        index += 1;
    }
    if opts.output.as_os_str().is_empty() {
        bail!("create-wallet requires --output");
    }
    Ok(opts)
}

fn parse_pocket_balance_args(args: &[String]) -> Result<PocketBalanceOptions> {
    let mut opts = PocketBalanceOptions {
        rpc_url: DEFAULT_RPC_URL.to_string(),
        ..PocketBalanceOptions::default()
    };
    let mut index = 0;

    while index < args.len() {
        let arg = &args[index];
        match arg.as_str() {
            "--rpc-url" => opts.rpc_url = take_next(args, &mut index, arg)?,
            "--wallet" => opts.wallet = Some(PathBuf::from(take_next(args, &mut index, arg)?)),
            "--pubkey" => opts.pubkey = Some(parse_pubkey(&take_next(args, &mut index, arg)?)?),
            "--token-account" => {
                opts.token_account = Some(parse_pubkey(&take_next(args, &mut index, arg)?)?)
            }
            "--state" => opts.state = Some(PathBuf::from(take_next(args, &mut index, arg)?)),
            "--asset-id" => opts.asset_id = Some(take_next(args, &mut index, arg)?),
            _ if arg.starts_with("--rpc-url=") => {
                opts.rpc_url = arg["--rpc-url=".len()..].to_string();
            }
            _ if arg.starts_with("--wallet=") => {
                opts.wallet = Some(PathBuf::from(&arg["--wallet=".len()..]));
            }
            _ if arg.starts_with("--pubkey=") => {
                opts.pubkey = Some(parse_pubkey(&arg["--pubkey=".len()..])?);
            }
            _ if arg.starts_with("--token-account=") => {
                opts.token_account = Some(parse_pubkey(&arg["--token-account=".len()..])?);
            }
            _ if arg.starts_with("--state=") => {
                opts.state = Some(PathBuf::from(&arg["--state=".len()..]));
            }
            _ if arg.starts_with("--asset-id=") => {
                opts.asset_id = Some(arg["--asset-id=".len()..].to_string());
            }
            other => bail!("unknown balance argument: {other}"),
        }
        index += 1;
    }
    if opts.wallet.is_none()
        && opts.pubkey.is_none()
        && opts.token_account.is_none()
        && opts.state.is_none()
    {
        bail!("balance requires --wallet, --pubkey, --token-account, or --state");
    }
    Ok(opts)
}

fn parse_pocket_init_pool_tree_args(args: &[String]) -> Result<PocketInitPoolTreeOptions> {
    let mut opts = PocketInitPoolTreeOptions {
        rpc_url: DEFAULT_RPC_URL.to_string(),
        ..PocketInitPoolTreeOptions::default()
    };
    let mut index = 0;

    while index < args.len() {
        let arg = &args[index];
        match arg.as_str() {
            "--rpc-url" => opts.rpc_url = take_next(args, &mut index, arg)?,
            "--payer" => opts.payer = PathBuf::from(take_next(args, &mut index, arg)?),
            "--output" | "-o" => opts.output = PathBuf::from(take_next(args, &mut index, arg)?),
            "--force" => opts.force = true,
            "--pubkey-only" => opts.pubkey_only = true,
            _ if arg.starts_with("--rpc-url=") => {
                opts.rpc_url = arg["--rpc-url=".len()..].to_string();
            }
            _ if arg.starts_with("--payer=") => {
                opts.payer = PathBuf::from(&arg["--payer=".len()..]);
            }
            _ if arg.starts_with("--output=") => {
                opts.output = PathBuf::from(&arg["--output=".len()..]);
            }
            other => bail!("unknown init-pool-tree argument: {other}"),
        }
        index += 1;
    }
    if opts.payer.as_os_str().is_empty() {
        bail!("init-pool-tree requires --payer");
    }
    if opts.output.as_os_str().is_empty() {
        bail!("init-pool-tree requires --output");
    }
    Ok(opts)
}

fn parse_pocket_submit_args(default_tx_name: &str, args: &[String]) -> Result<PocketSubmitOptions> {
    let mut opts = PocketSubmitOptions {
        rpc_url: DEFAULT_RPC_URL.to_string(),
        tx_name: default_tx_name.to_string(),
        token_program: spl_token::id(),
        ..PocketSubmitOptions::default()
    };
    let mut index = 0;

    while index < args.len() {
        let arg = &args[index];
        match arg.as_str() {
            "--rpc-url" => opts.rpc_url = take_next(args, &mut index, arg)?,
            "--payer" => opts.payer = PathBuf::from(take_next(args, &mut index, arg)?),
            "--tree" => opts.tree = parse_pubkey(&take_next(args, &mut index, arg)?)?,
            "--proof-bundle" | "--bundle" => {
                opts.bundle = Some(PathBuf::from(take_next(args, &mut index, arg)?))
            }
            "--tx" => opts.tx_name = take_next(args, &mut index, arg)?,
            "--state" => opts.state = Some(PathBuf::from(take_next(args, &mut index, arg)?)),
            "--owner-p256-wallet" => {
                opts.owner_p256_wallet = Some(PathBuf::from(take_next(args, &mut index, arg)?))
            }
            "--recipient-wallet" => {
                opts.recipient_wallet = Some(PathBuf::from(take_next(args, &mut index, arg)?))
            }
            "--recipient-p256-wallet" => {
                opts.recipient_p256_wallet = Some(PathBuf::from(take_next(args, &mut index, arg)?))
            }
            "--recipient-state" => {
                opts.recipient_state = Some(PathBuf::from(take_next(args, &mut index, arg)?))
            }
            "--amount" => opts.amount = Some(parse_next(args, &mut index, arg)?),
            "--change-amount" => opts.change_amount = Some(parse_next(args, &mut index, arg)?),
            "--relayer-fee" => opts.relayer_fee = parse_next(args, &mut index, arg)?,
            "--asset-id" => opts.asset_id = Some(take_next(args, &mut index, arg)?),
            "--asset-pubkey" | "--spl-mint" | "--public-spl-asset-pubkey" => {
                opts.spl_asset_pubkey = Some(parse_pubkey(&take_next(args, &mut index, arg)?)?)
            }
            "--keys-file" => {
                opts.keys_file = Some(PathBuf::from(take_next(args, &mut index, arg)?))
            }
            "--prover-bin" => {
                opts.prover_bin = Some(PathBuf::from(take_next(args, &mut index, arg)?))
            }
            "--output-proof-bundle" => {
                opts.output_proof_bundle = Some(PathBuf::from(take_next(args, &mut index, arg)?))
            }
            "--user-sol-account" => {
                opts.user_sol_account = Some(parse_pubkey(&take_next(args, &mut index, arg)?)?)
            }
            "--user-spl-token" => {
                opts.user_spl_token = Some(parse_pubkey(&take_next(args, &mut index, arg)?)?)
            }
            "--spl-vault" => {
                opts.spl_vault = Some(parse_pubkey(&take_next(args, &mut index, arg)?)?)
            }
            "--spl-asset-registry" => {
                opts.spl_asset_registry = Some(parse_pubkey(&take_next(args, &mut index, arg)?)?)
            }
            "--token-program" => {
                opts.token_program = parse_pubkey(&take_next(args, &mut index, arg)?)?
            }
            _ if arg.starts_with("--rpc-url=") => {
                opts.rpc_url = arg["--rpc-url=".len()..].to_string();
            }
            _ if arg.starts_with("--payer=") => {
                opts.payer = PathBuf::from(&arg["--payer=".len()..]);
            }
            _ if arg.starts_with("--tree=") => {
                opts.tree = parse_pubkey(&arg["--tree=".len()..])?;
            }
            _ if arg.starts_with("--proof-bundle=") => {
                opts.bundle = Some(PathBuf::from(&arg["--proof-bundle=".len()..]));
            }
            _ if arg.starts_with("--bundle=") => {
                opts.bundle = Some(PathBuf::from(&arg["--bundle=".len()..]));
            }
            _ if arg.starts_with("--tx=") => {
                opts.tx_name = arg["--tx=".len()..].to_string();
            }
            _ if arg.starts_with("--state=") => {
                opts.state = Some(PathBuf::from(&arg["--state=".len()..]));
            }
            _ if arg.starts_with("--owner-p256-wallet=") => {
                opts.owner_p256_wallet = Some(PathBuf::from(&arg["--owner-p256-wallet=".len()..]));
            }
            _ if arg.starts_with("--recipient-wallet=") => {
                opts.recipient_wallet = Some(PathBuf::from(&arg["--recipient-wallet=".len()..]));
            }
            _ if arg.starts_with("--recipient-p256-wallet=") => {
                opts.recipient_p256_wallet =
                    Some(PathBuf::from(&arg["--recipient-p256-wallet=".len()..]));
            }
            _ if arg.starts_with("--recipient-state=") => {
                opts.recipient_state = Some(PathBuf::from(&arg["--recipient-state=".len()..]));
            }
            _ if arg.starts_with("--amount=") => {
                opts.amount = Some(parse_value(&arg["--amount=".len()..], arg)?);
            }
            _ if arg.starts_with("--change-amount=") => {
                opts.change_amount = Some(parse_value(&arg["--change-amount=".len()..], arg)?);
            }
            _ if arg.starts_with("--relayer-fee=") => {
                opts.relayer_fee = parse_value(&arg["--relayer-fee=".len()..], arg)?;
            }
            _ if arg.starts_with("--asset-id=") => {
                opts.asset_id = Some(arg["--asset-id=".len()..].to_string());
            }
            _ if arg.starts_with("--asset-pubkey=") => {
                opts.spl_asset_pubkey = Some(parse_pubkey(&arg["--asset-pubkey=".len()..])?);
            }
            _ if arg.starts_with("--spl-mint=") => {
                opts.spl_asset_pubkey = Some(parse_pubkey(&arg["--spl-mint=".len()..])?);
            }
            _ if arg.starts_with("--public-spl-asset-pubkey=") => {
                opts.spl_asset_pubkey =
                    Some(parse_pubkey(&arg["--public-spl-asset-pubkey=".len()..])?);
            }
            _ if arg.starts_with("--keys-file=") => {
                opts.keys_file = Some(PathBuf::from(&arg["--keys-file=".len()..]));
            }
            _ if arg.starts_with("--prover-bin=") => {
                opts.prover_bin = Some(PathBuf::from(&arg["--prover-bin=".len()..]));
            }
            _ if arg.starts_with("--output-proof-bundle=") => {
                opts.output_proof_bundle =
                    Some(PathBuf::from(&arg["--output-proof-bundle=".len()..]));
            }
            _ if arg.starts_with("--user-sol-account=") => {
                opts.user_sol_account = Some(parse_pubkey(&arg["--user-sol-account=".len()..])?);
            }
            _ if arg.starts_with("--user-spl-token=") => {
                opts.user_spl_token = Some(parse_pubkey(&arg["--user-spl-token=".len()..])?);
            }
            _ if arg.starts_with("--spl-vault=") => {
                opts.spl_vault = Some(parse_pubkey(&arg["--spl-vault=".len()..])?);
            }
            _ if arg.starts_with("--spl-asset-registry=") => {
                opts.spl_asset_registry =
                    Some(parse_pubkey(&arg["--spl-asset-registry=".len()..])?);
            }
            _ if arg.starts_with("--token-program=") => {
                opts.token_program = parse_pubkey(&arg["--token-program=".len()..])?;
            }
            other => bail!("unknown {default_tx_name} argument: {other}"),
        }
        index += 1;
    }
    if opts.payer.as_os_str().is_empty() {
        bail!("{default_tx_name} requires --payer");
    }
    if opts.tree == Pubkey::default() {
        bail!("{default_tx_name} requires --tree");
    }
    if opts.bundle.is_none() {
        if opts.state.is_none() {
            bail!("{default_tx_name} direct proving requires --state");
        }
        if opts.keys_file.is_none() {
            bail!("{default_tx_name} direct proving requires --keys-file");
        }
        if opts.prover_bin.is_none() {
            bail!("{default_tx_name} direct proving requires --prover-bin");
        }
        if opts.amount.is_none() {
            bail!("{default_tx_name} direct proving requires --amount");
        }
        if default_tx_name != "transfer"
            && opts.spl_asset_pubkey.is_none()
            && opts.has_spl_settlement()
        {
            bail!("{default_tx_name} direct proving requires --asset-pubkey/--spl-mint for SPL settlement");
        }
        if default_tx_name == "transfer" {
            if opts.recipient_state.is_none()
                || (opts.recipient_wallet.is_none() && opts.recipient_p256_wallet.is_none())
            {
                bail!("transfer direct proving requires --recipient-state and one of --recipient-wallet or --recipient-p256-wallet");
            }
            if opts.recipient_wallet.is_some() && opts.recipient_p256_wallet.is_some() {
                bail!("transfer direct proving accepts only one of --recipient-wallet or --recipient-p256-wallet");
            }
        }
    }
    Ok(opts)
}

fn pocket_create_wallet(opts: PocketCreateWalletOptions) -> Result<()> {
    if opts.output.exists() && !opts.force {
        bail!(
            "{} already exists; pass --force to overwrite",
            opts.output.display()
        );
    }
    if let Some(parent) = opts
        .output
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }

    let keypair = Keypair::new();
    write_keypair_file(&keypair, &opts.output)
        .map_err(|error| anyhow!("write keypair {}: {error}", opts.output.display()))?;

    let mut out = json!({
        "pubkey": keypair.pubkey().to_string(),
        "keypair": opts.output,
    });
    if let Some(lamports) = opts.airdrop_lamports {
        let client = pocket_rpc_client(&opts.rpc_url);
        let signature = client
            .request_airdrop(&keypair.pubkey(), lamports)
            .context("request airdrop")?;
        let confirmed = client
            .confirm_transaction(&signature)
            .context("confirm airdrop")?;
        out["airdrop_signature"] = json!(signature.to_string());
        out["airdrop_confirmed"] = json!(confirmed);
    }
    println!("{}", serde_json::to_string_pretty(&out)?);
    Ok(())
}

fn pocket_create_shielded_wallet(opts: PocketCreateShieldedWalletOptions) -> Result<()> {
    if opts.output.exists() && !opts.force {
        bail!(
            "{} already exists; pass --force to overwrite",
            opts.output.display()
        );
    }
    let signing_key = random_p256_signing_key()?;
    let public_key = signing_key.verifying_key().to_encoded_point(true);
    let nullifier_secret = p256_nullifier_secret_hex(&signing_key)?;
    let wallet = PocketP256Wallet {
        version: 1,
        scheme: "p256".to_string(),
        p256_secret_key: hex::encode(signing_key.to_bytes()),
        p256_public_key: hex::encode(public_key.as_bytes()),
        nullifier_secret,
    };
    write_json_file(&opts.output, &wallet)?;
    println!(
        "{}",
        serde_json::to_string_pretty(&json!({
            "wallet": opts.output,
            "scheme": wallet.scheme,
            "p256_public_key": wallet.p256_public_key,
        }))?
    );
    Ok(())
}

fn pocket_balance(opts: PocketBalanceOptions) -> Result<()> {
    if let Some(state_path) = opts.state {
        let state = read_pocket_state(&state_path)?;
        let asset_id = opts
            .asset_id
            .as_deref()
            .map(normalize_pocket_field)
            .transpose()?;
        let mut private_amount = 0u64;
        let mut note_count = 0usize;
        for note in state.notes.iter().filter(|note| !note.spent) {
            let note_asset_id = pocket_note_asset_id(note)?;
            if asset_id
                .as_deref()
                .is_some_and(|asset_id| asset_id != note_asset_id)
            {
                continue;
            }
            private_amount = private_amount
                .checked_add(pocket_note_amount(note)?)
                .ok_or_else(|| anyhow!("private balance overflow"))?;
            note_count += 1;
        }
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "state": state_path,
                "asset_id": asset_id,
                "private_amount": private_amount,
                "unspent_notes": note_count,
            }))?
        );
        return Ok(());
    }

    let client = pocket_rpc_client(&opts.rpc_url);
    if let Some(token_account) = opts.token_account {
        let account = client
            .get_account(&token_account)
            .with_context(|| format!("fetch token account {token_account}"))?;
        let token = TokenAccount::unpack(&account.data).context("decode SPL token account")?;
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "token_account": token_account.to_string(),
                "mint": token.mint.to_string(),
                "owner": token.owner.to_string(),
                "amount": token.amount,
            }))?
        );
        return Ok(());
    }

    let pubkey = if let Some(pubkey) = opts.pubkey {
        pubkey
    } else {
        read_keypair_file(opts.wallet.expect("checked above"))
            .map_err(|error| anyhow!("read wallet keypair: {error}"))?
            .pubkey()
    };
    let account = client
        .get_account(&pubkey)
        .with_context(|| format!("fetch account {pubkey}"))?;
    println!(
        "{}",
        serde_json::to_string_pretty(&json!({
            "pubkey": pubkey.to_string(),
            "lamports": account.lamports,
        }))?
    );
    Ok(())
}

fn pocket_init_pool_tree(opts: PocketInitPoolTreeOptions) -> Result<()> {
    if opts.output.exists() && !opts.force {
        bail!(
            "{} already exists; pass --force to overwrite",
            opts.output.display()
        );
    }
    if let Some(parent) = opts
        .output
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }

    let payer = read_keypair_file(&opts.payer)
        .map_err(|error| anyhow!("read payer keypair {}: {error}", opts.payer.display()))?;
    let tree = Keypair::new();
    let program_id = Pubkey::new_from_array(SHIELDED_POOL_PROGRAM_ID);
    let client = pocket_rpc_client(&opts.rpc_url);
    let account_size = pool_tree_account_size();
    let lamports = client
        .get_minimum_balance_for_rent_exemption(account_size)
        .context("get pool-tree rent exemption")?;
    let create_ix = system_instruction::create_account(
        &payer.pubkey(),
        &tree.pubkey(),
        lamports,
        account_size as u64,
        &program_id,
    );
    let init_ix = Instruction {
        program_id,
        accounts: vec![
            AccountMeta::new_readonly(payer.pubkey(), true),
            AccountMeta::new(tree.pubkey(), false),
        ],
        data: encode_instruction(
            tag::CREATE_POOL_TREE,
            &zolana_interface::instruction::CreatePoolTreeData,
        ),
    };
    let signature = send_pocket_instructions_with_extra_signers(
        &client,
        &payer,
        &[create_ix, init_ix],
        &[&tree],
    )?;
    write_keypair_file(&tree, &opts.output)
        .map_err(|error| anyhow!("write tree keypair {}: {error}", opts.output.display()))?;
    if opts.pubkey_only {
        println!("{}", tree.pubkey());
    } else {
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "tree": tree.pubkey().to_string(),
                "keypair": opts.output,
                "signature": signature.to_string(),
                "account_size": account_size,
            }))?
        );
    }
    Ok(())
}

fn pocket_submit(command: &str, opts: PocketSubmitOptions) -> Result<()> {
    let payer = read_keypair_file(&opts.payer)
        .map_err(|error| anyhow!("read payer keypair {}: {error}", opts.payer.display()))?;
    let direct = if opts.bundle.is_none() {
        Some(pocket_build_direct_proof(command, &opts, &payer)?)
    } else {
        None
    };
    let bundle_path = opts
        .bundle
        .as_ref()
        .cloned()
        .or_else(|| direct.as_ref().map(|direct| direct.bundle_path.clone()))
        .expect("checked above");
    let tx_name = direct
        .as_ref()
        .map(|direct| direct.tx_name.as_str())
        .unwrap_or(&opts.tx_name);
    let bundle = read_pocket_proof_bundle(&bundle_path)?;
    let tx = bundle
        .transactions
        .iter()
        .find(|fixture| fixture.name == tx_name)
        .cloned()
        .ok_or_else(|| anyhow!("proof bundle does not contain tx {tx_name}"))?;

    let payer_hex = hex::encode(payer.pubkey().to_bytes());
    if bundle.solana_signer_pubkey != payer_hex {
        bail!(
            "proof bundle signer {} does not match payer {}",
            bundle.solana_signer_pubkey,
            payer.pubkey()
        );
    }

    let data = pocket_transact_data(&tx)?;
    let signer_receives_relayer_fee =
        data.public_amount_mode == PUBLIC_AMOUNT_WITHDRAW && data.relayer_fee != 0;
    let mut accounts = vec![
        AccountMeta::new(opts.tree, false),
        if signer_receives_relayer_fee {
            AccountMeta::new(payer.pubkey(), true)
        } else {
            AccountMeta::new_readonly(payer.pubkey(), true)
        },
    ];
    let needs_sol = data.public_sol_amount.unwrap_or(0) != 0;
    let needs_spl = data.public_spl_amount.unwrap_or(0) != 0;
    if needs_sol {
        let user_sol_account = opts.user_sol_account.unwrap_or_else(|| payer.pubkey());
        assert_bundle_pubkey("user SOL account", &tx.user_sol_account, &user_sol_account)?;
        accounts.extend([
            AccountMeta::new_readonly(Pubkey::default(), false),
            AccountMeta::new(Pubkey::new_from_array(SHIELDED_POOL_CPI_AUTHORITY), false),
            AccountMeta::new(user_sol_account, false),
        ]);
    }
    if needs_spl {
        let user_spl_token = required_pubkey(opts.user_spl_token, "--user-spl-token")?;
        let spl_vault = required_pubkey(opts.spl_vault, "--spl-vault")?;
        let spl_asset_registry = required_pubkey(opts.spl_asset_registry, "--spl-asset-registry")?;
        if let Some(asset_pubkey) = opts.spl_asset_pubkey {
            assert_bundle_pubkey(
                "public SPL asset pubkey",
                &tx.public_spl_asset_pubkey,
                &asset_pubkey,
            )?;
        }
        assert_bundle_pubkey(
            "user SPL token",
            &tx.user_spl_token_account,
            &user_spl_token,
        )?;
        assert_bundle_pubkey("SPL vault/interface", &tx.spl_token_interface, &spl_vault)?;
        if !needs_sol {
            accounts.push(AccountMeta::new_readonly(
                Pubkey::new_from_array(SHIELDED_POOL_CPI_AUTHORITY),
                false,
            ));
        }
        accounts.extend([
            AccountMeta::new(user_spl_token, false),
            AccountMeta::new(spl_vault, false),
            AccountMeta::new_readonly(spl_asset_registry, false),
            AccountMeta::new_readonly(opts.token_program, false),
        ]);
    }

    let ix = Instruction {
        program_id: Pubkey::new_from_array(SHIELDED_POOL_PROGRAM_ID),
        accounts,
        data: encode_instruction(tag::TRANSACT, &data),
    };
    let client = pocket_rpc_client(&opts.rpc_url);
    let compute_budget_ix = ComputeBudgetInstruction::set_compute_unit_limit(1_400_000);
    let signature = send_pocket_instructions(&client, &payer, &[compute_budget_ix, ix])?;
    if let Some(direct) = direct {
        pocket_apply_state_updates(direct.state_updates)?;
    }
    println!(
        "{}",
        serde_json::to_string_pretty(&json!({
            "command": command,
            "tx": tx.name,
            "proof_bundle": bundle_path,
            "signature": signature.to_string(),
        }))?
    );
    Ok(())
}

fn pocket_build_direct_proof(
    command: &str,
    opts: &PocketSubmitOptions,
    payer: &Keypair,
) -> Result<PocketDirectProof> {
    let state_path = opts
        .state
        .as_ref()
        .cloned()
        .ok_or_else(|| anyhow!("{command} requires --state"))?;
    let keys_file = opts
        .keys_file
        .as_ref()
        .ok_or_else(|| anyhow!("{command} requires --keys-file"))?;
    let prover_bin = opts
        .prover_bin
        .as_ref()
        .ok_or_else(|| anyhow!("{command} requires --prover-bin"))?;
    let amount = opts
        .amount
        .ok_or_else(|| anyhow!("{command} requires --amount"))?;
    if opts.relayer_fee != 0 && command != "unshield" {
        bail!("--relayer-fee is only supported for SOL unshield");
    }
    let mut sender_state = read_pocket_state(&state_path)?;
    normalize_pocket_state(&mut sender_state);

    let signer_hex = pubkey_hex(&payer.pubkey());
    let owner_p256_wallet = opts
        .owner_p256_wallet
        .as_ref()
        .map(|path| read_pocket_p256_wallet(path))
        .transpose()?;
    let sender_output_owner = match owner_p256_wallet.clone() {
        Some(wallet) => PocketOwner::P256(wallet),
        None => PocketOwner::Solana {
            pubkey: payer.pubkey(),
            nullifier_secret: ed25519_nullifier_secret_hex(payer)?,
        },
    };
    let mut recipient_state_path = None;
    let mut recipient_state = None;
    let mut output_targets = Vec::<PocketOutputTarget>::new();
    let mut spent_note_id = None;
    let sender_next_leaf_index = sender_state.next_leaf_index;

    let mut request_tx = match command {
        "shield" => {
            let is_spl = opts.has_spl_settlement();
            let (asset_id, public_spl_asset_pubkey) = if is_spl {
                pocket_spl_asset_identity(opts, "shield")?
            } else {
                validate_sol_asset_id(opts.asset_id.as_deref(), "shield")?;
                (pocket_sol_asset_field(), String::new())
            };
            let (utxo, nullifier_secret) =
                pocket_new_utxo_for_owner(&sender_output_owner, &asset_id, amount);
            output_targets.push(PocketOutputTarget {
                recipient: PocketOutputRecipient::Sender,
                nullifier_secret,
                owner: sender_output_owner.clone(),
            });
            pocket_request_tx(PocketRequestTxParams {
                name: opts.tx_name.clone(),
                state: &sender_state,
                inputs: Vec::new(),
                outputs: vec![utxo],
                public_amount_mode: PUBLIC_AMOUNT_DEPOSIT,
                public_sol_amount: if is_spl { None } else { Some(amount) },
                public_spl_amount: if is_spl { Some(amount) } else { None },
                public_spl_asset_pubkey,
                relayer_fee: 0,
                user_sol_account: if is_spl { None } else { Some(payer.pubkey()) },
                user_spl_token_account: if is_spl {
                    Some(required_pubkey(opts.user_spl_token, "--user-spl-token")?)
                } else {
                    None
                },
                spl_token_interface: if is_spl {
                    Some(required_pubkey(opts.spl_vault, "--spl-vault")?)
                } else {
                    None
                },
            })
        }
        "transfer" => {
            let recipient_owner = if let Some(path) = opts.recipient_p256_wallet.as_ref() {
                PocketOwner::P256(read_pocket_p256_wallet(path)?)
            } else {
                let recipient_wallet = opts
                    .recipient_wallet
                    .as_ref()
                    .ok_or_else(|| anyhow!("transfer requires --recipient-wallet"))?;
                let recipient_keypair = read_keypair_file(recipient_wallet).map_err(|error| {
                    anyhow!(
                        "read recipient keypair {}: {error}",
                        recipient_wallet.display()
                    )
                })?;
                PocketOwner::Solana {
                    pubkey: recipient_keypair.pubkey(),
                    nullifier_secret: ed25519_nullifier_secret_hex(&recipient_keypair)?,
                }
            };
            let recipient_state_file = opts
                .recipient_state
                .as_ref()
                .cloned()
                .ok_or_else(|| anyhow!("transfer requires --recipient-state"))?;
            let mut loaded_recipient_state = read_pocket_state(&recipient_state_file)?;
            normalize_pocket_state(&mut loaded_recipient_state);
            merge_known_leaves(&mut loaded_recipient_state, &sender_state);
            recipient_state_path = Some(recipient_state_file);

            let selected = select_pocket_note(&sender_state, opts.asset_id.as_deref(), amount)?;
            validate_p256_input_owner(&selected.note, owner_p256_wallet.as_ref())?;
            let input_amount = pocket_note_amount(&selected.note)?;
            let change_amount = opts.change_amount.unwrap_or(input_amount - amount);
            if amount
                .checked_add(change_amount)
                .ok_or_else(|| anyhow!("transfer amount plus change overflow"))?
                != input_amount
            {
                bail!(
                    "transfer amount plus change ({amount} + {change_amount}) must equal input note amount {input_amount}"
                );
            }
            let asset_id = pocket_note_asset_id(&selected.note)?;
            let (recipient_utxo, recipient_nullifier_secret) =
                pocket_new_utxo_for_owner(&recipient_owner, &asset_id, amount);
            let mut outputs = vec![recipient_utxo];
            output_targets.push(PocketOutputTarget {
                recipient: PocketOutputRecipient::Recipient,
                nullifier_secret: recipient_nullifier_secret,
                owner: recipient_owner,
            });
            if change_amount > 0 {
                let (change_utxo, change_nullifier_secret) =
                    pocket_new_utxo_for_owner(&sender_output_owner, &asset_id, change_amount);
                outputs.push(change_utxo);
                output_targets.push(PocketOutputTarget {
                    recipient: PocketOutputRecipient::Sender,
                    nullifier_secret: change_nullifier_secret,
                    owner: sender_output_owner.clone(),
                });
            }
            spent_note_id = Some(selected.note.id.clone());
            recipient_state = Some(loaded_recipient_state);
            pocket_request_tx(PocketRequestTxParams {
                name: opts.tx_name.clone(),
                state: &sender_state,
                inputs: vec![PocketProofInput {
                    utxo: selected.note.utxo.clone(),
                    leaf_index: selected.note.leaf_index,
                    nullifier_secret: selected.note.nullifier_secret.clone(),
                }],
                outputs,
                public_amount_mode: PUBLIC_AMOUNT_NONE,
                public_sol_amount: None,
                public_spl_amount: None,
                public_spl_asset_pubkey: String::new(),
                relayer_fee: 0,
                user_sol_account: None,
                user_spl_token_account: None,
                spl_token_interface: None,
            })
        }
        "unshield" => {
            let is_spl = opts.has_spl_settlement();
            let (asset_id, public_spl_asset_pubkey) = if is_spl {
                pocket_spl_asset_identity(opts, "unshield")?
            } else {
                validate_sol_asset_id(opts.asset_id.as_deref(), "unshield")?;
                (pocket_sol_asset_field(), String::new())
            };
            if is_spl && opts.relayer_fee != 0 {
                bail!("--relayer-fee is only supported for SOL unshield");
            }
            let total_private_amount = amount
                .checked_add(opts.relayer_fee as u64)
                .ok_or_else(|| anyhow!("unshield amount plus relayer fee overflow"))?;
            let selected =
                select_pocket_note(&sender_state, Some(asset_id.as_str()), total_private_amount)?;
            validate_p256_input_owner(&selected.note, owner_p256_wallet.as_ref())?;
            let input_amount = pocket_note_amount(&selected.note)?;
            if input_amount != total_private_amount {
                bail!(
                    "unshield currently requires an exact note amount including relayer fee: selected {input_amount}, requested {amount} plus fee {}",
                    opts.relayer_fee
                );
            }
            spent_note_id = Some(selected.note.id.clone());
            pocket_request_tx(PocketRequestTxParams {
                name: opts.tx_name.clone(),
                state: &sender_state,
                inputs: vec![PocketProofInput {
                    utxo: selected.note.utxo.clone(),
                    leaf_index: selected.note.leaf_index,
                    nullifier_secret: selected.note.nullifier_secret.clone(),
                }],
                outputs: Vec::new(),
                public_amount_mode: PUBLIC_AMOUNT_WITHDRAW,
                public_sol_amount: if is_spl { None } else { Some(amount) },
                public_spl_amount: if is_spl { Some(amount) } else { None },
                public_spl_asset_pubkey,
                relayer_fee: if is_spl { 0 } else { opts.relayer_fee },
                user_sol_account: if is_spl {
                    None
                } else {
                    Some(opts.user_sol_account.unwrap_or_else(|| payer.pubkey()))
                },
                user_spl_token_account: if is_spl {
                    Some(required_pubkey(opts.user_spl_token, "--user-spl-token")?)
                } else {
                    None
                },
                spl_token_interface: if is_spl {
                    Some(required_pubkey(opts.spl_vault, "--spl-vault")?)
                } else {
                    None
                },
            })
        }
        other => bail!("unsupported pocket command for direct proving: {other}"),
    }?;

    let bundle_path = opts
        .output_proof_bundle
        .clone()
        .unwrap_or_else(|| default_pocket_bundle_path(&state_path, command));
    let request_path = bundle_path.with_extension("request.json");
    if pocket_request_has_p256_inputs(&request_tx) {
        let wallet = owner_p256_wallet.as_ref().ok_or_else(|| {
            anyhow!("{command} spends a P256-owned note and requires --owner-p256-wallet")
        })?;
        let unsigned_request = PocketProofRequest {
            solana_signer_pubkey: signer_hex.clone(),
            transactions: vec![request_tx.clone()],
        };
        write_json_file(&request_path, &unsigned_request)?;
        let signing_payload_path = bundle_path.with_extension("signing-payload.json");
        invoke_spp_signing_payload(prover_bin, keys_file, &request_path, &signing_payload_path)?;
        let payload = read_pocket_signing_payload(&signing_payload_path)?;
        let tx_payload = payload
            .transactions
            .iter()
            .find(|tx| tx.name == opts.tx_name)
            .ok_or_else(|| anyhow!("signing payload does not contain tx {}", opts.tx_name))?;
        if !tx_payload.requires_p256_signature {
            bail!("signing payload did not request a P256 signature for a P256-owned input");
        }
        let (signature_r, signature_s) =
            sign_p256_private_tx_hash(wallet, &tx_payload.private_tx_hash)?;
        request_tx.p256_owner_pubkey = wallet.p256_public_key.clone();
        request_tx.p256_signature_r = signature_r;
        request_tx.p256_signature_s = signature_s;
    }
    let request = PocketProofRequest {
        solana_signer_pubkey: signer_hex,
        transactions: vec![request_tx],
    };
    write_json_file(&request_path, &request)?;
    invoke_spp_prover(prover_bin, keys_file, &request_path, &bundle_path)?;

    let bundle = read_pocket_proof_bundle(&bundle_path)?;
    let tx = bundle
        .transactions
        .iter()
        .find(|tx| tx.name == opts.tx_name)
        .ok_or_else(|| anyhow!("prover output does not contain tx {}", opts.tx_name))?;
    if tx.output_utxos.len() != output_targets.len() {
        bail!(
            "prover output has {} output UTXOs, expected {}",
            tx.output_utxos.len(),
            output_targets.len()
        );
    }

    if let Some(id) = spent_note_id {
        mark_pocket_note_spent(&mut sender_state, &id)?;
    }
    let mut next_root_index = sender_state.utxo_root_index;
    if !tx.output_utxos.is_empty() {
        next_root_index = (next_root_index + 1) % POCKET_UTXO_ROOT_HISTORY_CAPACITY;
    }
    for (offset, (proved, target)) in tx.output_utxos.iter().zip(output_targets).enumerate() {
        let PocketOutputTarget {
            recipient,
            nullifier_secret,
            owner,
        } = target;
        let leaf_index = sender_next_leaf_index + offset as u64;
        let note = PocketNote {
            id: format!("{}:{leaf_index}", opts.tree),
            owner_pubkey: owner.label(),
            leaf_index,
            utxo: proved.utxo.clone(),
            nullifier_secret,
            hash: proved.hash.clone(),
            spent: false,
        };
        insert_known_leaf(&mut sender_state, leaf_index, proved.hash.clone());
        match recipient {
            PocketOutputRecipient::Sender => sender_state.notes.push(note),
            PocketOutputRecipient::Recipient => {
                let recipient = recipient_state
                    .as_mut()
                    .ok_or_else(|| anyhow!("missing recipient state for transfer output"))?;
                insert_known_leaf(recipient, leaf_index, proved.hash.clone());
                recipient.notes.push(note);
            }
        }
    }
    let new_next = sender_next_leaf_index + tx.output_utxos.len() as u64;
    sender_state.next_leaf_index = sender_state.next_leaf_index.max(new_next);
    sender_state.utxo_root_index = next_root_index;
    if let Some(recipient) = recipient_state.as_mut() {
        merge_known_leaves(recipient, &sender_state);
        recipient.next_leaf_index = recipient.next_leaf_index.max(sender_state.next_leaf_index);
        recipient.utxo_root_index = sender_state.utxo_root_index;
    }

    Ok(PocketDirectProof {
        bundle_path,
        tx_name: opts.tx_name.clone(),
        state_updates: PocketStateUpdates {
            sender_state_path: Some(state_path),
            sender_state,
            recipient_state_path,
            recipient_state,
        },
    })
}

fn pocket_apply_state_updates(updates: PocketStateUpdates) -> Result<()> {
    if let Some(path) = updates.sender_state_path {
        write_json_file(&path, &updates.sender_state)?;
    }
    if let (Some(path), Some(state)) = (updates.recipient_state_path, updates.recipient_state) {
        write_json_file(&path, &state)?;
    }
    Ok(())
}

#[derive(Clone, Debug)]
struct PocketRequestTxParams<'a> {
    name: String,
    state: &'a PocketState,
    inputs: Vec<PocketProofInput>,
    outputs: Vec<PocketUtxo>,
    public_amount_mode: u8,
    public_sol_amount: Option<u64>,
    public_spl_amount: Option<u64>,
    public_spl_asset_pubkey: String,
    relayer_fee: u16,
    user_sol_account: Option<Pubkey>,
    user_spl_token_account: Option<Pubkey>,
    spl_token_interface: Option<Pubkey>,
}

#[derive(Clone, Debug)]
struct PocketOutputTarget {
    recipient: PocketOutputRecipient,
    nullifier_secret: String,
    owner: PocketOwner,
}

#[derive(Clone, Debug)]
enum PocketOutputRecipient {
    Sender,
    Recipient,
}

#[derive(Clone, Debug)]
enum PocketOwner {
    // nullifier_secret is wallet-wide (derived from the Ed25519 signing key),
    // so every UTXO for this owner shares one nullifier_pk — required for
    // multi-input spends, which the circuit forces to share one nullifier_secret.
    Solana {
        pubkey: Pubkey,
        nullifier_secret: String,
    },
    P256(PocketP256Wallet),
}

impl PocketOwner {
    fn label(&self) -> String {
        match self {
            PocketOwner::Solana { pubkey, .. } => pubkey.to_string(),
            PocketOwner::P256(wallet) => format!("p256:{}", wallet.p256_public_key),
        }
    }
}

#[derive(Clone, Debug)]
struct SelectedPocketNote {
    note: PocketNote,
}

fn pocket_request_tx(params: PocketRequestTxParams<'_>) -> Result<PocketProofRequestTx> {
    let input_count = params.inputs.len();
    Ok(PocketProofRequestTx {
        name: params.name,
        instruction_discriminator: tag::TRANSACT,
        expiry_unix_ts: pocket_expiry_unix_ts()?,
        sender_view_tag: random_field_hex(),
        relayer_fee: params.relayer_fee,
        public_amount_mode: params.public_amount_mode,
        public_sol_amount: params.public_sol_amount,
        public_spl_amount: params.public_spl_amount,
        public_spl_asset_pubkey: params.public_spl_asset_pubkey,
        encrypted_utxos: random_hex_bytes(64),
        user_sol_account: params
            .user_sol_account
            .map(|pubkey| pubkey_hex(&pubkey))
            .unwrap_or_default(),
        user_spl_token_account: params
            .user_spl_token_account
            .map(|pubkey| pubkey_hex(&pubkey))
            .unwrap_or_default(),
        spl_token_interface: params
            .spl_token_interface
            .map(|pubkey| pubkey_hex(&pubkey))
            .unwrap_or_default(),
        state_entries: pocket_state_entries(params.state),
        inputs: params.inputs,
        outputs: params.outputs,
        utxo_tree_root_index: vec![params.state.utxo_root_index; input_count],
        nullifier_tree_root_index: vec![0; input_count],
        program_id_hashchain: zero_field_hex(),
        data_hash: zero_field_hex(),
        zone_data_hash: zero_field_hex(),
        p256_owner_pubkey: String::new(),
        p256_signature_r: String::new(),
        p256_signature_s: String::new(),
    })
}

fn pocket_new_utxo(
    owner: &Pubkey,
    nullifier_secret: &str,
    asset_id: &str,
    asset_amount: u64,
) -> (PocketUtxo, String) {
    (
        PocketUtxo {
            domain: pocket_field_hex_from_u64(POCKET_UTXO_DOMAIN),
            owner: String::new(),
            owner_solana_pubkey: pubkey_hex(owner),
            owner_p256_pubkey: String::new(),
            owner_nullifier_secret: nullifier_secret.to_string(),
            asset_id: prover_field(asset_id),
            asset_amount: asset_amount.to_string(),
            blinding: random_field_hex(),
            data_hash: zero_field_hex(),
            zone_data_hash: zero_field_hex(),
            zone_program_id: zero_field_hex(),
        },
        nullifier_secret.to_string(),
    )
}

fn pocket_new_p256_utxo(
    wallet: &PocketP256Wallet,
    asset_id: &str,
    asset_amount: u64,
) -> (PocketUtxo, String) {
    (
        PocketUtxo {
            domain: pocket_field_hex_from_u64(POCKET_UTXO_DOMAIN),
            owner: String::new(),
            owner_solana_pubkey: String::new(),
            owner_p256_pubkey: wallet.p256_public_key.clone(),
            owner_nullifier_secret: wallet.nullifier_secret.clone(),
            asset_id: prover_field(asset_id),
            asset_amount: asset_amount.to_string(),
            blinding: random_field_hex(),
            data_hash: zero_field_hex(),
            zone_data_hash: zero_field_hex(),
            zone_program_id: zero_field_hex(),
        },
        wallet.nullifier_secret.clone(),
    )
}

fn pocket_new_utxo_for_owner(
    owner: &PocketOwner,
    asset_id: &str,
    asset_amount: u64,
) -> (PocketUtxo, String) {
    match owner {
        PocketOwner::Solana {
            pubkey,
            nullifier_secret,
        } => pocket_new_utxo(pubkey, nullifier_secret, asset_id, asset_amount),
        PocketOwner::P256(wallet) => pocket_new_p256_utxo(wallet, asset_id, asset_amount),
    }
}

fn random_p256_signing_key() -> Result<P256SigningKey> {
    let mut rng = rand::thread_rng();
    loop {
        let mut bytes = [0u8; 32];
        rng.fill_bytes(&mut bytes);
        if let Ok(secret) = P256SecretKey::from_slice(&bytes) {
            return Ok(P256SigningKey::from(secret));
        }
    }
}

fn read_pocket_p256_wallet(path: &Path) -> Result<PocketP256Wallet> {
    let bytes = fs::read(path).with_context(|| format!("read {}", path.display()))?;
    let wallet: PocketP256Wallet =
        serde_json::from_slice(&bytes).with_context(|| format!("decode {}", path.display()))?;
    if wallet.version != 1 {
        bail!(
            "{} has unsupported shielded wallet version {}",
            path.display(),
            wallet.version
        );
    }
    if wallet.scheme != "p256" {
        bail!("{} is not a p256 shielded wallet", path.display());
    }
    let signing_key = p256_signing_key(&wallet)?;
    let derived_public = hex::encode(
        signing_key
            .verifying_key()
            .to_encoded_point(true)
            .as_bytes(),
    );
    if derived_public != wallet.p256_public_key {
        bail!(
            "{} p256_public_key does not match p256_secret_key",
            path.display()
        );
    }
    let actual_nullifier_secret = p256_nullifier_secret_bytes(&wallet.nullifier_secret)
        .with_context(|| format!("{} nullifier_secret", path.display()))?;
    let expected_nullifier_secret = p256_nullifier_secret_bytes_from_key(&signing_key)?;
    if actual_nullifier_secret != expected_nullifier_secret {
        bail!(
            "{} nullifier_secret is not derived from p256_secret_key",
            path.display()
        );
    }
    let public_key = hex_bytes(&wallet.p256_public_key)
        .with_context(|| format!("{} p256_public_key", path.display()))?;
    if public_key.len() != 33 {
        bail!(
            "{} p256_public_key must be a 33-byte compressed SEC1 key",
            path.display()
        );
    }
    Ok(wallet)
}

fn p256_signing_key(wallet: &PocketP256Wallet) -> Result<P256SigningKey> {
    let secret = hex_bytes(&wallet.p256_secret_key)?;
    if secret.len() != 32 {
        bail!("p256_secret_key must be 32 bytes, got {}", secret.len());
    }
    let secret = P256SecretKey::from_slice(&secret)
        .map_err(|error| anyhow!("invalid p256_secret_key: {error}"))?;
    Ok(P256SigningKey::from(secret))
}

fn p256_nullifier_secret_hex(signing_key: &P256SigningKey) -> Result<String> {
    // 0x-prefixed: nullifier_secret is a field element fed straight into the
    // prover, whose field parser reads a bare (un-prefixed) hex string as
    // decimal. Matches random_field_hex and the other request fields.
    Ok(format!(
        "0x{}",
        hex::encode(p256_nullifier_secret_bytes_from_key(signing_key)?)
    ))
}

// Wallet-wide nullifier secret for a Solana/Ed25519 owner, derived from the
// signing key per spec ("Nullifier Key"): HKDF-SHA256(IKM=signing_sk). Used so
// every UTXO of one Solana owner shares a nullifier_pk (multi-input spends).
fn ed25519_nullifier_secret_hex(keypair: &Keypair) -> Result<String> {
    // 0x-prefixed for the same reason as p256_nullifier_secret_hex.
    Ok(format!(
        "0x{}",
        hex::encode(nullifier_secret_bytes_from_ikm(keypair.secret_bytes())?)
    ))
}

fn p256_nullifier_secret_bytes_from_key(signing_key: &P256SigningKey) -> Result<[u8; 31]> {
    nullifier_secret_bytes_from_ikm(signing_key.to_bytes().as_slice())
}

// HKDF-SHA256 with empty salt, info=POCKET_NULLIFIER_HKDF_INFO, L=31, per spec.
fn nullifier_secret_bytes_from_ikm(ikm: &[u8]) -> Result<[u8; 31]> {
    let mut extract =
        Hmac::<Sha256>::new_from_slice(&[0u8; 32]).context("initialize HKDF extract")?;
    extract.update(ikm);
    let prk = extract.finalize().into_bytes();

    let mut expand = Hmac::<Sha256>::new_from_slice(&prk).context("initialize HKDF expand")?;
    expand.update(POCKET_NULLIFIER_HKDF_INFO);
    expand.update(&[1]);
    let okm = expand.finalize().into_bytes();
    let mut out = [0u8; 31];
    out.copy_from_slice(&okm[..31]);
    Ok(out)
}

fn p256_nullifier_secret_bytes(value: &str) -> Result<[u8; 31]> {
    let bytes = hex_bytes(value)?;
    if bytes.len() != 31 {
        bail!(
            "p256 nullifier_secret must be a 31-byte big-endian field element, got {} bytes",
            bytes.len()
        );
    }
    let mut out = [0u8; 31];
    out.copy_from_slice(&bytes);
    Ok(out)
}

fn sign_p256_private_tx_hash(
    wallet: &PocketP256Wallet,
    private_tx_hash: &str,
) -> Result<(String, String)> {
    let message = hex_field(private_tx_hash)?;
    let signing_key = p256_signing_key(wallet)?;
    let signature: P256Signature = signing_key
        .sign_prehash(&message)
        .map_err(|error| anyhow!("sign P256 private_tx_hash: {error}"))?;
    let signature_bytes = signature.to_bytes();
    Ok((
        format!("0x{}", hex::encode(&signature_bytes[..32])),
        format!("0x{}", hex::encode(&signature_bytes[32..])),
    ))
}

fn validate_p256_input_owner(note: &PocketNote, wallet: Option<&PocketP256Wallet>) -> Result<()> {
    if note.utxo.owner_p256_pubkey.is_empty() {
        return Ok(());
    }
    let wallet = wallet.ok_or_else(|| {
        anyhow!(
            "note {} is P256-owned and requires --owner-p256-wallet to spend",
            note.id
        )
    })?;
    if note.utxo.owner_p256_pubkey != wallet.p256_public_key {
        bail!(
            "note {} is owned by P256 key {}, not {}",
            note.id,
            note.utxo.owner_p256_pubkey,
            wallet.p256_public_key
        );
    }
    if note.nullifier_secret != wallet.nullifier_secret {
        bail!(
            "note {} nullifier secret does not match --owner-p256-wallet",
            note.id
        );
    }
    Ok(())
}

fn pocket_request_has_p256_inputs(tx: &PocketProofRequestTx) -> bool {
    tx.inputs
        .iter()
        .any(|input| !input.utxo.owner_p256_pubkey.is_empty())
}

fn read_pocket_state(path: &Path) -> Result<PocketState> {
    match fs::read(path) {
        Ok(bytes) => serde_json::from_slice(&bytes)
            .with_context(|| format!("decode pocket state {}", path.display())),
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(PocketState::default()),
        Err(error) => Err(error).with_context(|| format!("read {}", path.display())),
    }
}

fn write_json_file<T: Serialize>(path: &Path, value: &T) -> Result<()> {
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }
    let mut bytes = serde_json::to_vec_pretty(value)?;
    bytes.push(b'\n');
    fs::write(path, bytes).with_context(|| format!("write {}", path.display()))
}

fn normalize_pocket_state(state: &mut PocketState) {
    let mut leaves = BTreeMap::<u64, String>::new();
    for leaf in state.known_leaves.drain(..) {
        leaves.insert(leaf.index, leaf.hash);
    }
    state.known_leaves = leaves
        .iter()
        .map(|(index, hash)| PocketKnownLeaf {
            index: *index,
            hash: hash.clone(),
        })
        .collect();
    if let Some(max_index) = leaves.keys().next_back() {
        state.next_leaf_index = state.next_leaf_index.max(max_index + 1);
    }
}

fn merge_known_leaves(dst: &mut PocketState, src: &PocketState) {
    let mut leaves = dst
        .known_leaves
        .iter()
        .map(|leaf| (leaf.index, leaf.hash.clone()))
        .collect::<BTreeMap<_, _>>();
    for leaf in &src.known_leaves {
        leaves.insert(leaf.index, leaf.hash.clone());
    }
    dst.known_leaves = leaves
        .into_iter()
        .map(|(index, hash)| PocketKnownLeaf { index, hash })
        .collect();
    dst.next_leaf_index = dst.next_leaf_index.max(src.next_leaf_index);
    dst.utxo_root_index = dst.utxo_root_index.max(src.utxo_root_index);
}

fn insert_known_leaf(state: &mut PocketState, index: u64, hash: String) {
    if let Some(existing) = state
        .known_leaves
        .iter_mut()
        .find(|leaf| leaf.index == index)
    {
        existing.hash = hash;
    } else {
        state.known_leaves.push(PocketKnownLeaf { index, hash });
        state.known_leaves.sort_by_key(|leaf| leaf.index);
    }
    state.next_leaf_index = state.next_leaf_index.max(index + 1);
}

fn pocket_state_entries(state: &PocketState) -> Vec<PocketStateEntry> {
    state
        .known_leaves
        .iter()
        .map(|leaf| PocketStateEntry {
            index: leaf.index,
            hash: prover_field(&leaf.hash),
        })
        .collect()
}

fn prover_field(value: &str) -> String {
    let value = value.trim();
    if value.starts_with("0x") || value.starts_with("0X") {
        value.to_string()
    } else {
        format!("0x{value}")
    }
}

fn select_pocket_note(
    state: &PocketState,
    asset_id: Option<&str>,
    min_amount: u64,
) -> Result<SelectedPocketNote> {
    let asset_id = asset_id.map(normalize_pocket_field).transpose()?;
    for note in &state.notes {
        if note.spent {
            continue;
        }
        let note_asset_id = pocket_note_asset_id(note)?;
        if asset_id
            .as_deref()
            .is_some_and(|asset_id| asset_id != note_asset_id)
        {
            continue;
        }
        if pocket_note_amount(note)? >= min_amount {
            return Ok(SelectedPocketNote { note: note.clone() });
        }
    }
    bail!(
        "no unspent pocket note found for asset {:?} with at least {} units",
        asset_id,
        min_amount
    )
}

fn validate_sol_asset_id(asset_id: Option<&str>, command: &str) -> Result<()> {
    if let Some(asset_id) = asset_id {
        let asset_id = normalize_pocket_field(asset_id)?;
        let sol_asset_id = pocket_sol_asset_field();
        if asset_id != sol_asset_id {
            bail!("{command} SOL settlement uses reserved asset id {sol_asset_id}, got {asset_id}");
        }
    }
    Ok(())
}

fn pocket_spl_asset_identity(
    opts: &PocketSubmitOptions,
    command: &str,
) -> Result<(String, String)> {
    let asset_pubkey = opts.spl_asset_pubkey.ok_or_else(|| {
        anyhow!("{command} requires --asset-pubkey/--spl-mint for SPL settlement")
    })?;
    let asset_id = pocket_canonical_asset_field(&asset_pubkey)?;
    let normalized_asset_id = normalize_pocket_field(&asset_id)?;
    if let Some(requested) = opts.asset_id.as_deref() {
        let requested = normalize_pocket_field(requested)?;
        if requested != normalized_asset_id {
            bail!(
                "{command} SPL settlement uses canonical mint-derived asset id {normalized_asset_id}, got {requested}"
            );
        }
    }
    Ok((asset_id, pubkey_hex(&asset_pubkey)))
}

fn pocket_sol_asset_field() -> String {
    // SOL's asset id is the canonical encoding of Address::default() —
    // Poseidon(0, 0) — matching protocol.SolAsset() (Go) and the program, which
    // the circuit's balance check pins public SOL movement to. (A literal id
    // would never satisfy balance conservation.)
    pocket_canonical_asset_field(&Pubkey::default()).expect("canonical SOL asset hash")
}

fn pocket_canonical_asset_field(pubkey: &Pubkey) -> Result<String> {
    let pubkey = pubkey.to_bytes();
    let low = pocket_field_from_u128_be(&pubkey[16..]);
    let high = pocket_field_from_u128_be(&pubkey[..16]);
    let hash = Poseidon::hashv(&[low.as_slice(), high.as_slice()])
        .map_err(|error| anyhow!("hash canonical SPL asset pubkey: {error:?}"))?;
    Ok(format!("0x{}", hex::encode(hash)))
}

fn pocket_field_from_u128_be(value: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[16..32].copy_from_slice(value);
    out
}

fn mark_pocket_note_spent(state: &mut PocketState, id: &str) -> Result<()> {
    let note = state
        .notes
        .iter_mut()
        .find(|note| note.id == id)
        .ok_or_else(|| anyhow!("spent note {id} not found in state"))?;
    note.spent = true;
    Ok(())
}

fn pocket_note_amount(note: &PocketNote) -> Result<u64> {
    parse_pocket_u64_field(&note.utxo.asset_amount)
        .with_context(|| format!("note {} asset_amount", note.id))
}

fn pocket_note_asset_id(note: &PocketNote) -> Result<String> {
    normalize_pocket_field(&note.utxo.asset_id)
        .with_context(|| format!("note {} asset_id", note.id))
}

fn parse_pocket_u64_field(value: &str) -> Result<u64> {
    let out = parse_pocket_biguint(value)?;
    out.to_u64()
        .ok_or_else(|| anyhow!("field {value} does not fit into u64"))
}

fn normalize_pocket_field(value: &str) -> Result<String> {
    Ok(format!("{:064x}", parse_pocket_biguint(value)?))
}

fn pocket_field_hex_from_u64(value: u64) -> String {
    format!("{value:064x}")
}

fn parse_pocket_biguint(value: &str) -> Result<BigUint> {
    let trimmed = value.trim().trim_start_matches("0x");
    if trimmed.is_empty() {
        bail!("empty numeric field");
    }
    let base = if trimmed.len() > 20
        || trimmed
            .chars()
            .any(|c| c.is_ascii_hexdigit() && !c.is_ascii_digit())
    {
        16
    } else {
        10
    };
    let out = BigUint::parse_bytes(trimmed.as_bytes(), base)
        .ok_or_else(|| anyhow!("invalid numeric field {value}"))?;
    if out.bits() > 254 {
        bail!("field {value} exceeds BN254 scalar field width");
    }
    Ok(out)
}

fn invoke_spp_prover(
    prover_bin: &Path,
    keys_file: &Path,
    request_path: &Path,
    bundle_path: &Path,
) -> Result<()> {
    let output = Command::new(prover_bin)
        .args(["spp", "prove-bundle", "--keys-file"])
        .arg(keys_file)
        .arg("--input")
        .arg(request_path)
        .arg("--output")
        .arg(bundle_path)
        .output()
        .with_context(|| format!("run prover {}", prover_bin.display()))?;
    if !output.status.success() {
        bail!(
            "prover failed with status {}\nstdout:\n{}\nstderr:\n{}",
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
    Ok(())
}

fn invoke_spp_signing_payload(
    prover_bin: &Path,
    keys_file: &Path,
    request_path: &Path,
    payload_path: &Path,
) -> Result<()> {
    let output = Command::new(prover_bin)
        .args(["spp", "signing-payload", "--keys-file"])
        .arg(keys_file)
        .arg("--input")
        .arg(request_path)
        .arg("--output")
        .arg(payload_path)
        .output()
        .with_context(|| format!("run prover {}", prover_bin.display()))?;
    if !output.status.success() {
        bail!(
            "prover signing-payload failed with status {}\nstdout:\n{}\nstderr:\n{}",
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
    Ok(())
}

fn default_pocket_bundle_path(state_path: &Path, command: &str) -> PathBuf {
    let parent = state_path.parent().unwrap_or_else(|| Path::new("."));
    let stem = state_path
        .file_stem()
        .and_then(|stem| stem.to_str())
        .unwrap_or("pocket");
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis())
        .unwrap_or(0);
    parent.join(format!("{stem}.{command}.{millis}.proof.json"))
}

fn pocket_expiry_unix_ts() -> Result<u64> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system time is before unix epoch")?
        .as_secs();
    Ok(now + 24 * 60 * 60)
}

fn random_field_hex() -> String {
    let keypair = Keypair::new();
    let mut bytes = keypair.to_bytes();
    bytes[0] = 0;
    format!("0x{}", hex::encode(&bytes[..32]))
}

fn random_hex_bytes(len: usize) -> String {
    let mut out = Vec::with_capacity(len);
    while out.len() < len {
        out.extend_from_slice(&Keypair::new().to_bytes());
    }
    out.truncate(len);
    hex::encode(out)
}

fn zero_field_hex() -> String {
    "0000000000000000000000000000000000000000000000000000000000000000".to_string()
}

fn pubkey_hex(pubkey: &Pubkey) -> String {
    hex::encode(pubkey.to_bytes())
}

fn read_pocket_proof_bundle(path: &Path) -> Result<PocketProofBundle> {
    let bytes = fs::read(path).with_context(|| format!("read {}", path.display()))?;
    serde_json::from_slice(&bytes).with_context(|| format!("decode {}", path.display()))
}

fn read_pocket_signing_payload(path: &Path) -> Result<PocketSigningPayloadBundle> {
    let bytes = fs::read(path).with_context(|| format!("read {}", path.display()))?;
    serde_json::from_slice(&bytes).with_context(|| format!("decode {}", path.display()))
}

fn pocket_transact_data(tx: &PocketProofTx) -> Result<TransactData> {
    Ok(TransactData {
        expiry_unix_ts: tx.expiry_unix_ts,
        sender_view_tag: hex_field(&tx.sender_view_tag)?,
        proof: pocket_proof_bytes(&tx.proof)?,
        relayer_fee: tx.relayer_fee,
        public_amount_mode: tx.public_amount_mode,
        nullifiers: tx
            .nullifiers
            .iter()
            .map(|value| hex_field(value))
            .collect::<Result<Vec<_>>>()?,
        output_utxo_hashes: tx
            .output_utxo_hashes
            .iter()
            .map(|value| hex_field(value))
            .collect::<Result<Vec<_>>>()?,
        utxo_tree_root_index: tx.utxo_tree_root_index.clone(),
        nullifier_tree_root_index: tx.nullifier_tree_root_index.clone(),
        private_tx_hash: hex_field(&tx.private_tx_hash)?,
        public_sol_amount: tx.public_sol_amount,
        public_spl_amount: tx.public_spl_amount,
        cpi_signer: None,
        in_utxo_signer_indices: pocket_input_signer_indices(
            tx.nullifiers.len(),
            tx.solana_owner_input_indices.as_deref(),
        ),
        encrypted_utxos: hex_bytes(&tx.encrypted_utxos)?,
        requires_p256: tx.requires_p256,
    })
}

fn pocket_input_signer_indices(
    input_count: usize,
    solana_indices: Option<&[u8]>,
) -> Option<Vec<InputUtxoSignerIndex>> {
    let input_indices = solana_indices
        .map(|indices| indices.to_vec())
        .unwrap_or_else(|| {
            (0..input_count)
                .map(|input_index| input_index as u8)
                .collect()
        });
    if input_indices.is_empty() {
        return None;
    }
    Some(
        input_indices
            .into_iter()
            .map(|input_index| InputUtxoSignerIndex {
                account_index: 1,
                input_index,
            })
            .collect(),
    )
}

fn pocket_proof_bytes(value: &serde_json::Value) -> Result<[u8; 192]> {
    let proof: GnarkProofJson =
        serde_json::from_value(value.clone()).context("decode gnark proof")?;
    bsb22_proof_bytes_from_json_struct(proof).context("encode BSB22 proof")
}

fn send_pocket_instructions(
    client: &RpcClient,
    payer: &Keypair,
    instructions: &[Instruction],
) -> Result<solana_signature::Signature> {
    send_pocket_instructions_with_extra_signers(client, payer, instructions, &[])
}

fn send_pocket_instructions_with_extra_signers(
    client: &RpcClient,
    payer: &Keypair,
    instructions: &[Instruction],
    extra_signers: &[&Keypair],
) -> Result<solana_signature::Signature> {
    let blockhash = client
        .get_latest_blockhash()
        .context("get latest blockhash")?;
    let message = Message::new(instructions, Some(&payer.pubkey()));
    let mut transaction = Transaction::new_unsigned(message);
    let mut signers = Vec::with_capacity(extra_signers.len() + 1);
    signers.push(payer);
    signers.extend_from_slice(extra_signers);
    transaction
        .try_sign(&signers, blockhash)
        .context("sign transaction")?;
    client
        .send_and_confirm_transaction(&transaction)
        .context("send and confirm transaction")
}

fn pocket_rpc_client(rpc_url: &str) -> RpcClient {
    RpcClient::new_with_commitment(rpc_url.to_string(), CommitmentConfig::confirmed())
}

fn parse_pubkey(value: &str) -> Result<Pubkey> {
    Pubkey::from_str(value).map_err(|error| anyhow!("invalid pubkey {value}: {error}"))
}

fn required_pubkey(value: Option<Pubkey>, flag: &str) -> Result<Pubkey> {
    value.ok_or_else(|| anyhow!("missing {flag}"))
}

fn assert_bundle_pubkey(label: &str, hex_value: &str, pubkey: &Pubkey) -> Result<()> {
    let expected = hex::encode(pubkey.to_bytes());
    if hex_value != expected {
        bail!("proof bundle {label} {hex_value} does not match provided pubkey {pubkey}");
    }
    Ok(())
}

fn hex_field(value: &str) -> Result<[u8; 32]> {
    let bytes = hex_bytes(value)?;
    if bytes.len() != 32 {
        bail!("expected 32-byte field, got {} bytes", bytes.len());
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

fn hex_bytes(value: &str) -> Result<Vec<u8>> {
    hex::decode(value.trim_start_matches("0x")).map_err(|error| anyhow!("invalid hex: {error}"))
}

fn print_pocket_help() {
    println!("pocket <command>");
    println!();
    println!("Commands:");
    println!("  create-wallet             Create a Solana wallet keypair");
    println!("  create-shielded-wallet    Create a P256 shielded wallet");
    println!("  init-pool-tree            Create and initialize a shielded-pool tree account");
    println!("  shield                    Submit a shield proof bundle transaction");
    println!("  transfer                  Submit a shielded transfer proof bundle transaction");
    println!("  unshield                  Submit an unshield proof bundle transaction");
    println!("  balance                   Query SOL or SPL-token account balance");
}

fn print_help() {
    println!("zolana <command>");
    println!();
    println!("Commands:");
    println!("  pocket            Run pocket wallet and shielded-pool commands");
    println!("  test-validator    Start the local Light Protocol test validator");
    println!("  start-prover      Start the local prover server");
}
