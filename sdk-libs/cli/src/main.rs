use std::{
    env,
    fs::{self, OpenOptions},
    io::{Read, Write},
    net::{SocketAddr, TcpStream},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    thread,
    time::{Duration, Instant},
};

use anyhow::{anyhow, bail, Context, Result};
use serde_json::{json, Value};

const DEFAULT_RPC_PORT: u16 = 8899;
const DEFAULT_INDEXER_PORT: u16 = 8784;
const DEFAULT_PROVER_PORT: u16 = 3001;
const DEFAULT_LIMIT_LEDGER_SIZE: u64 = 10_000;
const DEFAULT_GOSSIP_HOST: &str = "127.0.0.1";
const READINESS_TIMEOUT: Duration = Duration::from_secs(180);

const SPL_NOOP_ID: &str = "noopb9bkMVfRPU8AsbpTUg8AQkHtKwMYZiFUjNRtMmV";
const LIGHT_SYSTEM_PROGRAM_ID: &str = "SySTEM1eSU2p4BGQfQpimFEWWSC1XDFeun3Nqzz3rT7";
const LIGHT_COMPRESSED_TOKEN_ID: &str = "cTokenmWW8bLPjZEBAUgYy3zKxQZW6VKi7bqNFEVv3m";
const ACCOUNT_COMPRESSION_ID: &str = "compr6CUsB5m2jS4Y3831ztGSTnDpnKJTKS95d64XVq";
const LIGHT_REGISTRY_ID: &str = "Lighton6oQpVkeewmo2mcPTQQp7kYHr4fWpAgJyEmDX";

const SYSTEM_PROGRAMS: &[(&str, &str)] = &[
    (SPL_NOOP_ID, "spl_noop.so"),
    (LIGHT_SYSTEM_PROGRAM_ID, "light_system_program_pinocchio.so"),
    (LIGHT_COMPRESSED_TOKEN_ID, "light_compressed_token.so"),
    (ACCOUNT_COMPRESSION_ID, "account_compression.so"),
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
    let args = env::args().skip(1).collect::<Vec<_>>();
    match args.first().map(String::as_str) {
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

    let vendored_candidate = root.join("sdk-libs/cli/bin").join(name);
    if vendored_candidate.exists() {
        return Ok(vendored_candidate);
    }

    bail!("missing {name}; run `just build-light-programs` to build/copy local validator artifacts")
}

fn accounts_dir() -> Result<PathBuf> {
    if let Ok(dir) = env::var("LIGHT_PROTOCOL_ACCOUNTS_DIR") {
        let path = PathBuf::from(dir);
        if path.exists() {
            return Ok(path);
        }
    }

    let path = project_root()?.join("sdk-libs/cli/accounts");
    if path.exists() {
        return Ok(path);
    }

    bail!("missing vendored account fixtures at sdk-libs/cli/accounts")
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
        path_string(&keys_dir)?,
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
    wait_for_http_get_with_child(
        indexer_port,
        "/getIndexerHealth",
        READINESS_TIMEOUT,
        &mut child,
        "Photon",
    )
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

fn rpc_u64(port: u16, method: &str) -> Result<u64> {
    let value = rpc_request(port, method)?;
    value
        .get("result")
        .and_then(Value::as_u64)
        .ok_or_else(|| anyhow!("JSON-RPC method {method} did not return a u64 result: {value}"))
}

fn rpc_request(port: u16, method: &str) -> Result<Value> {
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
        "/",
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

    let mut response = String::new();
    stream.read_to_string(&mut response)?;
    Ok(response)
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

fn print_help() {
    println!("zolana <command>");
    println!();
    println!("Commands:");
    println!("  test-validator    Start the local Light Protocol test validator");
    println!("  start-prover      Start the local prover server");
}
