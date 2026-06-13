use std::{
    env,
    fs::{self, OpenOptions},
    io::{ErrorKind, Read, Write},
    net::{SocketAddr, TcpStream},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    thread,
    time::{Duration, Instant},
};

use anyhow::{anyhow, bail, Context, Result};
use clap::{Args, CommandFactory, Parser, Subcommand};
use serde_json::{json, Value};

const DEFAULT_RPC_PORT: u16 = 8899;
const DEFAULT_PROVER_PORT: u16 = 3001;
const DEFAULT_LIMIT_LEDGER_SIZE: u64 = 10_000;
const DEFAULT_GOSSIP_HOST: &str = "127.0.0.1";
const READINESS_TIMEOUT: Duration = Duration::from_secs(180);

const SPL_NOOP_ID: &str = "noopb9bkMVfRPU8AsbpTUg8AQkHtKwMYZiFUjNRtMmV";

// Programs auto-loaded into `zolana test-validator`.
const SYSTEM_PROGRAMS: &[(&str, &str)] = &[(SPL_NOOP_ID, "spl_noop.so")];

#[derive(Debug, Parser)]
#[command(name = "zolana", about = "Local Zolana developer tooling")]
struct Cli {
    #[command(subcommand)]
    command: Option<CliCommand>,
}

#[derive(Debug, Subcommand)]
enum CliCommand {
    #[command(
        name = "test-validator",
        about = "Start the local Zolana test validator"
    )]
    TestValidator(Box<TestValidatorOptions>),

    #[command(name = "start-prover", about = "Start the local prover server")]
    StartProver(StartProverOptions),
}

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

#[derive(Args, Debug)]
struct TestValidatorOptions {
    #[arg(long, help = "Do not start the prover server")]
    skip_prover: bool,

    #[arg(long, help = "Stop the local validator environment")]
    stop: bool,

    #[arg(long, help = "Do not load account fixtures")]
    skip_system_accounts: bool,

    #[arg(long, help = "Do not load bundled SBF program fixtures")]
    skip_system_programs: bool,

    #[arg(
        long = "use-surfpool",
        conflicts_with = "no_use_surfpool",
        help = "Use surfpool as the validator backend (default)"
    )]
    use_surfpool: bool,

    #[arg(
        long = "no-use-surfpool",
        conflicts_with = "use_surfpool",
        help = "Use solana-test-validator directly"
    )]
    no_use_surfpool: bool,

    #[arg(long, help = "Reuse the existing validator ledger")]
    skip_reset: bool,

    #[arg(long, default_value_t = DEFAULT_RPC_PORT, help = "Validator RPC port")]
    rpc_port: u16,

    #[arg(
        long,
        help = "Faucet port for solana-test-validator",
        value_name = "PORT"
    )]
    faucet_port: Option<u16>,

    #[arg(
        long,
        default_value_t = DEFAULT_PROVER_PORT,
        help = "Prover server port"
    )]
    prover_port: u16,

    #[arg(
        long,
        default_value = DEFAULT_GOSSIP_HOST,
        help = "Validator host or bind address"
    )]
    gossip_host: String,

    #[arg(
        long,
        default_value_t = DEFAULT_LIMIT_LEDGER_SIZE,
        help = "solana-test-validator ledger retention"
    )]
    limit_ledger_size: u64,

    #[arg(
        long,
        help = "Ledger path for solana-test-validator",
        value_name = "PATH"
    )]
    ledger: Option<String>,

    #[arg(
        long = "sbf-program",
        num_args = 2,
        value_names = ["ADDRESS", "PATH"],
        help = "Load an immutable SBF program"
    )]
    sbf_programs: Vec<String>,

    #[arg(
        long = "upgradeable-program",
        num_args = 3,
        value_names = ["ADDRESS", "PATH", "AUTHORITY"],
        help = "Load an upgradeable SBF program"
    )]
    upgradeable_programs: Vec<String>,

    #[arg(
        long = "account-dir",
        help = "Additional account fixture directory",
        value_name = "PATH"
    )]
    account_dirs: Vec<String>,

    #[arg(
        long = "validator-args",
        help = "Forward a whitespace-separated argument string to the validator",
        value_name = "ARGS"
    )]
    validator_arg_groups: Vec<String>,

    #[arg(last = true, allow_hyphen_values = true, value_name = "VALIDATOR_ARG")]
    trailing_validator_args: Vec<String>,

    #[arg(
        long,
        help = "solana-test-validator geyser config",
        value_name = "PATH"
    )]
    geyser_config: Option<String>,
}

#[derive(Args, Debug)]
struct StartProverOptions {
    #[arg(
        long = "prover-port",
        alias = "port",
        visible_alias = "port",
        default_value_t = DEFAULT_PROVER_PORT,
        help = "Prover server port"
    )]
    prover_port: u16,

    #[arg(
        long = "redis-url",
        alias = "redisUrl",
        visible_alias = "redisUrl",
        help = "Redis URL for prover state"
    )]
    redis_url: Option<String>,
}

impl TestValidatorOptions {
    fn use_surfpool_backend(&self) -> bool {
        self.use_surfpool || !self.no_use_surfpool
    }

    fn sbf_program_specs(&self) -> Vec<ProgramSpec> {
        self.sbf_programs
            .chunks_exact(2)
            .map(|chunk| ProgramSpec {
                address: chunk[0].clone(),
                path: chunk[1].clone(),
            })
            .collect()
    }

    fn upgradeable_program_specs(&self) -> Vec<UpgradeableProgramSpec> {
        self.upgradeable_programs
            .chunks_exact(3)
            .map(|chunk| UpgradeableProgramSpec {
                address: chunk[0].clone(),
                path: chunk[1].clone(),
                upgrade_authority: chunk[2].clone(),
            })
            .collect()
    }

    fn validator_args(&self) -> Vec<String> {
        let mut args = self
            .validator_arg_groups
            .iter()
            .flat_map(|group| group.split_whitespace().map(str::to_string))
            .collect::<Vec<_>>();
        args.extend(self.trailing_validator_args.iter().cloned());
        args
    }
}

fn main() {
    if let Err(error) = run(Cli::parse()) {
        eprintln!("error: {error:#}");
        std::process::exit(1);
    }
}

fn run(cli: Cli) -> Result<()> {
    match cli.command {
        Some(CliCommand::TestValidator(opts)) => run_test_validator(*opts),
        Some(CliCommand::StartProver(opts)) => run_start_prover(opts),
        None => {
            Cli::command().print_help()?;
            println!();
            Ok(())
        }
    }
}

fn run_test_validator(opts: TestValidatorOptions) -> Result<()> {
    if opts.stop {
        stop_test_env(&opts);
        return Ok(());
    }

    println!("Starting local validator with zolana fixtures");
    kill_test_validator(opts.rpc_port);
    thread::sleep(Duration::from_secs(1));

    let mut validator = if opts.use_surfpool_backend() {
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

    println!("Local validator environment is ready");
    std::mem::forget(validator);
    Ok(())
}

fn run_start_prover(opts: StartProverOptions) -> Result<()> {
    start_prover_service(opts.prover_port, opts.redis_url.as_deref())
}

fn surfpool_args(opts: &TestValidatorOptions) -> Result<Vec<String>> {
    if opts.faucet_port.is_some() {
        bail!("--faucet-port is only supported with --no-use-surfpool");
    }
    if opts.ledger.is_some() {
        bail!("--ledger is only supported with --no-use-surfpool");
    }

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

    if !opts.skip_system_programs {
        add_system_program_args(&mut args)?;
    }
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
    if let Some(faucet_port) = opts.faucet_port {
        args.push(format!("--faucet-port={faucet_port}"));
    }
    if let Some(ledger) = &opts.ledger {
        args.push("--ledger".to_string());
        args.push(ledger.clone());
    }

    if !opts.skip_system_programs {
        add_system_program_args(&mut args)?;
    }
    add_additional_program_args(&mut args, opts);
    add_account_dir_args(&mut args, opts)?;

    if let Some(geyser_config) = &opts.geyser_config {
        args.push("--geyser-plugin-config".to_string());
        args.push(geyser_config.clone());
    }
    args.extend(opts.validator_args());
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
    for program in opts.sbf_program_specs() {
        args.push("--bpf-program".to_string());
        args.push(program.address);
        args.push(program.path);
    }

    for program in opts.upgradeable_program_specs() {
        args.push("--upgradeable-program".to_string());
        args.push(program.address);
        args.push(program.path);
        args.push(program.upgrade_authority);
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
    if let Ok(dir) = env::var("ZOLANA_PROGRAMS_DIR") {
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

    for dir in fixture_dirs()? {
        let candidate = dir.join("bin").join(name);
        if candidate.exists() {
            return Ok(candidate);
        }
    }

    bail!("missing {name}; run `just build-fixtures` with a fixture source tree, or set ZOLANA_FIXTURES_DIR")
}

fn accounts_dir() -> Result<PathBuf> {
    if let Ok(dir) = env::var("ZOLANA_ACCOUNTS_DIR") {
        let path = PathBuf::from(dir);
        if path.exists() {
            return Ok(path);
        }
    }

    for dir in fixture_dirs()? {
        let path = dir.join("accounts");
        if path.exists() {
            return Ok(path);
        }
    }

    bail!("missing account fixtures; run `just build-fixtures` with a fixture source tree, or set ZOLANA_FIXTURES_DIR")
}

fn fixture_dirs() -> Result<Vec<PathBuf>> {
    let mut dirs = Vec::new();
    if let Ok(dir) = env::var("ZOLANA_FIXTURES_DIR") {
        dirs.push(PathBuf::from(dir));
    }

    dirs.push(project_root()?.join("target/fixtures/staging"));

    if let Ok(cache) = fixtures_cache_dir() {
        dirs.push(cache);
    }

    Ok(dirs)
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
        &["PROVER_BIN", "ZOLANA_PROVER_BIN"],
        &["target/prover-server"],
        &["prover-server"],
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
    let mut child = spawn_service(&prover, &args, "prover-server")?;
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
    if !opts.skip_prover {
        kill_name("prover-server");
        kill_port(opts.prover_port);
    }
    kill_test_validator(opts.rpc_port);
}

fn kill_test_validator(rpc_port: u16) {
    remove_launchd_validators();
    kill_name("solana-test-validator");
    kill_name("surfpool");
    kill_port(rpc_port);
}

fn remove_launchd_validators() {
    if !cfg!(target_os = "macos") {
        return;
    }

    for label in ["com.zolana.localnet", "com.zolana.localnet-proofless"] {
        let _ = Command::new("launchctl")
            .args(["remove", label])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }
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
    if let Ok(path) = env::var("ZOLANA_PROVER_KEYS_DIR") {
        return Ok(PathBuf::from(path));
    }

    let home = env::var("HOME").context("HOME is not set")?;
    Ok(Path::new(&home).join(".config/zolana/proving-keys"))
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

#[cfg(test)]
mod tests {
    use super::*;

    fn strings(values: &[&str]) -> Vec<String> {
        values.iter().map(|value| (*value).to_string()).collect()
    }

    fn parse_cli(values: &[&str]) -> Cli {
        Cli::try_parse_from(std::iter::once("zolana").chain(values.iter().copied()))
            .expect("parse cli")
    }

    fn parse_validator(values: &[&str]) -> TestValidatorOptions {
        match parse_cli(
            &std::iter::once("test-validator")
                .chain(values.iter().copied())
                .collect::<Vec<_>>(),
        )
        .command
        .expect("command")
        {
            CliCommand::TestValidator(opts) => *opts,
            CliCommand::StartProver(_) => panic!("expected test-validator command"),
        }
    }

    #[test]
    fn test_validator_help_documents_localnet_flags() {
        let mut command = Cli::command();
        let help = command
            .find_subcommand_mut("test-validator")
            .expect("test-validator subcommand")
            .render_long_help()
            .to_string();

        for flag in [
            "--skip-system-programs",
            "--faucet-port <PORT>",
            "--ledger <PATH>",
            "--sbf-program <ADDRESS> <PATH>",
        ] {
            assert!(help.contains(flag), "missing help entry for {flag}");
        }
    }

    #[test]
    fn clap_accepts_top_level_and_command_help() {
        for args in [
            ["zolana", "--help"].as_slice(),
            ["zolana", "test-validator", "--help"].as_slice(),
            ["zolana", "start-prover", "--help"].as_slice(),
        ] {
            let error = Cli::try_parse_from(args).expect_err("help exits early");
            assert_eq!(error.kind(), clap::error::ErrorKind::DisplayHelp);
        }
    }

    #[test]
    fn parses_local_validator_flags() {
        let opts = parse_validator(&[
            "--no-use-surfpool",
            "--skip-prover",
            "--skip-system-accounts",
            "--skip-system-programs",
            "--rpc-port",
            "8901",
            "--faucet-port",
            "9901",
            "--ledger",
            "target/localnet/ledger",
            "--sbf-program",
            "Pool111111111111111111111111111111111111111",
            "target/deploy/pool.so",
            "--sbf-program",
            "Zone111111111111111111111111111111111111111",
            "target/deploy/zone.so",
        ]);

        assert!(!opts.use_surfpool_backend());
        assert!(opts.skip_prover);
        assert!(opts.skip_system_accounts);
        assert!(opts.skip_system_programs);
        assert_eq!(opts.rpc_port, 8901);
        assert_eq!(opts.faucet_port, Some(9901));
        assert_eq!(opts.ledger.as_deref(), Some("target/localnet/ledger"));
        let programs = opts.sbf_program_specs();
        assert_eq!(programs.len(), 2);
        assert_eq!(
            programs[0].address,
            "Pool111111111111111111111111111111111111111"
        );
        assert_eq!(programs[0].path, "target/deploy/pool.so");
        assert_eq!(
            programs[1].address,
            "Zone111111111111111111111111111111111111111"
        );
        assert_eq!(programs[1].path, "target/deploy/zone.so");
    }

    #[test]
    fn builds_solana_validator_args_for_program_tests_without_fixtures() {
        let opts = parse_validator(&[
            "--no-use-surfpool",
            "--skip-system-accounts",
            "--skip-system-programs",
            "--rpc-port",
            "8899",
            "--faucet-port",
            "9900",
            "--ledger",
            "target/localnet/ledger",
            "--sbf-program",
            "Pool111111111111111111111111111111111111111",
            "target/deploy/pool.so",
            "--sbf-program",
            "Zone111111111111111111111111111111111111111",
            "target/deploy/zone.so",
        ]);

        let actual = solana_validator_args(&opts).expect("build solana validator args");
        let expected = strings(&[
            "--reset",
            "--limit-ledger-size=10000",
            "--rpc-port=8899",
            "--bind-address=127.0.0.1",
            "--quiet",
            "--faucet-port=9900",
            "--ledger",
            "target/localnet/ledger",
            "--bpf-program",
            "Pool111111111111111111111111111111111111111",
            "target/deploy/pool.so",
            "--bpf-program",
            "Zone111111111111111111111111111111111111111",
            "target/deploy/zone.so",
        ]);

        assert_eq!(actual, expected);
    }

    #[test]
    fn rejects_solana_validator_only_flags_with_surfpool() {
        let opts = parse_validator(&["--ledger", "target/localnet/ledger"]);
        let error = surfpool_args(&opts).expect_err("surfpool should reject --ledger");
        assert!(error.to_string().contains("--ledger"));

        let opts = parse_validator(&["--faucet-port", "9900"]);
        let error = surfpool_args(&opts).expect_err("surfpool should reject --faucet-port");
        assert!(error.to_string().contains("--faucet-port"));
    }

    #[test]
    fn parses_start_prover_options() {
        let command = parse_cli(&[
            "start-prover",
            "--port",
            "3002",
            "--redis-url",
            "redis://localhost:6379/15",
        ])
        .command
        .expect("command");
        let CliCommand::StartProver(opts) = command else {
            panic!("expected start-prover command");
        };

        assert_eq!(opts.prover_port, 3002);
        assert_eq!(opts.redis_url.as_deref(), Some("redis://localhost:6379/15"));
    }
}
