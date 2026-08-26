//! `localnet`, the `zolana` cli's validator plus the ring rpc of the release of the binary.

use std::{
    env,
    fs::File,
    io,
    net::{SocketAddr, TcpStream},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    thread,
    time::{Duration, Instant},
};

use serde::Deserialize;
use thiserror::Error;
use zolana_ring_rpc::KeyFileError;

use crate::{
    config::{ConfigError, RingConfig, Target, Urls},
    file::{self, FileError},
    keys, line, probe,
    release::{self, ReleaseError, RingRelease},
    tool::{Tool, ToolError, SOLANA_TEST_VALIDATOR, ZOLANA},
    AuditorKeyArgs, Context, LocalnetArgs, ProjectRoot, AUDITOR_KEY_FILE,
};

/// SIMD-0500 off, the ring program deploys as SBPF v0 like on devnet.
const SBPF_V0_FEATURE: &str = "B8JJXCy5amZyWG9r7EnUYLwzXSXTxG7GZ1qZ1qggo83g";
const PROVING_KEY_FILE: &str = "custom_ring.key";
const RING_RPC: Tool = Tool {
    name: "ring-rpc serve",
    install: "rerun `zolana-ring localnet`, it downloads the ring rpc of the release",
};
const READY_TIMEOUT: Duration = Duration::from_secs(300);
const STOP_TIMEOUT: Duration = Duration::from_secs(10);
const POLL: Duration = Duration::from_secs(2);

#[derive(Debug, Error)]
pub enum LocalnetError {
    #[error(transparent)]
    Config(#[from] ConfigError),
    #[error(transparent)]
    Release(#[from] ReleaseError),
    #[error(transparent)]
    Tool(#[from] ToolError),
    #[error(transparent)]
    File(#[from] FileError),
    #[error(transparent)]
    KeyFile(#[from] KeyFileError),
    #[error("{url} carries no port, localnet URLs are http://127.0.0.1:<port>")]
    Port { url: String },
    #[error("the prover at {url} serves no custom-ring circuit, install the zolana cli of a newer localnet release")]
    StaleProver { url: String },
    #[error("cannot read the prover health at {url}")]
    ProverHealth {
        url: String,
        #[source]
        source: reqwest::Error,
    },
    #[error("{addr} stays busy, stop the listener on it")]
    PortBusy { addr: SocketAddr },
    #[error("the ring rpc did not answer on {addr} within {timeout:?}, see {log}")]
    NotReady {
        addr: SocketAddr,
        timeout: Duration,
        log: PathBuf,
    },
    #[error("cannot open the log {path}")]
    Log {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
}

#[derive(Debug, Clone, Copy)]
struct Ports {
    rpc: u16,
    photon: u16,
    prover: u16,
    ring_rpc: u16,
}

#[derive(Debug, Clone, Copy)]
enum LiveRingRpc {
    Keep,
    Replace,
}

#[must_use]
struct RingRpc<'a> {
    release: &'a RingRelease,
    urls: &'a Urls,
    auditor_key: PathBuf,
    program_id: solana_address::Address,
    log_dir: &'a Path,
}

/// The target is recorded first, a failed bring-up still leaves ring.toml on localnet.
pub fn run(
    config_path: &Path,
    config: &RingConfig,
    args: LocalnetArgs,
) -> Result<(), LocalnetError> {
    probe::print_urls(config);
    if args.no_start {
        return Ok(());
    }
    bring_up(config_path, config, LiveRingRpc::Replace)?;
    println!();
    println!("localnet ready, next `zolana-ring pipeline`");
    Ok(())
}

/// Localnet only, `devnet` probes its services instead of starting them.
pub fn ensure(ctx: &Context) -> Result<(), LocalnetError> {
    if matches!(ctx.config.target, Target::Localnet) {
        bring_up(&ctx.config_path, &ctx.config, LiveRingRpc::Keep)?;
    }
    Ok(())
}

/// A live validator keeps its ledger, the ring rpc is replaced only on request.
fn bring_up(
    config_path: &Path,
    config: &RingConfig,
    live_ring_rpc: LiveRingRpc,
) -> Result<(), LocalnetError> {
    let urls = config.urls();
    let ports = Ports::of(urls)?;
    let release = RingRelease::from_lock()?;
    if answers(local(ports.rpc)) {
        line("validator", format_args!("{} answers", urls.rpc));
    } else {
        for tool in [ZOLANA, SOLANA_TEST_VALIDATOR] {
            tool.check_installed()?;
        }
        release.ensure_as(
            release.proving_key()?,
            &prover_keys_dir()?.join(PROVING_KEY_FILE),
        )?;
        start_validator(ports)?;
    }
    check_prover_serves_custom_ring(&urls.prover)?;
    if matches!(live_ring_rpc, LiveRingRpc::Keep) && answers(local(ports.ring_rpc)) {
        line("ring rpc", format_args!("{} answers", urls.ring_rpc));
        return Ok(());
    }
    let project_root = ProjectRoot::for_config(config_path);
    let auditor_key = project_root.resolve(Path::new(AUDITOR_KEY_FILE));
    if !auditor_key.is_file() {
        keys::run(
            &project_root,
            AuditorKeyArgs {
                key_file: PathBuf::from(AUDITOR_KEY_FILE),
                create: true,
            },
        )?;
    }
    RingRpc {
        release: &release,
        urls,
        auditor_key,
        program_id: config.program_id,
        log_dir: &release::config_dir().join("localnet"),
    }
    .start(ports.ring_rpc)
}

fn local(port: u16) -> SocketAddr {
    SocketAddr::from(([127, 0, 0, 1], port))
}

impl Ports {
    fn of(urls: &Urls) -> Result<Self, LocalnetError> {
        let port = |url: &str| {
            Urls::port(url).ok_or_else(|| LocalnetError::Port {
                url: url.to_owned(),
            })
        };
        Ok(Self {
            rpc: port(&urls.rpc)?,
            photon: port(&urls.indexer)?,
            prover: port(&urls.prover)?,
            ring_rpc: port(&urls.ring_rpc)?,
        })
    }
}

/// Mirrors the `zolana` cli, `ZOLANA_CONFIG_DIR` does not move it.
fn prover_keys_dir() -> Result<PathBuf, LocalnetError> {
    if let Some(dir) = env::var_os("ZOLANA_PROVER_KEYS_DIR") {
        return Ok(PathBuf::from(dir));
    }
    let home = env::var_os("HOME").ok_or(ConfigError::HomeUnset)?;
    Ok(PathBuf::from(home)
        .join(".config")
        .join("zolana")
        .join("proving-keys"))
}

#[derive(Deserialize)]
struct ProverHealth {
    circuits: Vec<String>,
}

/// The prover of an older `zolana` release answers health without the ring circuit.
fn check_prover_serves_custom_ring(prover_url: &str) -> Result<(), LocalnetError> {
    let url = probe::service_url(prover_url, "/health");
    let health = probe::http(POLL, READY_TIMEOUT)
        .get(&url)
        .send()
        .and_then(reqwest::blocking::Response::error_for_status)
        .and_then(|response| response.json::<ProverHealth>())
        .map_err(|source| LocalnetError::ProverHealth {
            url: url.clone(),
            source,
        })?;
    if health
        .circuits
        .iter()
        .any(|circuit| circuit == "custom-ring")
    {
        return Ok(());
    }
    Err(LocalnetError::StaleProver { url })
}

/// `zolana dev start` returns once the validator, Photon and the prover answer.
fn start_validator(ports: Ports) -> Result<(), LocalnetError> {
    line("validator", "zolana dev start");
    ZOLANA.named("zolana dev start").run(
        Command::new("zolana")
            .args(["dev", "start", "--no-use-surfpool"])
            .args(["--rpc-port", &ports.rpc.to_string()])
            .args(["--photon-port", &ports.photon.to_string()])
            .args(["--prover-port", &ports.prover.to_string()])
            .args(["--", "--deactivate-feature", SBPF_V0_FEATURE]),
    )?;
    Ok(())
}

impl RingRpc<'_> {
    /// Local mode, `init` pins the key from `keys/`.
    fn start(self, port: u16) -> Result<(), LocalnetError> {
        let (os, arch) = release::host_platform()?;
        let binary = self.release.binary("ring_rpc", os, arch)?;
        let path = self.release.ensure(binary)?;
        file::make_executable(&path)?;
        file::create_dir_all(self.log_dir)?;
        let log = self.log_dir.join("ring-rpc.log");
        let addr = local(port);
        stop_listeners(addr)?;
        let open = || {
            File::create(&log).map_err(|source| LocalnetError::Log {
                path: log.clone(),
                source,
            })
        };
        let (out, err) = (open()?, open()?);
        RING_RPC.spawn(
            Command::new(&path)
                .arg("serve")
                .args(["--port", &port.to_string()])
                .args(["--indexer-url", &self.urls.indexer])
                .args(["--rpc-url", &self.urls.rpc])
                .arg("--auditor-key-file")
                .arg(&self.auditor_key)
                .args(["--ring-program-id", &self.program_id.to_string()])
                .stdin(Stdio::null())
                .stdout(out)
                .stderr(err),
        )?;
        if !wait_until(READY_TIMEOUT, || answers(addr)) {
            return Err(LocalnetError::NotReady {
                addr,
                timeout: READY_TIMEOUT,
                log,
            });
        }
        line(
            "ring rpc",
            format_args!(
                "{} serving {}, {}",
                self.urls.ring_rpc,
                self.program_id,
                log.display()
            ),
        );
        Ok(())
    }
}

/// A listener left on the port is replaced, as `zolana dev start` does with its services.
fn stop_listeners(addr: SocketAddr) -> Result<(), LocalnetError> {
    if !answers(addr) {
        return Ok(());
    }
    let pids = Command::new("lsof")
        .arg(format!("-ti:{}", addr.port()))
        .output()
        .map(|output| String::from_utf8_lossy(&output.stdout).into_owned())
        .unwrap_or_default();
    for pid in pids.split_whitespace() {
        let _ = Command::new("kill").arg(pid).status();
    }
    if wait_until(STOP_TIMEOUT, || !answers(addr)) {
        return Ok(());
    }
    Err(LocalnetError::PortBusy { addr })
}

fn answers(addr: SocketAddr) -> bool {
    TcpStream::connect_timeout(&addr, POLL).is_ok()
}

fn wait_until(timeout: Duration, ready: impl Fn() -> bool) -> bool {
    let started = Instant::now();
    loop {
        if ready() {
            return true;
        }
        if started.elapsed() >= timeout {
            return false;
        }
        thread::sleep(POLL);
    }
}
