//! `localnet`, the `zolana` cli's validator plus the ring rpc of the release of the binary.

use std::{
    env,
    fs::File,
    net::SocketAddr,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    time::Duration,
};

use anyhow::{ensure, Context as _, Result};
use serde::Deserialize;
use zolana_cli_common::{
    config_dir,
    process::{answers, process_scope, spawn_owned, stop_owned_listener, wait_until},
    release::{host_platform, make_executable},
};

use crate::{
    config::{RingConfig, Target, Urls},
    file, keys, line, probe,
    release::{RingKey, RingRelease},
    tool::{Tool, SOLANA_TEST_VALIDATOR, ZOLANA},
    ui::{self, icon},
    workspace::{Workspace, WRONG_TARGET},
    Context, LocalnetArgs, AUDITOR_KEY_FILE,
};

/// SIMD-0500 off, the ring program deploys as SBPF v0 like on devnet.
const SBPF_V0_FEATURE: &str = "B8JJXCy5amZyWG9r7EnUYLwzXSXTxG7GZ1qZ1qggo83g";
const RING_RPC: Tool = Tool::new(
    "ring-rpc serve",
    "rerun `zolana-ring localnet`, it downloads the ring rpc of the release",
);
const READY_TIMEOUT: Duration = Duration::from_secs(300);
const POLL: Duration = Duration::from_secs(2);

#[derive(Deserialize)]
struct ProverHealth {
    circuits: Vec<String>,
}

/// The target is recorded first, a failed bring-up still leaves ring.toml on localnet.
pub fn run(config_path: &Path, config: &RingConfig, args: LocalnetArgs) -> Result<()> {
    probe::print_urls(config);
    if !args.no_start {
        bring_up(config, &config_path.with_file_name(AUDITOR_KEY_FILE), true)?;
        println!("\nlocalnet ready, next `zolana-ring pipeline`");
    }
    Ok(())
}

/// Localnet only, `devnet` probes its services instead of starting them.
pub fn ensure(ctx: &Context) -> Result<()> {
    if ctx.config.target == Target::Localnet {
        bring_up(&ctx.config, &ctx.path(Path::new(AUDITOR_KEY_FILE)), false)?;
    }
    Ok(())
}

/// A live validator keeps its ledger, the ring rpc is replaced only on request.
fn bring_up(config: &RingConfig, auditor_key: &Path, replace: bool) -> Result<()> {
    if let Some(workspace) = Workspace::from_env()? {
        return bring_up_workspace(&workspace, config, auditor_key, replace);
    }
    let urls = config.urls();
    let [rpc, photon, prover, ring_rpc] = ports(urls)?;
    let release = RingRelease::from_lock()?;
    if answers(local(rpc)) {
        line("validator", format_args!("{} answers", urls.rpc));
    } else {
        ZOLANA.check_installed()?;
        SOLANA_TEST_VALIDATOR.check_installed()?;
        let keys_dir = prover_keys_dir()?;
        for key in RingKey::ALL {
            release.ensure_as(release.key(key)?, &keys_dir.join(key.file_name()))?;
        }
        line("validator", "zolana dev start");
        let mut command = Command::new("zolana");
        command.args(["dev", "start"]);
        ZOLANA
            .named("zolana dev start")
            .run(dev_start(&mut command, [rpc, photon, prover]))?;
    }
    check_prover_serves_custom_ring(&urls.prover)?;
    if !replace && answers(local(ring_rpc)) {
        line("ring rpc", format_args!("{} answers", urls.ring_rpc));
        return Ok(());
    }
    keys::ensure(auditor_key)?;
    let (os, arch) = host_platform()?;
    let binary = release.ensure(release.binary("ring_rpc", os, arch)?)?;
    make_executable(&binary)?;
    let command = serve(&binary, config, ring_rpc, auditor_key);
    start_ring_rpc(command, config, ring_rpc, &scope()?)
}

/// Every service from the workspace build, the ring rpc in the foreground.
fn bring_up_workspace(
    workspace: &Workspace,
    config: &RingConfig,
    auditor_key: &Path,
    replace: bool,
) -> Result<()> {
    ensure!(config.target == Target::Localnet, WRONG_TARGET);
    workspace.check_artifacts()?;
    let urls = config.urls();
    let services = [&urls.rpc, &urls.indexer, &urls.prover, &urls.ring_rpc];
    for url in services {
        ensure!(
            Urls::is_local(url),
            "workspace services require a loopback URL, found {url}"
        );
    }
    let ports = ports(urls)?;
    let [rpc, photon, prover, ring_rpc] = ports;
    if !replace {
        answering(ports.into_iter().zip(services))?;
        return check_prover_serves_custom_ring(&urls.prover);
    }
    let addr = local(ring_rpc);
    ensure!(!answers(addr), "{addr} stays busy, stop the listener on it");
    if !answers(local(rpc)) {
        let snapshots = workspace.account_snapshots()?;
        let mut command = workspace.command()?;
        command
            .args(["dev", "start", "--local"])
            .args(["--photon-start-slot", "0", "--account-dir"])
            .arg(snapshots)
            .arg("--sbf-program")
            .arg(zolana_interface::pda::shielded_pool_program_id().to_string())
            .arg(workspace.shielded_pool_so()?);
        let dev_start = dev_start(&mut command, [rpc, photon, prover]);
        ZOLANA.named("workspace zolana dev start").run(dev_start)?;
    }
    answering([(photon, &urls.indexer), (prover, &urls.prover)])?;
    check_prover_serves_custom_ring(&urls.prover)?;
    keys::ensure(auditor_key)?;
    ui::heading(icon::RING, "workspace services ready");
    let next = "zolana-ring pipeline in a second terminal with the same environment";
    line("next", next);
    let ring_rpc_binary = workspace.ring_rpc()?;
    RING_RPC.run(&mut serve(&ring_rpc_binary, config, ring_rpc, auditor_key))
}

fn answering<'a>(services: impl IntoIterator<Item = (u16, &'a String)>) -> Result<()> {
    for (port, url) in services {
        let next = "run `zolana-ring dev` first";
        ensure!(
            answers(local(port)),
            "local workspace service is unavailable at {url}, {next}"
        );
    }
    Ok(())
}

fn local(port: u16) -> SocketAddr {
    SocketAddr::from(([127, 0, 0, 1], port))
}

/// RPC, Photon, prover and ring rpc, in that order.
fn ports(urls: &Urls) -> Result<[u16; 4]> {
    let port = |url: &str| {
        let hint = "localnet URLs are http://127.0.0.1:<port>";
        Urls::port(url).with_context(|| format!("{url} carries no port, {hint}"))
    };
    let [rpc, indexer, prover, ring_rpc] = [&urls.rpc, &urls.indexer, &urls.prover, &urls.ring_rpc];
    Ok([port(rpc)?, port(indexer)?, port(prover)?, port(ring_rpc)?])
}

/// The service ports and the SBPF v0 deployment both `zolana dev start` paths take.
fn dev_start(command: &mut Command, ports: [u16; 3]) -> &mut Command {
    for (flag, port) in ["--rpc-port", "--photon-port", "--prover-port"]
        .iter()
        .zip(ports)
    {
        command.arg(flag).arg(port.to_string());
    }
    command.args(["--", "--deactivate-feature", SBPF_V0_FEATURE])
}

/// Local mode, `init` pins the key from `keys/`.
fn serve(binary: &Path, config: &RingConfig, port: u16, auditor_key: &Path) -> Command {
    let urls = config.urls();
    let mut command = Command::new(binary);
    command
        .args(["serve", "--port", &port.to_string()])
        .args(["--indexer-url", &urls.indexer, "--rpc-url", &urls.rpc])
        .arg("--auditor-key-file")
        .arg(auditor_key)
        .args(["--ring-program-id", &config.program_id.to_string()]);
    command
}

/// Receipts of the services this cli started, the task scope when one is set.
fn scope() -> Result<PathBuf> {
    if let Some(scope) = process_scope()? {
        return Ok(scope);
    }
    let scope = config_dir().join("localnet/scope");
    file::create_dir_all(&scope)?;
    Ok(scope)
}

/// Replaces a ring rpc this cli started, a listener it did not start is refused.
fn start_ring_rpc(
    mut command: Command,
    config: &RingConfig,
    port: u16,
    scope: &Path,
) -> Result<()> {
    stop_owned_listener(scope, port)?;
    let log_dir = config_dir().join("localnet");
    file::create_dir_all(&log_dir)?;
    let log = log_dir.join("ring-rpc.log");
    let shown = log.display();
    let open = || File::create(&log).with_context(|| format!("cannot open the log {shown}"));
    command.stdin(Stdio::null()).stdout(open()?).stderr(open()?);
    spawn_owned(scope, "ring-rpc", &mut command)?;
    let addr = local(port);
    let ready = wait_until(READY_TIMEOUT, POLL, || answers(addr));
    ensure!(
        ready,
        "the ring rpc did not answer on {addr} within {READY_TIMEOUT:?}, see {shown}"
    );
    let (url, program) = (&config.urls().ring_rpc, config.program_id);
    line("ring rpc", format_args!("{url} serving {program}, {shown}"));
    Ok(())
}

/// Mirrors the `zolana` cli, `ZOLANA_CONFIG_DIR` does not move it.
fn prover_keys_dir() -> Result<PathBuf> {
    if let Some(dir) = env::var_os("ZOLANA_PROVER_KEYS_DIR") {
        return Ok(PathBuf::from(dir));
    }
    let home = env::var_os("HOME").context("HOME is not set")?;
    Ok(PathBuf::from(home).join(".config/zolana/proving-keys"))
}

/// The prover of an older `zolana` release answers health without the ring circuit.
fn check_prover_serves_custom_ring(prover_url: &str) -> Result<()> {
    let url = probe::service_url(prover_url, "/health");
    let health: ProverHealth = probe::http(POLL, READY_TIMEOUT)
        .get(&url)
        .send()
        .and_then(reqwest::blocking::Response::error_for_status)
        .and_then(reqwest::blocking::Response::json)
        .with_context(|| format!("cannot read the prover health at {url}"))?;
    let serves = |key: &RingKey| health.circuits.iter().any(|name| name == key.circuit());
    let newer = "install the zolana cli of a newer localnet release";
    ensure!(
        RingKey::ALL.iter().all(serves),
        "the prover at {url} serves no custom-ring circuit, {newer}"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::net::{TcpListener, TcpStream};

    use super::*;

    #[test]
    fn a_foreign_listener_on_the_ring_rpc_port_is_refused_and_left_running() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("addr");
        let config: RingConfig = toml::from_str(&format!(
            "name = \"x\"\ntarget = \"localnet\"\nprogram_id = \"11111111111111111111111111111111\"\nauthority_keypair = \"a.json\"\n\n[localnet]\nrpc = \"r\"\nindexer = \"i\"\nprover = \"p\"\nring_rpc = \"http://{addr}\"\n\n[devnet]\nrpc = \"r\"\nindexer = \"i\"\nprover = \"p\"\nring_rpc = \"g\"\n"
        ))
        .expect("ring.toml");
        let scope = env::temp_dir().join(format!("ring-localnet-scope-{}", std::process::id()));
        file::create_dir_all(&scope).expect("scope");
        let command = serve(
            Path::new("/nonexistent/ring-rpc"),
            &config,
            addr.port(),
            Path::new("k"),
        );
        let error =
            start_ring_rpc(command, &config, addr.port(), &scope).expect_err("foreign listener");
        assert_eq!(
            error.to_string(),
            format!(
                "port {} is held by a process this cli did not start",
                addr.port()
            )
        );
        assert!(
            TcpStream::connect(addr).is_ok(),
            "the foreign listener still answers"
        );
        std::fs::remove_dir_all(scope).expect("cleanup");
    }

    #[test]
    fn localnet_ports_come_from_each_service_url() {
        let urls = Urls {
            rpc: "http://127.0.0.1:8899".to_owned(),
            indexer: "http://127.0.0.1:8784".to_owned(),
            prover: "http://127.0.0.1:3001".to_owned(),
            ring_rpc: "http://127.0.0.1:8785".to_owned(),
            ring_rpc_pubkey: None,
            prover_tee: None,
        };
        assert_eq!(ports(&urls).expect("ports"), [8899, 8784, 3001, 8785]);
        let portless = Urls {
            ring_rpc: "http://localhost".to_owned(),
            ..urls
        };
        let error = ports(&portless).expect_err("no port").to_string();
        assert!(
            error.starts_with("http://localhost carries no port"),
            "{error}"
        );
    }
}
