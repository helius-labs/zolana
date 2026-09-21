use std::{path::Path, thread, time::Duration};

use anyhow::{anyhow, bail, Context, Result};

use crate::{
    args::TestValidatorOptions,
    config::{READINESS_STABLE_CHECKS, READINESS_TIMEOUT, SCOPED_PHOTON_BLOCK_FETCHES},
    http::{wait_for_http_get_with_child, wait_for_rpc_with_child},
    process::{
        find_binary, path_string, process_scope, remove_launchd_validators,
        require_scoped_port_available, spawn_service, stop_name, stop_port, Service,
    },
    prover::start_prover_service,
    release::Release,
};

pub(crate) fn run_test_validator(mut opts: TestValidatorOptions) -> Result<()> {
    if opts.stop {
        println!("Stopping local validator environment");
        stop_test_env(&opts);
        println!("Local validator environment stopped");
        return Ok(());
    }

    println!("Starting local validator");
    stop_test_validator(opts.rpc_port);
    require_scoped_port_available(opts.rpc_port)?;
    if opts.use_surfpool_backend() && process_scope()?.is_some() {
        for port in scoped_surfpool_ports(&opts)? {
            require_scoped_port_available(port.port)?;
        }
    }
    thread::sleep(Duration::from_secs(1));

    // Default rail: fetch version-pinned programs, initialized account snapshots,
    // and helper binaries from the release. `--local` (or explicit --sbf-program)
    // keeps the fully-local artifacts used by dev and CI. Release programs and
    // snapshots are folded into `opts` so the arg builders keep a single source.
    let release = if opts.use_release() {
        Some(Release::load()?)
    } else {
        None
    };
    if let Some(release) = &release {
        println!("Using release {} artifacts", release.tag());
        for spec in release.program_specs()? {
            opts.sbf_programs.push(spec.address);
            opts.sbf_programs.push(spec.path);
        }
        opts.account_dirs
            .push(path_string(&release.accounts_dir()?)?);
    }

    let mut validator = if opts.use_surfpool_backend() {
        let surfpool = match &release {
            Some(release) => release.surfpool_binary()?,
            None => find_binary(&["SURFPOOL_BIN"], &["target/tools/surfpool"], &["surfpool"])?,
        };
        let args = surfpool_args(&opts)?;
        println!(
            "Starting surfpool: {} {}",
            surfpool.display(),
            args.join(" ")
        );
        spawn_service(&surfpool, &args, Service::Surfpool, &opts.log_dir)?
    } else {
        let validator = find_binary(&[], &[], &["solana-test-validator"])?;
        let args = solana_validator_args(&opts)?;
        println!(
            "Starting solana-test-validator: {} {}",
            validator.display(),
            args.join(" ")
        );
        spawn_service(&validator, &args, Service::Validator, &opts.log_dir)?
    };

    wait_for_rpc_with_child(
        opts.rpc_port,
        READINESS_TIMEOUT,
        READINESS_STABLE_CHECKS,
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
        let prover_binary = match &release {
            Some(release) => Some(release.prover_binary()?),
            None => None,
        };
        start_prover_service(
            opts.prover_port,
            None,
            opts.prover_auto_download,
            &opts.log_dir,
            prover_binary.as_deref(),
        )?;
    }

    if opts.start_indexer() {
        let photon_binary = match &release {
            Some(release) => Some(release.photon_binary()?),
            None => None,
        };
        start_photon_service(&opts, photon_binary.as_deref())?;
    }

    println!("Local validator environment is ready");
    std::mem::forget(validator);
    Ok(())
}

pub(crate) fn surfpool_args(opts: &TestValidatorOptions) -> Result<Vec<String>> {
    if opts.faucet_port.is_some() {
        bail!("--faucet-port is only supported with --no-use-surfpool");
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
    if process_scope()?.is_some() {
        for port in scoped_surfpool_ports(opts)? {
            if !port.explicit {
                args.extend([port.flag.to_string(), port.port.to_string()]);
            }
        }
    }

    // `--ledger` and `--limit-ledger-size` are dropped rather than refused.
    // surfpool keeps its state in memory, so a caller asking for a ledger
    // directory is asking for per-run isolation, which it already has; refusing
    // would make every caller special-case the backend for nothing.

    add_additional_program_args(&mut args, opts);
    add_account_dir_args(&mut args, opts);

    if let Some(geyser_config) = &opts.geyser_config {
        args.push("--geyser-plugin-config".to_string());
        args.push(geyser_config.clone());
    }
    args.extend(surfpool_validator_args(opts)?);
    Ok(args)
}

#[derive(Debug, PartialEq, Eq)]
struct ScopedPort {
    flag: &'static str,
    port: u16,
    explicit: bool,
}

fn scoped_surfpool_ports(opts: &TestValidatorOptions) -> Result<[ScopedPort; 2]> {
    let passthrough = opts.validator_args();
    let port = |flag: &'static str, offset: u16| -> Result<ScopedPort> {
        let supplied = passthrough.iter().enumerate().find_map(|(index, arg)| {
            if arg == flag {
                passthrough.get(index + 1).map(String::as_str)
            } else {
                arg.strip_prefix(&format!("{flag}="))
            }
        });
        let value = match supplied {
            Some(value) => value.parse().with_context(|| format!("invalid {flag}"))?,
            None => opts
                .rpc_port
                .checked_add(offset)
                .context("RPC port leaves no room for scoped auxiliary ports")?,
        };
        Ok(ScopedPort {
            flag,
            port: value,
            explicit: supplied.is_some(),
        })
    };
    let ports = [port("--ws-port", 1)?, port("--studio-port", 2)?];
    if ports[0].port == opts.rpc_port
        || ports[1].port == opts.rpc_port
        || ports[0].port == ports[1].port
    {
        bail!("scoped RPC, WebSocket and Studio ports must be distinct");
    }
    Ok(ports)
}

/// Translate passthrough validator arguments to surfpool's spelling.
///
/// solana-test-validator's `--deactivate-feature` means "never activate this";
/// surfpool's `--disable-feature` means "deactivate it from the mainnet
/// baseline it starts from". Both leave the gate off, which is what every
/// caller here wants, so the flag is renamed rather than reimplemented.
fn surfpool_validator_args(opts: &TestValidatorOptions) -> Result<Vec<String>> {
    let mut translated = Vec::new();
    let mut passthrough = opts.validator_args().into_iter();
    while let Some(arg) = passthrough.next() {
        match arg.as_str() {
            "--deactivate-feature" => {
                let feature = passthrough
                    .next()
                    .ok_or_else(|| anyhow!("--deactivate-feature needs a feature address"))?;
                translated.push("--disable-feature".to_string());
                translated.push(feature);
            }
            other => translated.push(other.to_string()),
        }
    }
    Ok(translated)
}

pub(crate) fn solana_validator_args(opts: &TestValidatorOptions) -> Result<Vec<String>> {
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

    add_additional_program_args(&mut args, opts);
    add_account_dir_args(&mut args, opts);

    if let Some(geyser_config) = &opts.geyser_config {
        args.push("--geyser-plugin-config".to_string());
        args.push(geyser_config.clone());
    }
    args.extend(opts.validator_args());
    Ok(args)
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

fn add_account_dir_args(args: &mut Vec<String>, opts: &TestValidatorOptions) {
    for account_dir in &opts.account_dirs {
        args.push("--account-dir".to_string());
        args.push(account_dir.clone());
    }
}

fn stop_test_env(opts: &TestValidatorOptions) {
    if !opts.skip_prover {
        stop_name("prover-server");
        stop_port(opts.prover_port);
    }
    if opts.start_indexer() {
        stop_name("photon");
        stop_port(opts.photon_port);
    }
    stop_test_validator(opts.rpc_port);
}

fn stop_test_validator(rpc_port: u16) {
    remove_launchd_validators();
    stop_name("solana-test-validator");
    stop_name("surfpool");
    stop_port(rpc_port);
}

fn start_photon_service(opts: &TestValidatorOptions, binary: Option<&Path>) -> Result<()> {
    stop_name("photon");
    stop_port(opts.photon_port);
    require_scoped_port_available(opts.photon_port)?;

    let photon = match binary {
        Some(path) => path.to_path_buf(),
        None => find_binary(
            &["ZOLANA_PHOTON_BIN"],
            &["target/release/photon", "target/debug/photon"],
            &["photon"],
        )?,
    };
    let rpc_url = format!("http://127.0.0.1:{}", opts.rpc_port);
    let mut args = vec![
        "--rpc-url".to_string(),
        rpc_url,
        "--port".to_string(),
        opts.photon_port.to_string(),
        "--start-slot".to_string(),
        opts.photon_start_slot.clone(),
    ];
    if process_scope()?.is_some() {
        args.extend([
            "--max-concurrent-block-fetches".to_string(),
            SCOPED_PHOTON_BLOCK_FETCHES.to_string(),
        ]);
    }
    if opts.photon_ring_projection {
        args.push("--enable-ring-projection".to_string());
    }
    if let Some(db_url) = &opts.photon_db_url {
        args.push("--db-url".to_string());
        args.push(db_url.clone());
    }

    const START_ATTEMPTS: u32 = 3;
    for attempt in 1..=START_ATTEMPTS {
        println!("Starting Photon: {} {}", photon.display(), args.join(" "));
        let mut child = spawn_service(&photon, &args, Service::Photon, &opts.log_dir)?;
        let readiness = wait_for_http_get_with_child(
            opts.photon_port,
            "/readiness",
            READINESS_TIMEOUT,
            READINESS_STABLE_CHECKS,
            &mut child,
            "photon",
        )
        .with_context(|| format!("Photon on port {} did not become ready", opts.photon_port));

        match readiness {
            Ok(()) => {
                println!(
                    "Photon indexer is ready at http://127.0.0.1:{}",
                    opts.photon_port
                );
                std::mem::forget(child);
                return Ok(());
            }
            Err(error) if attempt < START_ATTEMPTS => {
                eprintln!(
                    "Photon startup attempt {attempt}/{START_ATTEMPTS} failed: {error:#}; retrying"
                );
                let _ = child.kill();
                let _ = child.wait();
                stop_name("photon");
                stop_port(opts.photon_port);
                thread::sleep(Duration::from_secs(1));
            }
            Err(error) => return Err(error),
        }
    }

    unreachable!("Photon startup attempts are nonzero")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::args::parse_validator;

    fn strings(values: &[&str]) -> Vec<String> {
        values.iter().map(|value| (*value).to_string()).collect()
    }

    #[test]
    fn scoped_auxiliary_ports_follow_rpc_or_explicit_overrides() {
        let scoped = |flag, port, explicit| ScopedPort {
            flag,
            port,
            explicit,
        };
        let defaults = parse_validator(&["--rpc-port", "18899"]);
        assert_eq!(
            scoped_surfpool_ports(&defaults).unwrap(),
            [
                scoped("--ws-port", 18900, false),
                scoped("--studio-port", 18901, false),
            ]
        );
        let explicit = parse_validator(&[
            "--rpc-port",
            "18899",
            "--",
            "--ws-port",
            "18902",
            "--studio-port=18903",
        ]);
        assert_eq!(
            scoped_surfpool_ports(&explicit).unwrap(),
            [
                scoped("--ws-port", 18902, true),
                scoped("--studio-port", 18903, true),
            ]
        );
        let duplicate = parse_validator(&["--rpc-port", "18899", "--", "--ws-port", "18899"]);
        assert!(scoped_surfpool_ports(&duplicate).is_err());
        let overflow = parse_validator(&["--rpc-port", "65535"]);
        assert!(scoped_surfpool_ports(&overflow).is_err());
    }

    #[test]
    fn builds_solana_validator_args_for_program_tests() {
        let opts = parse_validator(&[
            "--no-use-surfpool",
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
            "Ring111111111111111111111111111111111111111",
            "target/deploy/ring.so",
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
            "Ring111111111111111111111111111111111111111",
            "target/deploy/ring.so",
        ]);

        assert_eq!(actual, expected);
    }

    /// surfpool keeps its state in memory, so `--ledger` and the ledger-size
    /// cap have nothing to bind to. Dropping them rather than refusing them is
    /// what lets a caller name a ledger for per-clone isolation and still run
    /// on either backend.
    #[test]
    fn builds_surfpool_args_and_drops_the_ledger_flags() {
        let opts = parse_validator(&[
            "--rpc-port",
            "8899",
            "--ledger",
            "target/localnet/ledger",
            "--sbf-program",
            "Pool111111111111111111111111111111111111111",
            "target/deploy/pool.so",
        ]);

        let actual = surfpool_args(&opts).expect("build surfpool args");
        let expected = strings(&[
            "start",
            "--offline",
            "--no-tui",
            "--no-deploy",
            "--no-studio",
            "--port",
            "8899",
            "--host",
            "127.0.0.1",
            "--bpf-program",
            "Pool111111111111111111111111111111111111111",
            "target/deploy/pool.so",
        ]);

        assert_eq!(actual, expected);
    }

    /// The two backends spell the same intent differently: solana's
    /// `--deactivate-feature` never activates the gate, surfpool's
    /// `--disable-feature` clears it from the mainnet baseline. Both leave it
    /// off, so the flag is renamed in passing rather than handled by callers.
    #[test]
    fn translates_deactivate_feature_to_surfpool_spelling() {
        const SBPF_V0_GATE: &str = "B8JJXCy5amZyWG9r7EnUYLwzXSXTxG7GZ1qZ1qggo83g";
        let opts = parse_validator(&[
            "--rpc-port",
            "8899",
            "--sbf-program",
            "Pool111111111111111111111111111111111111111",
            "target/deploy/pool.so",
            "--",
            "--deactivate-feature",
            SBPF_V0_GATE,
        ]);

        let actual = surfpool_args(&opts).expect("build surfpool args");
        assert_eq!(
            actual.iter().rev().take(2).collect::<Vec<_>>(),
            vec![&SBPF_V0_GATE.to_string(), &"--disable-feature".to_string()],
            "the passthrough gate must reach surfpool under its own flag name"
        );
        assert!(
            !actual.iter().any(|arg| arg == "--deactivate-feature"),
            "solana's spelling must not survive the translation: {actual:?}"
        );
    }

    /// A passthrough flag surfpool shares with solana goes through untouched;
    /// only the renamed one is rewritten.
    #[test]
    fn passes_other_validator_args_through_unchanged() {
        let opts = parse_validator(&[
            "--rpc-port",
            "8899",
            "--sbf-program",
            "Pool111111111111111111111111111111111111111",
            "target/deploy/pool.so",
            "--",
            "--some-shared-flag",
            "value",
        ]);

        let actual = surfpool_args(&opts).expect("build surfpool args");
        assert_eq!(
            actual.iter().rev().take(2).collect::<Vec<_>>(),
            vec![&"value".to_string(), &"--some-shared-flag".to_string()]
        );
    }

    #[test]
    fn parses_photon_options() {
        let opts = parse_validator(&["--photon-port", "8785"]);
        assert!(opts.start_indexer());
        assert_eq!(opts.photon_port, 8785);
        assert_eq!(opts.photon_start_slot, "latest");
    }

    #[test]
    fn forwards_explicit_account_dirs() {
        let opts = parse_validator(&[
            "--no-use-surfpool",
            "--account-dir",
            "accounts/a",
            "--account-dir",
            "accounts/b",
        ]);

        let actual = solana_validator_args(&opts).expect("build solana validator args");
        assert!(actual
            .windows(2)
            .any(|args| args == ["--account-dir", "accounts/a"]));
        assert!(actual
            .windows(2)
            .any(|args| args == ["--account-dir", "accounts/b"]));
    }

    /// `--faucet-port` still has no surfpool equivalent, and unlike the ledger
    /// flags a caller asking for one wants a service that will not exist, so it
    /// is refused rather than dropped.
    #[test]
    fn rejects_the_faucet_port_with_surfpool() {
        let opts = parse_validator(&["--faucet-port", "9900"]);
        let error = surfpool_args(&opts).expect_err("surfpool should reject --faucet-port");
        assert!(error.to_string().contains("--faucet-port"));
    }
}
