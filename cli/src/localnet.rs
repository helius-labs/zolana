use std::{thread, time::Duration};

use anyhow::{bail, Context, Result};

use crate::{
    args::TestValidatorOptions,
    config::{READINESS_STABLE_CHECKS, READINESS_TIMEOUT},
    http::{wait_for_http_get_with_child, wait_for_rpc_with_child},
    process::{find_binary, remove_launchd_validators, spawn_service, stop_name, stop_port},
    prover::start_prover_service,
};

pub(crate) fn run_test_validator(opts: TestValidatorOptions) -> Result<()> {
    if opts.stop {
        println!("Stopping local validator environment");
        stop_test_env(&opts);
        println!("Local validator environment stopped");
        return Ok(());
    }

    println!("Starting local validator");
    stop_test_validator(opts.rpc_port);
    thread::sleep(Duration::from_secs(1));

    let mut validator = if opts.use_surfpool_backend() {
        let surfpool = find_binary(&["SURFPOOL_BIN"], &["target/tools/surfpool"], &["surfpool"])?;
        let args = surfpool_args(&opts)?;
        println!(
            "Starting surfpool: {} {}",
            surfpool.display(),
            args.join(" ")
        );
        spawn_service(&surfpool, &args, "surfpool", &opts.log_dir)?
    } else {
        let validator = find_binary(&[], &[], &["solana-test-validator"])?;
        let args = solana_validator_args(&opts)?;
        println!(
            "Starting solana-test-validator: {} {}",
            validator.display(),
            args.join(" ")
        );
        spawn_service(&validator, &args, "solana-test-validator", &opts.log_dir)?
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
        start_prover_service(
            opts.prover_port,
            None,
            opts.prover_auto_download,
            &opts.log_dir,
        )?;
    }

    if opts.with_photon {
        start_photon_service(&opts)?;
    }

    println!("Local validator environment is ready");
    std::mem::forget(validator);
    Ok(())
}

pub(crate) fn surfpool_args(opts: &TestValidatorOptions) -> Result<Vec<String>> {
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

    add_additional_program_args(&mut args, opts);
    add_account_dir_args(&mut args, opts);
    Ok(args)
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
    if opts.with_photon {
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

fn start_photon_service(opts: &TestValidatorOptions) -> Result<()> {
    stop_name("photon");
    stop_port(opts.photon_port);

    let photon = find_binary(
        &["ZOLANA_PHOTON_BIN"],
        &["target/release/photon", "target/debug/photon"],
        &["photon"],
    )?;
    let rpc_url = format!("http://127.0.0.1:{}", opts.rpc_port);
    let mut args = vec![
        "--rpc-url".to_string(),
        rpc_url,
        "--port".to_string(),
        opts.photon_port.to_string(),
        "--start-slot".to_string(),
        opts.photon_start_slot.clone(),
    ];
    if let Some(db_url) = &opts.photon_db_url {
        args.push("--db-url".to_string());
        args.push(db_url.clone());
    }

    println!("Starting Photon: {} {}", photon.display(), args.join(" "));
    let mut child = spawn_service(&photon, &args, "photon", &opts.log_dir)?;
    wait_for_http_get_with_child(
        opts.photon_port,
        "/readiness",
        READINESS_TIMEOUT,
        READINESS_STABLE_CHECKS,
        &mut child,
        "photon",
    )
    .with_context(|| format!("Photon on port {} did not become ready", opts.photon_port))?;
    println!(
        "Photon indexer is ready at http://127.0.0.1:{}",
        opts.photon_port
    );
    std::mem::forget(child);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::args::parse_validator;

    fn strings(values: &[&str]) -> Vec<String> {
        values.iter().map(|value| (*value).to_string()).collect()
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
    fn parses_photon_options() {
        let opts = parse_validator(&["--with-photon", "--photon-port", "8785"]);
        assert!(opts.with_photon);
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

    #[test]
    fn rejects_solana_validator_only_flags_with_surfpool() {
        let opts = parse_validator(&["--ledger", "target/localnet/ledger"]);
        let error = surfpool_args(&opts).expect_err("surfpool should reject --ledger");
        assert!(error.to_string().contains("--ledger"));

        let opts = parse_validator(&["--faucet-port", "9900"]);
        let error = surfpool_args(&opts).expect_err("surfpool should reject --faucet-port");
        assert!(error.to_string().contains("--faucet-port"));
    }
}
