use std::{fs, path::Path};

use anyhow::{Context, Result};

use crate::{
    args::StartProverOptions,
    config::{DEFAULT_LOG_DIR, PROVER_READINESS_STABLE_CHECKS, READINESS_TIMEOUT},
    http::wait_for_http_get_with_child,
    process::{find_binary, path_string_with_trailing_separator, spawn_service, stop_port},
};

pub(crate) fn run_start_prover(opts: StartProverOptions) -> Result<()> {
    start_prover_service(opts.prover_port, opts.redis_url.as_deref(), DEFAULT_LOG_DIR)
}

pub(crate) fn start_prover_service(
    prover_port: u16,
    redis_url: Option<&str>,
    log_dir: &str,
) -> Result<()> {
    stop_port(prover_port);

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
    let mut child = spawn_service(&prover, &args, "prover-server", log_dir)?;
    wait_for_http_get_with_child(
        prover_port,
        "/health",
        READINESS_TIMEOUT,
        PROVER_READINESS_STABLE_CHECKS,
        &mut child,
        "prover",
    )
    .with_context(|| format!("prover on port {prover_port} did not become ready"))?;
    println!("Prover started successfully");
    std::mem::forget(child);
    Ok(())
}

fn prover_keys_dir() -> Result<std::path::PathBuf> {
    if let Ok(path) = std::env::var("ZOLANA_PROVER_KEYS_DIR") {
        return Ok(path.into());
    }

    let home = std::env::var("HOME").context("HOME is not set")?;
    Ok(Path::new(&home).join(".config/zolana/proving-keys"))
}
