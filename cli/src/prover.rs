use std::{env, fs, path::Path};

use anyhow::{Context, Result};

use crate::{
    args::StartProverOptions,
    config::{
        DEFAULT_LOG_DIR, DEFAULT_METRICS_PORT, DEFAULT_PROVER_PORT, PROVER_READINESS_STABLE_CHECKS,
        READINESS_TIMEOUT,
    },
    http::wait_for_http_get_with_child,
    process::{find_binary, path_string_with_trailing_separator, spawn_service, stop_port},
};

pub(crate) fn run_start_prover(opts: StartProverOptions) -> Result<()> {
    start_prover_service(
        opts.prover_port,
        opts.redis_url.as_deref(),
        opts.auto_download,
        DEFAULT_LOG_DIR,
    )
}

pub(crate) fn start_prover_service(
    prover_port: u16,
    redis_url: Option<&str>,
    auto_download: bool,
    log_dir: &str,
) -> Result<()> {
    // The prover's Prometheus metrics server defaults to the fixed port 9998, so
    // two clones running prover-backed tests concurrently would collide there and
    // panic even though their `--prover-address` ports are offset apart. Track the
    // prover port's offset so the metrics port moves in lockstep (the canonical
    // 3001 -> 9998 mapping is preserved at offset 0).
    let offset = prover_port.saturating_sub(DEFAULT_PROVER_PORT);
    let metrics_port = DEFAULT_METRICS_PORT.saturating_add(offset);

    stop_port(prover_port);
    stop_port(metrics_port);

    let prover = find_binary(
        &["PROVER_BIN", "ZOLANA_PROVER_BIN"],
        &["target/prover-server"],
        &["prover-server"],
    )?;
    let keys_dir = prover_keys_dir()?;
    fs::create_dir_all(&keys_dir)
        .with_context(|| format!("failed to create prover keys dir {}", keys_dir.display()))?;

    let args = prover_start_args(
        prover_port,
        metrics_port,
        redis_url,
        auto_download,
        &keys_dir,
    )?;
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

fn prover_start_args(
    prover_port: u16,
    metrics_port: u16,
    redis_url: Option<&str>,
    auto_download: bool,
    keys_dir: &Path,
) -> Result<Vec<String>> {
    let mut args = vec![
        "start".into(),
        "--keys-dir".into(),
        path_string_with_trailing_separator(keys_dir)?,
        "--prover-address".into(),
        format!("0.0.0.0:{prover_port}"),
        "--metrics-address".into(),
        format!("0.0.0.0:{metrics_port}"),
        format!("--auto-download={auto_download}"),
    ];

    if let Some(redis_url) = redis_url {
        args.extend(["--redis-url".into(), redis_url.into()]);
    }

    Ok(args)
}

fn prover_keys_dir() -> Result<std::path::PathBuf> {
    if let Ok(path) = env::var("ZOLANA_PROVER_KEYS_DIR") {
        return Ok(path.into());
    }

    let home = env::var("HOME").context("HOME is not set")?;
    Ok(Path::new(&home).join(".config/zolana/proving-keys"))
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::prover_start_args;

    #[test]
    fn prover_args_forward_auto_download_and_metrics_port() {
        let args = prover_start_args(
            3002,
            9999,
            Some("redis://localhost:6379/15"),
            false,
            Path::new("/tmp/zolana-keys"),
        )
        .expect("build prover args");

        assert_eq!(
            args,
            vec![
                "start",
                "--keys-dir",
                "/tmp/zolana-keys/",
                "--prover-address",
                "0.0.0.0:3002",
                "--metrics-address",
                "0.0.0.0:9999",
                "--auto-download=false",
                "--redis-url",
                "redis://localhost:6379/15",
            ]
        );
    }
}
