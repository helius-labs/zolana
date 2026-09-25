use std::{env, ffi::OsStr, fs, path::Path};

use anyhow::{Context, Result};
use zolana_client::{
    prover::{redact_api_key, PROVER_INDEXER_URL_ENV},
    ProverClient,
};

use crate::{
    args::StartProverOptions,
    config::{DEFAULT_LOG_DIR, DEFAULT_METRICS_PORT, DEFAULT_PROVER_PORT, READINESS_TIMEOUT},
    http::{http_get_ok, wait_for_http_get_with_child},
    process::{
        find_binary, path_string_with_trailing_separator, require_scoped_port_available,
        spawn_service, stop_port, Service,
    },
};

pub(crate) fn run_start_prover(opts: StartProverOptions) -> Result<()> {
    ProverService {
        port: opts.prover_port,
        redis_url: opts.redis_url.as_deref(),
        auto_download: opts.auto_download,
        log_dir: DEFAULT_LOG_DIR,
        binary: None,
        indexer_url: opts.indexer_url.as_deref(),
    }
    .start()
}

pub(crate) struct ProverService<'a> {
    pub(crate) port: u16,
    pub(crate) redis_url: Option<&'a str>,
    pub(crate) auto_download: bool,
    pub(crate) log_dir: &'a str,
    pub(crate) binary: Option<&'a Path>,
    pub(crate) indexer_url: Option<&'a str>,
}

impl ProverService<'_> {
    pub(crate) fn start(self) -> Result<()> {
        let prover_port = self.port;
        let metrics_port = self.metrics_port();

        // Environments started in parallel share one prover. When another start won
        // the race, reuse its prover rather than stopping it.
        if http_get_ok(prover_port, "/health") {
            println!("Prover already running on port {prover_port}");
            return self.check();
        }
        stop_port(prover_port);
        stop_port(metrics_port);
        require_scoped_port_available(prover_port)?;
        require_scoped_port_available(metrics_port)?;

        let prover = match self.binary {
            Some(path) => path.to_path_buf(),
            None => find_binary(
                &["PROVER_BIN", "ZOLANA_PROVER_BIN"],
                &["target/prover-server"],
                &["prover-server"],
            )?,
        };
        let keys_dir = prover_keys_dir()?;
        fs::create_dir_all(&keys_dir)
            .with_context(|| format!("failed to create prover keys dir {}", keys_dir.display()))?;

        let args = self.args(&keys_dir)?;
        println!("Starting prover: {} {}", prover.display(), args.join(" "));
        let envs = match self.indexer_url {
            Some(url) => {
                println!("Prover indexer: {}", redact_api_key(url));
                vec![(PROVER_INDEXER_URL_ENV, OsStr::new(url))]
            }
            None => Vec::new(),
        };
        let mut child = spawn_service(&prover, &args, &envs, Service::Prover, self.log_dir)?;
        let ready = wait_for_http_get_with_child(
            prover_port,
            "/health",
            READINESS_TIMEOUT,
            &mut child,
            "prover",
        );
        // A parallel start can bind the port between the check above and this
        // spawn, so ours exits; its prover serves both environments.
        if ready.is_err() && http_get_ok(prover_port, "/health") {
            println!("Prover already running on port {prover_port}");
            return self.check();
        }
        ready.with_context(|| format!("prover on port {prover_port} did not become ready"))?;
        // Stop a prover that fails the check rather than leave it on the port for
        // the next caller to reuse.
        if let Err(error) = self.check() {
            let _ = child.kill();
            let _ = child.wait();
            return Err(error);
        }
        println!("Prover started successfully");
        std::mem::forget(child);
        Ok(())
    }

    /// The prover's Prometheus metrics server defaults to the fixed port 9998, so
    /// two clones running prover-backed tests concurrently would collide there and
    /// panic even though their `--prover-address` ports are offset apart. Track the
    /// prover port's offset so the metrics port moves in lockstep (the canonical
    /// 3001 -> 9998 mapping is preserved at offset 0).
    fn metrics_port(&self) -> u16 {
        let offset = self.port.saturating_sub(DEFAULT_PROVER_PORT);
        DEFAULT_METRICS_PORT.saturating_add(offset)
    }

    fn args(&self, keys_dir: &Path) -> Result<Vec<String>> {
        let mut args = vec![
            "start".into(),
            "--keys-dir".into(),
            path_string_with_trailing_separator(keys_dir)?,
            "--prover-address".into(),
            format!("0.0.0.0:{}", self.port),
            "--metrics-address".into(),
            format!("0.0.0.0:{}", self.metrics_port()),
            format!("--auto-download={}", self.auto_download),
        ];

        if let Some(redis_url) = self.redis_url {
            args.extend(["--redis-url".into(), redis_url.into()]);
        }

        Ok(args)
    }

    /// A stale prebuilt prover binary, or a running prover from another build,
    /// pins a different proving-key set than this build's verifying keys; its
    /// proofs would fail on-chain.
    fn check(&self) -> Result<()> {
        let prover_port = self.port;
        let keys = ProverClient::new(format!("http://127.0.0.1:{prover_port}"))
            .check_proving_keys()
            .with_context(|| {
                format!("prover on port {prover_port} failed the proving key check")
            })?;
        println!("Prover proving keys match ({})", keys.prefix);
        Ok(())
    }
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

    use super::ProverService;

    #[test]
    fn prover_args_forward_auto_download_and_metrics_port() {
        let args = ProverService {
            port: 3002,
            redis_url: Some("redis://localhost:6379/15"),
            auto_download: false,
            log_dir: "unused",
            binary: None,
            indexer_url: Some("http://127.0.0.1:8784/?api-key=secret"),
        }
        .args(Path::new("/tmp/zolana-keys"))
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
