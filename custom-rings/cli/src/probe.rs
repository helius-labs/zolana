//! `devnet` and `localnet`, the target switch with service probes.

use std::{
    io::{self, Write},
    time::Duration,
};

use thiserror::Error;

use crate::config::RingConfig;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const TOTAL_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Debug, Error)]
pub enum ProbeError {
    #[error("cannot build the probe client")]
    Client(#[source] reqwest::Error),
    #[error("devnet {service} at {url} is not ready")]
    NotReady {
        service: &'static str,
        url: String,
        #[source]
        source: reqwest::Error,
    },
}

/// Every service is already deployed, the probes only confirm them.
pub fn run_devnet(config: &RingConfig) -> Result<(), ProbeError> {
    print_urls(config);
    println!();
    let http = probe_client()?;
    let urls = config.urls();
    for (service, base, path) in [
        ("indexer", &urls.indexer, "/readiness"),
        ("prover", &urls.prover, "/health"),
    ] {
        let url = service_url(base, path);
        print!("probing {service:<8} {url} ... ");
        let _ = io::stdout().flush();
        match http.get(&url).send().and_then(|r| r.error_for_status()) {
            Ok(_) => println!("ready"),
            Err(source) => {
                println!("not ready");
                return Err(ProbeError::NotReady {
                    service,
                    url,
                    source,
                });
            }
        }
    }
    println!("devnet services ready");
    println!();
    next_steps(config);
    Ok(())
}

pub fn run_localnet(config: &RingConfig) {
    print_urls(config);
    println!();
    println!("the localnet services come from a zolana checkout, run `just ring-localnet` there");
}

pub fn print_urls(config: &RingConfig) {
    let urls = config.urls();
    let served = if urls.ring_rpc_is_local() {
        "(local, run it on this machine)"
    } else {
        "(hosted, it serves this ring)"
    };
    println!("{} points at {}", config.name, config.target.as_str());
    println!("  rpc       {}", urls.rpc);
    println!("  indexer   {}", urls.indexer);
    println!("  prover    {}", urls.prover);
    println!("  ring rpc  {}  {served}", urls.ring_rpc);
}

pub fn probe_client() -> Result<reqwest::blocking::Client, ProbeError> {
    reqwest::blocking::Client::builder()
        .connect_timeout(CONNECT_TIMEOUT)
        .timeout(TOTAL_TIMEOUT)
        .build()
        .map_err(ProbeError::Client)
}

pub fn service_url(base: &str, path: &str) -> String {
    format!("{}{path}", base.trim_end_matches('/'))
}

fn next_steps(config: &RingConfig) {
    let rpc_step = if config.urls().ring_rpc_is_local() {
        "start the ring rpc here, serving keys/auditor.key"
    } else {
        "check that the hosted ring rpc holds this ring's auditor key"
    };
    println!("next: zolana-ring pipeline");
    println!("  1 build     the ring program");
    println!("  2 deploy    it under the authority, pausing for a faucet airdrop when its devnet SOL runs short");
    println!("  3 init      create the config with the auditor key and register the ring with SPP");
    println!("  4 ring rpc  {rpc_step}");
    println!(
        "  5 transact  grant the authority a reader, deposit twice, transfer once, read it back"
    );
    println!();
    println!("  each step is its own command, `zolana-ring status` shows how far a run got");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn service_urls_join_without_double_slashes() {
        assert_eq!(
            service_url("http://127.0.0.1:8784", "/readiness"),
            "http://127.0.0.1:8784/readiness"
        );
        assert_eq!(
            service_url("https://prover.example.com/", "/health"),
            "https://prover.example.com/health"
        );
    }
}
