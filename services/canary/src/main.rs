use std::{
    process::ExitCode,
    thread::sleep,
    time::{Instant, SystemTime, UNIX_EPOCH},
};

use spr_canary::{
    canary::{Canary, MIN_PAYER_LAMPORTS},
    config::Config,
    redact::Redactor,
    schedule::next_tick,
};

const USAGE: &str = "usage: spr-canary [--version]
configured by RPC_URL, SPR_API_URL, SPR_API_KEY, SPR_TEE_NETWORK, CANARY_KEYPAIR,
METRICS_NAMESPACE and optionally CANARY_INTERVAL_SECS, CANARY_AMOUNT_LAMPORTS, CANARY_TIMEOUT_SECS";

fn main() -> ExitCode {
    match std::env::args().nth(1).as_deref() {
        None => {}
        Some("--version" | "-V") => {
            println!("spr-canary {}", env!("CARGO_PKG_VERSION"));
            return ExitCode::SUCCESS;
        }
        Some("--help" | "-h") => {
            println!("{USAGE}");
            return ExitCode::SUCCESS;
        }
        Some(_) => {
            eprintln!("{USAGE}");
            return ExitCode::from(2);
        }
    }
    let config = match Config::from_env() {
        Ok(config) => config,
        Err(error) => {
            eprintln!("spr-canary: {error}");
            return ExitCode::from(2);
        }
    };
    let mut canary = match Canary::new(&config) {
        Ok(canary) => canary,
        Err(error) => {
            let redactor = Redactor::new(config.secrets());
            eprintln!(
                "spr-canary: CANARY_KEYPAIR: {}",
                redactor.apply(&error.to_string())
            );
            return ExitCode::from(2);
        }
    };
    eprintln!(
        "spr-canary {} wallet={} interval={}s amount={} timeout={}s namespace={} min_payer_lamports={MIN_PAYER_LAMPORTS}",
        env!("CARGO_PKG_VERSION"),
        canary.wallet(),
        config.interval.as_secs(),
        config.amount,
        config.timeout.as_secs(),
        config.namespace,
    );
    let mut scheduled = Instant::now();
    loop {
        let now = Instant::now();
        if scheduled > now {
            sleep(scheduled - now);
        }
        let outcome = canary.attempt(unix_millis());
        println!("{}", outcome.record.to_emf(&config.namespace));
        eprintln!("{}", outcome.record.summary(&outcome.detail));
        let (next, skipped) = next_tick(scheduled, Instant::now(), config.interval);
        if skipped > 0 {
            eprintln!("canary skipped {skipped} tick(s): the attempt overran the interval");
        }
        scheduled = next;
    }
}

fn unix_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| {
            u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX)
        })
}
