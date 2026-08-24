//! `pipeline`, every step in order against the active target.

use std::time::Duration;

use solana_signer::Signer;
use thiserror::Error;
use zolana_ring_client::{ReaderKey, ReaderKeyError};

use crate::{
    build_program, deploy, error::CliError, init, probe::service_url, reader, ring_rpc, transact,
    BuildArgs, Context, DeployArgs, InitArgs, ReaderCommand, TransactArgs,
};

const HEALTH_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Debug, Error)]
pub enum PipelineError {
    #[error(transparent)]
    ReaderKey(#[from] ReaderKeyError),
    #[error("cannot build the health probe client")]
    Client(#[source] reqwest::Error),
    #[error("no ring rpc answers at {url}, create its key with `zolana-ring auditor-key --create` and run the ring rpc from a zolana checkout serving keys/auditor.key")]
    RingRpcDown {
        url: String,
        #[source]
        source: reqwest::Error,
    },
}

/// Steps already on chain are skipped, a rerun resumes where it stopped.
pub fn run(ctx: &mut Context, build: BuildArgs) -> Result<(), CliError> {
    build_program::run(&ctx.config, build)?;
    deploy::run(ctx, DeployArgs::default())?;
    let hosted = !ctx.config.urls().ring_rpc_is_local();
    if hosted {
        // A hosted service that cannot serve the ring must fail before `init`
        // pins the auditor for good.
        ring_rpc::run_check(ctx)?;
    }
    init::run(ctx, InitArgs::default())?;
    if !hosted {
        check_local_ring_rpc(ctx)?;
    }
    let authority = ctx.config.authority()?;
    let reader = ReaderKey::ed25519(authority.pubkey()).map_err(PipelineError::from)?;
    reader::run(ctx, ReaderCommand::Grant { reader })?;
    transact::run(ctx, TransactArgs::default())?;
    Ok(())
}

/// The binary starts no services, a missing local ring rpc is the operator's step.
fn check_local_ring_rpc(ctx: &Context) -> Result<(), PipelineError> {
    let base = &ctx.config.urls().ring_rpc;
    let url = service_url(base, "/health");
    let http = reqwest::blocking::Client::builder()
        .connect_timeout(HEALTH_TIMEOUT)
        .timeout(HEALTH_TIMEOUT)
        .build()
        .map_err(PipelineError::Client)?;
    http.get(&url)
        .send()
        .and_then(|response| response.error_for_status())
        .map_err(|source| PipelineError::RingRpcDown {
            url: base.clone(),
            source,
        })?;
    println!("ring rpc    {base} answers");
    Ok(())
}
