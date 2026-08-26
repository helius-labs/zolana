//! `pipeline`, every step in order against the active target.

use std::time::Duration;

use solana_signer::Signer;
use thiserror::Error;
use zolana_ring_client::{ReaderKey, ReaderKeyError};

use crate::{
    deploy, error::CliError, init, probe, reader, ring_rpc, transact, Context, DeployArgs,
    InitArgs, ReaderCommand, TransactArgs,
};

const HEALTH_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Debug, Error)]
pub enum PipelineError {
    #[error(transparent)]
    ReaderKey(#[from] ReaderKeyError),
    #[error(
        "no ring rpc answers at {url}, `zolana-ring localnet` starts one serving keys/auditor.key"
    )]
    RingRpcDown {
        url: String,
        #[source]
        source: reqwest::Error,
    },
}

/// Steps already on chain are skipped, a rerun resumes where it stopped.
pub fn run(ctx: &mut Context) -> Result<(), CliError> {
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
    let authority = ctx.config.config_authority()?;
    let reader = ReaderKey::ed25519(authority.pubkey()).map_err(PipelineError::from)?;
    reader::run(ctx, ReaderCommand::Grant { reader })?;
    transact::run(ctx, TransactArgs::default())?;
    Ok(())
}

/// `localnet` starts the ring rpc, `pipeline` only checks it.
fn check_local_ring_rpc(ctx: &Context) -> Result<(), PipelineError> {
    let base = &ctx.config.urls().ring_rpc;
    let http = probe::http(HEALTH_TIMEOUT, HEALTH_TIMEOUT);
    probe::check(&http, &probe::service_url(base, "/health")).map_err(|source| {
        PipelineError::RingRpcDown {
            url: base.clone(),
            source,
        }
    })?;
    crate::line("ring rpc", format_args!("{base} answers"));
    Ok(())
}
