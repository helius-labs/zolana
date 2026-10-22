//! `pipeline`, every step in order against the active target.

use std::time::Duration;

use anyhow::{Context as _, Result};
use solana_signer::Signer;
use zolana_ring_client::ReaderKey;

use crate::{
    controls, defaults, deploy, init, line, localnet, probe, ring_rpc, transact, Context,
    DeployArgs, InitArgs, ReaderCommand,
};

const HEALTH_TIMEOUT: Duration = Duration::from_secs(5);

/// Steps already on chain are skipped, a rerun resumes where it stopped.
pub fn run(ctx: &mut Context, args: DeployArgs) -> Result<()> {
    localnet::ensure(ctx)?;
    deploy::run(ctx, args)?;
    let hosted = !ctx.config.urls().ring_rpc_is_local();
    if hosted {
        // A hosted service that cannot serve the ring must fail before `init` pins the auditor for good.
        ring_rpc::run_check(ctx)?;
    }
    init::run(ctx, defaults::<InitArgs>())?;
    if !hosted {
        // Started before `deploy`, it may have died since.
        let base = &ctx.config.urls().ring_rpc;
        let http = probe::http(HEALTH_TIMEOUT, HEALTH_TIMEOUT);
        probe::check(&http, &probe::service_url(base, "/health")).with_context(|| {
            format!("no ring rpc answers at {base}, `zolana-ring localnet` starts one serving keys/auditor.key")
        })?;
        line("ring rpc", format_args!("{base} answers"));
    }
    let reader = ReaderKey::ed25519(ctx.authority()?.pubkey())?;
    controls::reader(ctx, ReaderCommand::Grant { reader })?;
    transact::run(ctx, defaults())
}
