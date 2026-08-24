use std::path::{Path, PathBuf};

use custom_ring_program::CustomRingError;
use custom_ring_sdk::{
    AccountReadError, CreateConfig, CreateConfigError, CustomRing, InitSppRingConfig,
    CREATE_CONFIG_COMPUTE_UNIT_LIMIT, INIT_SPP_RING_CONFIG_COMPUTE_UNIT_LIMIT,
};
use solana_address::Address;
use solana_signer::Signer;
use thiserror::Error;
use zolana_client::SolanaRpc;
use zolana_interface::error::ShieldedPoolError;
use zolana_keypair::P256Pubkey;
use zolana_ring_rpc::{read_auditor_pubkey, write_auditor_pubkey, KeyFileError};

use crate::{
    ring_rpc::{RingRpcClient, RingRpcClientError, Trust},
    step::{IdempotentStep, Observed, StepError, StepOutcome},
    Context, ContextError, InitArgs,
};

pub enum AuditorKeySource<'a> {
    File(&'a Path),
    RingRpc {
        client: &'a RingRpcClient,
        trust: Trust,
        write_to: &'a Path,
    },
}

pub struct Init<'a> {
    pub ring: CustomRing,
    pub authority: &'a dyn Signer,
    pub auditor_pk: P256Pubkey,
}

pub struct InitOutcome {
    pub config: StepOutcome,
    pub ring: StepOutcome,
}

#[derive(Debug, Error)]
pub enum InitError {
    #[error(transparent)]
    Context(#[from] ContextError),
    #[error(transparent)]
    KeyFile(#[from] KeyFileError),
    #[error(transparent)]
    RingRpc(#[from] RingRpcClientError),
    #[error(transparent)]
    AccountRead(#[from] AccountReadError),
    #[error(transparent)]
    Build(#[from] CreateConfigError),
    #[error(transparent)]
    Step(#[from] StepError),
    #[error("ring config exists under authority {authority} with auditor {auditor}, ring.toml names another operator")]
    ConfigMismatch { authority: Address, auditor: String },
    #[error("ring config not created, run `init` first")]
    NotInitialized,
    #[error("{path} holds an auditor key, but the ring rpc at {url} is not on this machine and holds its own. Pinning this key means only a ring rpc serving it can ever open the ring: delete the file to take the service's key, or pass --local-auditor to keep it")]
    LocalAuditorAgainstRemoteRpc { path: PathBuf, url: String },
}

pub fn run(ctx: &mut Context, args: InitArgs) -> Result<(), InitError> {
    let authority = ctx.funded_authority()?;
    let ring_rpc = ctx.ring_rpc();
    let unpinned = if args.trust_ring_rpc {
        Trust::Unpinned
    } else {
        Trust::Refuse
    };
    // The config fixes the auditor for good, so a local key must not be pinned
    // by accident against a service that holds its own.
    if args.auditor_pubkey_file.exists()
        && !ctx.config.urls().ring_rpc_is_local()
        && !args.local_auditor
    {
        return Err(InitError::LocalAuditorAgainstRemoteRpc {
            path: args.auditor_pubkey_file.clone(),
            url: ctx.config.urls().ring_rpc.clone(),
        });
    }
    let source = if args.auditor_pubkey_file.exists() {
        AuditorKeySource::File(&args.auditor_pubkey_file)
    } else {
        AuditorKeySource::RingRpc {
            client: &ring_rpc,
            trust: ctx.trust(unpinned).map_err(ContextError::from)?,
            write_to: &args.auditor_pubkey_file,
        }
    };
    let auditor_pk = source.resolve(ctx.ring.program_id())?;
    if let AuditorKeySource::RingRpc { write_to, .. } = source {
        println!(
            "auditor pk  {} (from {}, written to {})",
            hex::encode(auditor_pk.as_bytes()),
            ctx.config.urls().ring_rpc,
            write_to.display()
        );
    }
    let outcome = Init {
        ring: ctx.ring,
        authority: &authority,
        auditor_pk,
    }
    .run(&ctx.rpc)?;
    println!("config      {}", outcome.config.label());
    println!(
        "spp ring    {}",
        match outcome.ring {
            StepOutcome::Created => "registered",
            other => other.label(),
        }
    );
    if matches!(outcome.ring, StepOutcome::Created | StepOutcome::Present) {
        crate::status::announce(&ctx.config);
    }
    Ok(())
}

impl AuditorKeySource<'_> {
    pub fn resolve(&self, ring: Address) -> Result<P256Pubkey, InitError> {
        match *self {
            Self::File(path) => Ok(read_auditor_pubkey(path)?),
            Self::RingRpc {
                client,
                trust,
                write_to,
            } => {
                let auditor_pk = client.auditor_pubkey(ring)?.require(trust)?;
                write_auditor_pubkey(write_to, &auditor_pk)?;
                Ok(auditor_pk)
            }
        }
    }
}

impl Init<'_> {
    /// A rerun after a partial failure finishes the job.
    pub fn run(self, rpc: &SolanaRpc) -> Result<InitOutcome, InitError> {
        let payer = self.authority.pubkey();
        let existing = self.ring.read_config(rpc)?;
        if let Some(config) = &existing {
            if config.auditor_pubkey != self.auditor_pk || config.authority != payer {
                return Err(InitError::ConfigMismatch {
                    authority: config.authority,
                    auditor: hex::encode(config.auditor_pubkey.as_bytes()),
                });
            }
        }
        let config = IdempotentStep {
            rpc,
            authority: self.authority,
            name: "create_config",
            compute_unit_limit: CREATE_CONFIG_COMPUTE_UNIT_LIMIT,
            hint,
        }
        .ensure_present(
            Observed::of(&existing),
            CreateConfig {
                ring: self.ring,
                payer,
                authority: payer,
                auditor_pubkey: self.auditor_pk,
            }
            .instruction()?,
        )?;
        let ring = IdempotentStep {
            rpc,
            authority: self.authority,
            name: "init_spp_ring_config",
            compute_unit_limit: INIT_SPP_RING_CONFIG_COMPUTE_UNIT_LIMIT,
            hint,
        }
        .ensure_present(
            Observed::of(&self.ring.read_spp_ring_config(rpc)?),
            InitSppRingConfig {
                ring: self.ring,
                payer,
                authority: payer,
            }
            .instruction(),
        )?;
        Ok(InitOutcome { config, ring })
    }
}

pub fn configured_auditor_pk(rpc: &SolanaRpc, ring: CustomRing) -> Result<P256Pubkey, InitError> {
    Ok(ring
        .read_config(rpc)?
        .ok_or(InitError::NotInitialized)?
        .auditor_pubkey)
}

fn hint(code: u32) -> Option<&'static str> {
    if code == CustomRingError::UnauthorizedInitializer as u32 {
        Some("the program was deployed with an upgrade authority and only that key may create the config")
    } else if code == ShieldedPoolError::UnauthorizedCaller as u32 {
        Some("ring creation on this cluster is gated by the SPP ring creation authority")
    } else {
        None
    }
}
