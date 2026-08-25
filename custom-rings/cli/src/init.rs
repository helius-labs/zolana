use std::path::{Path, PathBuf};

use custom_ring_program::CustomRingError;
use custom_ring_sdk::{
    AccountReadError, CreateConfig, CreateConfigError, CustomRing, CustomRingConfig,
    InitSppRingConfig, CREATE_CONFIG_COMPUTE_UNIT_LIMIT, INIT_SPP_RING_CONFIG_COMPUTE_UNIT_LIMIT,
};
use solana_address::Address;
use solana_signer::Signer;
use thiserror::Error;
use zolana_client::SolanaRpc;
use zolana_interface::error::ShieldedPoolError;
use zolana_keypair::P256Pubkey;
use zolana_ring_rpc::{read_auditor_pubkey, write_auditor_pubkey, KeyFileError};

use crate::{
    line,
    ring_rpc::{AuditorKeyRelease, RingRpcClient, RingRpcClientError, Trust},
    step::{IdempotentStep, Observed, StepError, StepOutcome},
    Context, ContextError, InitArgs,
};

pub enum AuditorKeySource<'a> {
    File(&'a Path),
    /// The config already pins the key.
    Chain(P256Pubkey),
    RingRpc {
        client: &'a RingRpcClient,
        release: AuditorKeyRelease<'a>,
        trust: Trust,
        write_to: &'a Path,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[must_use]
pub struct KeySelection {
    pub file_present: bool,
    pub hosted_rpc: bool,
    pub local_auditor: bool,
    pub configured: Option<P256Pubkey>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[must_use]
pub enum KeyChoice {
    File,
    Chain(P256Pubkey),
    RingRpc,
}

/// A file the service did not write must not be pinned against a hosted rpc.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[error("a local auditor key file against a hosted ring rpc")]
pub struct StrayLocalKey;

pub struct Init<'a> {
    pub ring: CustomRing,
    pub authority: &'a dyn Signer,
    pub auditor_pk: P256Pubkey,
    pub existing: Option<CustomRingConfig>,
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
    #[error("{path} holds an auditor key, but the ring rpc at {url} is not on this machine and holds its own. Pinning this key means only a ring rpc serving it can ever open the ring. Delete the file to take the service's key, or pass --local-auditor to keep it")]
    LocalAuditorAgainstRemoteRpc { path: PathBuf, url: String },
}

pub fn run(ctx: &mut Context, args: InitArgs) -> Result<(), InitError> {
    let auditor_pubkey_file = ctx.project_path(&args.auditor_pubkey_file);
    let authority = ctx.funded_authority()?;
    let ring_rpc = ctx.ring_rpc();
    let unpinned = if args.trust_ring_rpc {
        Trust::Unpinned
    } else {
        Trust::Refuse
    };
    let existing = ctx.ring.read_config(&ctx.rpc)?;
    let choice = KeySelection {
        file_present: auditor_pubkey_file.exists(),
        hosted_rpc: !ctx.config.urls().ring_rpc_is_local(),
        local_auditor: args.local_auditor,
        configured: existing.as_ref().map(|config| config.auditor_pubkey),
    }
    .decide()
    .map_err(|StrayLocalKey| InitError::LocalAuditorAgainstRemoteRpc {
        path: auditor_pubkey_file.clone(),
        url: ctx.config.urls().ring_rpc.clone(),
    })?;
    let upgrade_authority;
    let source = match choice {
        KeyChoice::File => AuditorKeySource::File(&auditor_pubkey_file),
        KeyChoice::Chain(auditor_pk) => AuditorKeySource::Chain(auditor_pk),
        KeyChoice::RingRpc => {
            upgrade_authority = ctx.config.upgrade_authority().map_err(ContextError::from)?;
            AuditorKeySource::RingRpc {
                client: &ring_rpc,
                release: AuditorKeyRelease {
                    ring: ctx.ring.program_id(),
                    genesis_hash: ctx.genesis_hash()?,
                    authority: &upgrade_authority,
                },
                trust: ctx.trust(unpinned).map_err(ContextError::from)?,
                write_to: &auditor_pubkey_file,
            }
        }
    };
    let auditor_pk = source.resolve()?;
    if let AuditorKeySource::RingRpc { write_to, .. } = &source {
        line(
            "auditor pk",
            format_args!(
                "{} (from {}, written to {})",
                hex::encode(auditor_pk.as_bytes()),
                ctx.config.urls().ring_rpc,
                write_to.display()
            ),
        );
    }
    let outcome = Init {
        ring: ctx.ring,
        authority: &authority,
        auditor_pk,
        existing,
    }
    .run(&ctx.rpc)?;
    line("config", outcome.config.label());
    line(
        "spp ring",
        match outcome.ring {
            StepOutcome::Created => "registered",
            other => other.label(),
        },
    );
    if matches!(outcome.ring, StepOutcome::Created | StepOutcome::Present) {
        crate::status::announce(&ctx.config);
    }
    Ok(())
}

impl KeySelection {
    /// A config wins, its key is fixed and a rerun must not touch the service.
    pub fn decide(self) -> Result<KeyChoice, StrayLocalKey> {
        if let Some(auditor_pk) = self.configured {
            return Ok(KeyChoice::Chain(auditor_pk));
        }
        if !self.file_present {
            return Ok(KeyChoice::RingRpc);
        }
        if self.hosted_rpc && !self.local_auditor {
            return Err(StrayLocalKey);
        }
        Ok(KeyChoice::File)
    }
}

impl AuditorKeySource<'_> {
    pub fn resolve(&self) -> Result<P256Pubkey, InitError> {
        match self {
            Self::File(path) => Ok(read_auditor_pubkey(path)?),
            Self::Chain(auditor_pk) => Ok(*auditor_pk),
            Self::RingRpc {
                client,
                release,
                trust,
                write_to,
            } => {
                let auditor_pk = client.release_auditor_key(release)?.require(*trust)?;
                write_auditor_pubkey(write_to, &auditor_pk)?;
                Ok(auditor_pk)
            }
        }
    }
}

impl Init<'_> {
    pub fn run(self, rpc: &SolanaRpc) -> Result<InitOutcome, InitError> {
        let payer = self.authority.pubkey();
        if let Some(config) = &self.existing {
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
            Observed::of(&self.existing),
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

#[cfg(test)]
mod tests {
    use zolana_keypair::ViewingKey;

    use super::*;

    fn select(file_present: bool, hosted_rpc: bool, local_auditor: bool) -> KeySelection {
        KeySelection {
            file_present,
            hosted_rpc,
            local_auditor,
            configured: None,
        }
    }

    #[test]
    fn a_config_wins_over_the_file_and_the_service() {
        let pinned = ViewingKey::new().pubkey();
        for (file_present, hosted_rpc) in [(true, true), (true, false), (false, true)] {
            let selection = KeySelection {
                configured: Some(pinned),
                ..select(file_present, hosted_rpc, false)
            };
            assert_eq!(selection.decide(), Ok(KeyChoice::Chain(pinned)));
        }
    }

    #[test]
    fn without_a_config_the_file_is_taken_only_where_the_service_wrote_it() {
        assert_eq!(select(false, true, false).decide(), Ok(KeyChoice::RingRpc));
        assert_eq!(select(false, false, false).decide(), Ok(KeyChoice::RingRpc));
        assert_eq!(select(true, false, false).decide(), Ok(KeyChoice::File));
        assert_eq!(select(true, true, true).decide(), Ok(KeyChoice::File));
        assert_eq!(select(true, true, false).decide(), Err(StrayLocalKey));
    }
}
