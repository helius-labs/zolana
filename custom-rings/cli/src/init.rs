use std::path::{Path, PathBuf};

use custom_ring_program::CustomRingError;
use custom_ring_sdk::{
    AccountReadError, CreateConfig, CreateConfigError, CreatePolicy, CustomRing, CustomRingConfig,
    InitSppRingConfig, SetAuthority, CREATE_CONFIG_COMPUTE_UNIT_LIMIT,
    CREATE_POLICY_COMPUTE_UNIT_LIMIT, INIT_SPP_RING_CONFIG_COMPUTE_UNIT_LIMIT,
    SET_AUTHORITY_COMPUTE_UNIT_LIMIT,
};
use solana_address::Address;
use solana_instruction::Instruction;
use solana_signer::Signer;
use thiserror::Error;
use zolana_client::SolanaRpc;
use zolana_interface::error::ShieldedPoolError;
use zolana_keypair::P256Pubkey;
use zolana_ring_rpc::{read_auditor_pubkey, write_auditor_pubkey, KeyFileError};

use crate::{
    config::expand_tilde,
    deploy::{read_program_data, DeployError},
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

/// `create_config` accepts only the upgrade authority, so a distinct config
/// authority takes the config over in the same transaction.
pub struct Init<'a> {
    pub ring: CustomRing,
    /// Needed until the config authority holds the config.
    pub upgrade_authority: Option<&'a dyn Signer>,
    pub config_authority: &'a dyn Signer,
    pub auditor_pk: P256Pubkey,
    pub records_tree: Address,
    pub shared_sources: Vec<(zolana_ring_policy::RecordKind, CustomRing)>,
    pub existing: Option<CustomRingConfig>,
}

pub struct InitOutcome {
    pub config: StepOutcome,
    pub authority: StepOutcome,
    pub ring: StepOutcome,
    pub policy: StepOutcome,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[must_use]
pub struct ConfigOwnership {
    pub existing: Option<Address>,
    pub upgrade_authority: Option<Address>,
    pub config_authority: Address,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[must_use]
pub enum ConfigState {
    Missing,
    HeldByUpgradeAuthority,
    HeldByConfigAuthority,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[error("the config on chain is held by {0}, neither the upgrade authority nor config_authority_keypair")]
pub struct ForeignConfigAuthority(pub Address);

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
    Program(Box<DeployError>),
    #[error(transparent)]
    Build(#[from] CreateConfigError),
    #[error(transparent)]
    Policy(#[from] custom_ring_sdk::RecordError),
    #[error(transparent)]
    PolicySources(Box<crate::record::RecordError>),
    #[error(transparent)]
    Step(#[from] StepError),
    #[error("ring config exists under authority {authority} with auditor {auditor}, ring.toml names another operator")]
    ConfigMismatch { authority: Address, auditor: String },
    #[error("{path} holds auditor {file}, the ring config pins {chain}. Delete the stale file")]
    StaleAuditorFile {
        path: PathBuf,
        file: String,
        chain: String,
    },
    #[error("program {program} is not deployed, run `deploy` first")]
    NotDeployed { program: Address },
    #[error("program {program} is immutable and has no config, nothing can create one")]
    Immutable { program: Address },
    #[error("program {program} is upgradeable by {authority}, ring.toml names {expected}")]
    ForeignUpgradeAuthority {
        program: Address,
        authority: Address,
        expected: Address,
    },
    #[error("the upgrade authority keypair is needed until the config authority holds the config")]
    UpgradeAuthorityNeeded,
    #[error("{path} holds an auditor key, but the ring rpc at {url} is not on this machine and holds its own. Pinning this key means only a ring rpc serving it can ever open the ring. Delete the file to take the service's key, or pass --local-auditor to keep it")]
    LocalAuditorAgainstRemoteRpc { path: PathBuf, url: String },
}

pub fn run(ctx: &mut Context, args: InitArgs) -> Result<(), InitError> {
    let auditor_pubkey_file = ctx.project_path(
        &expand_tilde(args.auditor_pubkey_file.as_path()).map_err(ContextError::from)?,
    );
    let config_authority = ctx.funded_authority()?;
    let existing = ctx.ring.read_config(&ctx.rpc)?;
    let held_by_config_authority = existing
        .as_ref()
        .is_some_and(|config| config.authority == config_authority.pubkey());
    let upgrade_authority = if held_by_config_authority {
        None
    } else {
        Some(ctx.config.upgrade_authority().map_err(ContextError::from)?)
    };
    if let Some(deployer) = upgrade_authority.as_ref().filter(|_| existing.is_none()) {
        let program = ctx.ring.program_id();
        match read_program_data(&ctx.rpc, ctx.ring)
            .map_err(|error| InitError::Program(Box::new(error)))?
            .ok_or(InitError::NotDeployed { program })?
            .upgrade_authority
        {
            None => return Err(InitError::Immutable { program }),
            Some(authority) if authority != deployer.pubkey() => {
                return Err(InitError::ForeignUpgradeAuthority {
                    program,
                    authority,
                    expected: deployer.pubkey(),
                })
            }
            Some(_) => {}
        }
    }
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
    let ring_rpc = ctx.ring_rpc();
    let source = match choice {
        KeyChoice::File => AuditorKeySource::File(&auditor_pubkey_file),
        KeyChoice::Chain(auditor_pk) => {
            if auditor_pubkey_file.exists() {
                let file = read_auditor_pubkey(auditor_pubkey_file.as_path())?;
                if file != auditor_pk {
                    return Err(InitError::StaleAuditorFile {
                        path: auditor_pubkey_file,
                        file: hex::encode(file.as_bytes()),
                        chain: hex::encode(auditor_pk.as_bytes()),
                    });
                }
            }
            AuditorKeySource::Chain(auditor_pk)
        }
        KeyChoice::RingRpc => AuditorKeySource::RingRpc {
            client: &ring_rpc,
            release: AuditorKeyRelease {
                ring: ctx.ring.program_id(),
                genesis_hash: ctx.genesis_hash()?,
                authority: upgrade_authority
                    .as_ref()
                    .ok_or(InitError::UpgradeAuthorityNeeded)?,
            },
            trust: ctx
                .trust(if args.trust_ring_rpc {
                    Trust::Unpinned
                } else {
                    Trust::Refuse
                })
                .map_err(ContextError::from)?,
        },
    };
    let auditor_pk = source.resolve()?;
    let outcome = Init {
        ring: ctx.ring,
        upgrade_authority: upgrade_authority
            .as_ref()
            .map(|keypair| keypair as &dyn Signer),
        config_authority: &config_authority,
        auditor_pk,
        records_tree: args.records_tree,
        shared_sources: crate::record::shared_sources(ctx.config.policy.as_ref())
            .map_err(|error| InitError::PolicySources(Box::new(error)))?,
        existing,
    }
    .run(&ctx.rpc)?;
    // Written after the chain agrees, a failed init must not leave a file
    // that the next run mistakes for a local key.
    if matches!(source, AuditorKeySource::RingRpc { .. }) {
        write_auditor_pubkey(&auditor_pubkey_file, &auditor_pk)?;
        line(
            "auditor pk",
            format_args!(
                "{} (from {}, written to {})",
                hex::encode(auditor_pk.as_bytes()),
                ctx.config.urls().ring_rpc,
                auditor_pubkey_file.display()
            ),
        );
    }
    line("config", outcome.config.label());
    line(
        "authority",
        match outcome.authority {
            StepOutcome::Created => "transferred",
            other => other.label(),
        },
    );
    line(
        "spp ring",
        match outcome.ring {
            StepOutcome::Created => "registered",
            other => other.label(),
        },
    );
    line("policy", outcome.policy.label());
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
            } => Ok(client.release_auditor_key(release)?.require(*trust)?),
        }
    }
}

impl ConfigOwnership {
    pub fn decide(self) -> Result<ConfigState, ForeignConfigAuthority> {
        match self.existing {
            None => Ok(ConfigState::Missing),
            Some(authority) if authority == self.config_authority => {
                Ok(ConfigState::HeldByConfigAuthority)
            }
            Some(authority) if Some(authority) == self.upgrade_authority => {
                Ok(ConfigState::HeldByUpgradeAuthority)
            }
            Some(authority) => Err(ForeignConfigAuthority(authority)),
        }
    }
}

impl Init<'_> {
    pub fn run(self, rpc: &SolanaRpc) -> Result<InitOutcome, InitError> {
        let config_authority = self.config_authority.pubkey();
        if let Some(config) = self
            .existing
            .as_ref()
            .filter(|config| config.auditor_pubkey != self.auditor_pk)
        {
            return Err(InitError::ConfigMismatch {
                authority: config.authority,
                auditor: hex::encode(config.auditor_pubkey.as_bytes()),
            });
        }
        let state = ConfigOwnership {
            existing: self.existing.as_ref().map(|config| config.authority),
            upgrade_authority: self.upgrade_authority.map(Signer::pubkey),
            config_authority,
        }
        .decide()
        .map_err(
            |ForeignConfigAuthority(authority)| InitError::ConfigMismatch {
                authority,
                auditor: hex::encode(self.auditor_pk.as_bytes()),
            },
        )?;
        let (config, authority) = match state {
            ConfigState::HeldByConfigAuthority => (StepOutcome::Present, StepOutcome::Present),
            ConfigState::Missing => {
                let deployer = self.deployer()?;
                let mut instructions = vec![CreateConfig {
                    ring: self.ring,
                    payer: config_authority,
                    authority: deployer.pubkey(),
                    auditor_pubkey: self.auditor_pk,
                }
                .instruction()?];
                let transfer = deployer.pubkey() != config_authority;
                if transfer {
                    instructions.push(self.hand_over(deployer.pubkey()));
                }
                self.step(
                    rpc,
                    "create_config",
                    &[deployer],
                    CREATE_CONFIG_COMPUTE_UNIT_LIMIT + SET_AUTHORITY_COMPUTE_UNIT_LIMIT,
                )
                .ensure_present(Observed::Absent, &instructions)?;
                (
                    StepOutcome::Created,
                    if transfer {
                        StepOutcome::Created
                    } else {
                        StepOutcome::Present
                    },
                )
            }
            ConfigState::HeldByUpgradeAuthority => {
                let deployer = self.deployer()?;
                let authority = self
                    .step(
                        rpc,
                        "set_authority",
                        &[deployer],
                        SET_AUTHORITY_COMPUTE_UNIT_LIMIT,
                    )
                    .ensure_present(Observed::Absent, &[self.hand_over(deployer.pubkey())])?;
                (StepOutcome::Present, authority)
            }
        };
        let ring = self
            .step(
                rpc,
                "init_spp_ring_config",
                &[],
                INIT_SPP_RING_CONFIG_COMPUTE_UNIT_LIMIT,
            )
            .ensure_present(
                Observed::of(&self.ring.read_spp_ring_config(rpc)?),
                &[InitSppRingConfig {
                    ring: self.ring,
                    payer: config_authority,
                    authority: config_authority,
                }
                .instruction()],
            )?;
        // Only the upgrade authority may pin the compiled policy table.
        let policy = match Observed::of(&self.ring.read_policy_config(rpc)?) {
            Observed::Present => StepOutcome::Present,
            Observed::Absent => {
                let deployer = self.deployer()?;
                self.step(
                    rpc,
                    "create_policy",
                    &[deployer],
                    CREATE_POLICY_COMPUTE_UNIT_LIMIT,
                )
                .ensure_present(
                    Observed::Absent,
                    &[CreatePolicy {
                        ring: self.ring,
                        payer: config_authority,
                        authority: deployer.pubkey(),
                        records_tree: self.records_tree,
                        shared_sources: self.shared_sources.clone(),
                    }
                    .instruction()?],
                )?
            }
        };
        Ok(InitOutcome {
            config,
            authority,
            ring,
            policy,
        })
    }

    fn deployer(&self) -> Result<&dyn Signer, InitError> {
        self.upgrade_authority
            .ok_or(InitError::UpgradeAuthorityNeeded)
    }

    fn hand_over(&self, deployer: Address) -> Instruction {
        SetAuthority {
            ring: self.ring,
            authority: deployer,
            new_authority: self.config_authority.pubkey(),
        }
        .instruction()
    }

    fn step<'r>(
        &'r self,
        rpc: &'r SolanaRpc,
        name: &'static str,
        co_signers: &'r [&'r dyn Signer],
        compute_unit_limit: u32,
    ) -> IdempotentStep<'r> {
        IdempotentStep {
            rpc,
            authority: self.config_authority,
            co_signers,
            name,
            compute_unit_limit,
            hint,
        }
    }
}

fn hint(code: u32) -> Option<&'static str> {
    if code == CustomRingError::UnauthorizedInitializer as u32 {
        Some("the program was deployed with an upgrade authority and only that key may create the config")
    } else if code == CustomRingError::UnauthorizedAuthority as u32 {
        Some("the config is held by another authority, `status` shows it")
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
        for file_present in [true, false] {
            for hosted_rpc in [true, false] {
                for local_auditor in [true, false] {
                    let selection = KeySelection {
                        configured: Some(pinned),
                        ..select(file_present, hosted_rpc, local_auditor)
                    };
                    assert_eq!(selection.decide(), Ok(KeyChoice::Chain(pinned)));
                }
            }
        }
    }

    #[test]
    fn without_a_config_the_file_is_taken_only_where_the_service_wrote_it() {
        for hosted_rpc in [true, false] {
            for local_auditor in [true, false] {
                assert_eq!(
                    select(false, hosted_rpc, local_auditor).decide(),
                    Ok(KeyChoice::RingRpc)
                );
            }
        }
        assert_eq!(select(true, false, false).decide(), Ok(KeyChoice::File));
        assert_eq!(select(true, false, true).decide(), Ok(KeyChoice::File));
        assert_eq!(select(true, true, true).decide(), Ok(KeyChoice::File));
        assert_eq!(select(true, true, false).decide(), Err(StrayLocalKey));
    }

    #[test]
    fn the_config_moves_from_the_upgrade_authority_to_the_config_authority_once() {
        let deployer = Address::new_from_array([1; 32]);
        let target = Address::new_from_array([2; 32]);
        let stranger = Address::new_from_array([3; 32]);
        let ownership = |existing, upgrade_authority| ConfigOwnership {
            existing,
            upgrade_authority,
            config_authority: target,
        };
        assert_eq!(
            ownership(None, Some(deployer)).decide(),
            Ok(ConfigState::Missing)
        );
        assert_eq!(ownership(None, None).decide(), Ok(ConfigState::Missing));
        assert_eq!(
            ownership(Some(deployer), Some(deployer)).decide(),
            Ok(ConfigState::HeldByUpgradeAuthority)
        );
        assert_eq!(
            ownership(Some(target), Some(deployer)).decide(),
            Ok(ConfigState::HeldByConfigAuthority)
        );
        assert_eq!(
            ownership(Some(target), None).decide(),
            Ok(ConfigState::HeldByConfigAuthority)
        );
        assert_eq!(
            ownership(Some(deployer), None).decide(),
            Err(ForeignConfigAuthority(deployer))
        );
        assert_eq!(
            ownership(Some(stranger), Some(deployer)).decide(),
            Err(ForeignConfigAuthority(stranger))
        );
        let same_key = ConfigOwnership {
            existing: Some(deployer),
            upgrade_authority: Some(deployer),
            config_authority: deployer,
        };
        assert_eq!(same_key.decide(), Ok(ConfigState::HeldByConfigAuthority));
    }
}
