use std::{
    path::{Path, PathBuf},
    process::Command,
};

use custom_ring_sdk::{
    AccountReadError, CustomRing, SetAuthority, SET_AUTHORITY_COMPUTE_UNIT_LIMIT,
};
use solana_address::Address;
use solana_compute_budget_interface::ComputeBudgetInstruction;
use solana_keypair::read_keypair_file;
use solana_signer::Signer;
use thiserror::Error;
use zolana_client::{Rpc, SolanaRpc};

use crate::{
    config::{expand_tilde, ConfigError},
    deploy::{read_program_data, DeployError, ProgramBinary, ProgramDataInfo},
    file::FileError,
    release::{ReleaseError, RingProgram},
    tool::{ToolError, SOLANA},
    AuthorityCommand, Context,
};

pub struct SetUpgradeAuthority<'a> {
    pub ring: CustomRing,
    pub authority_keypair: &'a Path,
    pub authority: Address,
    pub current: &'a ProgramDataInfo,
}

#[must_use]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum InitializationState {
    Complete,
    Incomplete,
}

#[derive(Debug, Error)]
pub enum AuthorityError {
    #[error(transparent)]
    Config(#[from] ConfigError),
    #[error(transparent)]
    Deploy(Box<DeployError>),
    #[error("program {program} is not deployed under the upgradeable loader")]
    NotDeployed { program: Address },
    #[error("renouncing is irreversible, pass --yes to make {program} immutable")]
    NeedsConfirmation { program: Address },
    #[error("pass --yes to hand {program} on {target} to {new_authority}, only that key can hand it back")]
    NeedsTransferConfirmation {
        program: Address,
        target: &'static str,
        new_authority: Address,
    },
    #[error(transparent)]
    Release(#[from] ReleaseError),
    #[error(transparent)]
    File(#[from] FileError),
    #[error("release lock sha256 {sha256} is not hex")]
    LockDigest { sha256: String },
    #[error("ring {program} is not initialized, run `init` before renouncing")]
    NotInitialized { program: Address },
    #[error(transparent)]
    AccountRead(#[from] AccountReadError),
    #[error(transparent)]
    Tool(#[from] ToolError),
    #[error("cannot read the new authority keypair {path}")]
    NewAuthorityKeypair { path: String },
    #[error("sending set_authority failed")]
    SetAuthority(#[source] Box<zolana_client::ClientError>),
}

pub fn run(ctx: &Context, command: AuthorityCommand) -> Result<(), AuthorityError> {
    let program = ctx.ring.program_id();
    match command {
        AuthorityCommand::Transfer { new_authority, yes } => {
            if !yes {
                return Err(AuthorityError::NeedsTransferConfirmation {
                    program,
                    target: ctx.config.target.as_str(),
                    new_authority,
                });
            }
            require_initialized(ctx)?;
            let authority = ctx.config.upgrade_authority()?;
            let current = deployed_program_data(&ctx.rpc, ctx.ring)?;
            SetUpgradeAuthority {
                ring: ctx.ring,
                authority_keypair: &expand_tilde(ctx.config.upgrade_authority_keypair())?,
                authority: authority.pubkey(),
                current: &current,
            }
            .transfer(new_authority, &ctx.rpc)?;
            println!(
                "upgrade authority of {program} is now {new_authority}, set upgrade_authority_keypair in {}",
                ctx.config_path.display()
            );
        }
        AuthorityCommand::TransferConfig {
            new_authority_keypair,
        } => {
            let authority = ctx.config.config_authority()?;
            let path = expand_tilde(&ctx.project_path(&new_authority_keypair))?;
            let new_authority =
                read_keypair_file(&path).map_err(|_| AuthorityError::NewAuthorityKeypair {
                    path: path.display().to_string(),
                })?;
            let instructions = [
                ComputeBudgetInstruction::set_compute_unit_limit(SET_AUTHORITY_COMPUTE_UNIT_LIMIT),
                SetAuthority {
                    ring: ctx.ring,
                    authority: authority.pubkey(),
                    new_authority: new_authority.pubkey(),
                }
                .instruction(),
            ];
            ctx.rpc
                .create_and_send_transaction(
                    &instructions,
                    authority.pubkey(),
                    &[&authority, &new_authority],
                )
                .map_err(|source| AuthorityError::SetAuthority(Box::new(source)))?;
            println!(
                "ring config authority of {program} is now {}, set config_authority_keypair in {} to {}",
                new_authority.pubkey(),
                ctx.config_path.display(),
                new_authority_keypair.display()
            );
        }
        AuthorityCommand::Renounce { yes, program_so } => {
            if !yes {
                return Err(AuthorityError::NeedsConfirmation { program });
            }
            let authority = ctx.config.upgrade_authority()?;
            require_initialized(ctx)?;
            expected_binary(ctx, program_so)?.verify_deployed(&ctx.rpc, ctx.ring)?;
            let current = deployed_program_data(&ctx.rpc, ctx.ring)?;
            SetUpgradeAuthority {
                ring: ctx.ring,
                authority_keypair: &expand_tilde(ctx.config.upgrade_authority_keypair())?,
                authority: authority.pubkey(),
                current: &current,
            }
            .renounce(&ctx.rpc)?;
            println!("{program} is immutable");
        }
    }
    Ok(())
}

fn expected_binary(
    ctx: &Context,
    program_so: Option<PathBuf>,
) -> Result<ProgramBinary, AuthorityError> {
    if let Some(path) = program_so {
        return Ok(ProgramBinary::read(&ctx.project_path(&path))?);
    }
    let program = RingProgram::from_lock()?;
    let sha256 = hex::decode(&program.asset.sha256)
        .ok()
        .and_then(|bytes| <[u8; 32]>::try_from(bytes).ok())
        .ok_or_else(|| AuthorityError::LockDigest {
            sha256: program.asset.sha256.clone(),
        })?;
    Ok(ProgramBinary {
        len: program.asset.size as usize,
        sha256,
    })
}

fn require_initialized(ctx: &Context) -> Result<(), AuthorityError> {
    InitializationState::observe(
        ctx.ring.read_config(&ctx.rpc)?,
        ctx.ring.read_spp_ring_config(&ctx.rpc)?,
        ctx.ring.read_policy_config(&ctx.rpc)?,
    )
    .require(ctx.ring.program_id())
}

impl InitializationState {
    /// An unpinned policy can never be created once renounce drops the upgrade authority.
    fn observe<C, R, P>(config: Option<C>, spp_ring: Option<R>, policy: Option<P>) -> Self {
        if config.is_some() && spp_ring.is_some() && policy.is_some() {
            Self::Complete
        } else {
            Self::Incomplete
        }
    }

    fn require(self, program: Address) -> Result<(), AuthorityError> {
        match self {
            Self::Complete => Ok(()),
            Self::Incomplete => Err(AuthorityError::NotInitialized { program }),
        }
    }
}

impl SetUpgradeAuthority<'_> {
    pub fn transfer(self, new_authority: Address, rpc: &SolanaRpc) -> Result<(), AuthorityError> {
        self.check_current()?;
        self.run(
            rpc,
            &[
                "--new-upgrade-authority",
                &new_authority.to_string(),
                "--skip-new-upgrade-authority-signer-check",
            ],
        )
    }

    pub fn renounce(self, rpc: &SolanaRpc) -> Result<(), AuthorityError> {
        self.check_current()?;
        self.run(rpc, &["--final"])
    }

    fn check_current(&self) -> Result<(), AuthorityError> {
        let program = self.ring.program_id();
        match self.current.upgrade_authority {
            Some(authority) if authority == self.authority => Ok(()),
            Some(authority) => Err(DeployError::ForeignAuthority {
                program,
                authority,
                expected: self.authority,
            }
            .into()),
            None => Err(DeployError::Immutable { program }.into()),
        }
    }

    fn run(&self, rpc: &SolanaRpc, args: &[&str]) -> Result<(), AuthorityError> {
        Ok(SOLANA.named("solana program set-upgrade-authority").run(
            Command::new("solana")
                .args([
                    "program",
                    "set-upgrade-authority",
                    "--url",
                    &rpc.client().url(),
                    "--keypair",
                ])
                .arg(self.authority_keypair)
                .arg(self.ring.program_id().to_string())
                .args(args),
        )?)
    }
}

pub fn deployed_program_data<R: Rpc>(
    rpc: &R,
    ring: CustomRing,
) -> Result<ProgramDataInfo, AuthorityError> {
    read_program_data(rpc, ring)?.ok_or(AuthorityError::NotDeployed {
        program: ring.program_id(),
    })
}

impl From<DeployError> for AuthorityError {
    fn from(error: DeployError) -> Self {
        Self::Deploy(Box::new(error))
    }
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use custom_ring_sdk::CustomRing;

    use super::*;

    fn check(upgrade_authority: Option<Address>) -> Result<(), AuthorityError> {
        let current = ProgramDataInfo {
            upgrade_authority,
            capacity: 0,
            slot: 0,
        };
        SetUpgradeAuthority {
            ring: CustomRing::new(Address::new_from_array([1; 32])),
            authority_keypair: Path::new("unused"),
            authority: Address::new_from_array([2; 32]),
            current: &current,
        }
        .check_current()
    }

    #[test]
    fn only_the_recorded_upgrade_authority_may_move_the_program() {
        assert!(check(Some(Address::new_from_array([2; 32]))).is_ok());
        assert!(matches!(
            check(Some(Address::new_from_array([3; 32]))),
            Err(AuthorityError::Deploy(error))
                if matches!(*error, DeployError::ForeignAuthority { .. })
        ));
        assert!(matches!(
            check(None),
            Err(AuthorityError::Deploy(error)) if matches!(*error, DeployError::Immutable { .. })
        ));
    }

    #[test]
    fn renounce_requires_every_ring_account_including_the_policy() {
        let program = Address::new_from_array([1; 32]);
        for state in [
            InitializationState::observe(None::<()>, None::<()>, None::<()>),
            InitializationState::observe(Some(()), None::<()>, None::<()>),
            InitializationState::observe(None::<()>, Some(()), None::<()>),
            InitializationState::observe(Some(()), Some(()), None::<()>),
            InitializationState::observe(Some(()), None::<()>, Some(())),
        ] {
            assert!(matches!(
                state.require(program),
                Err(AuthorityError::NotInitialized { program: found }) if found == program
            ));
        }
        assert!(InitializationState::observe(Some(()), Some(()), Some(()))
            .require(program)
            .is_ok());
    }
}
