use std::{
    io,
    path::Path,
    process::{Command, ExitStatus},
};

use custom_ring_sdk::{CustomRing, SetAuthority, SET_AUTHORITY_COMPUTE_UNIT_LIMIT};
use solana_address::Address;
use solana_compute_budget_interface::ComputeBudgetInstruction;
use solana_keypair::read_keypair_file;
use solana_signer::Signer;
use thiserror::Error;
use zolana_client::{Rpc, SolanaRpc};

use crate::{
    config::{expand_tilde, ConfigError},
    deploy::{read_program_data, DeployError, ProgramDataInfo},
    AuthorityCommand, Context,
};

pub struct SetUpgradeAuthority<'a> {
    pub ring: CustomRing,
    pub authority_keypair: &'a Path,
    pub authority: Address,
    pub current: &'a ProgramDataInfo,
}

#[derive(Debug, Error)]
pub enum AuthorityError {
    #[error(transparent)]
    Config(#[from] ConfigError),
    #[error(transparent)]
    Deploy(#[from] DeployError),
    #[error("program {program} is not deployed under the upgradeable loader")]
    NotDeployed { program: Address },
    #[error("program {program} is upgradeable by {authority}, ring.toml names {expected}")]
    ForeignAuthority {
        program: Address,
        authority: Address,
        expected: Address,
    },
    #[error("program {program} is already immutable")]
    Immutable { program: Address },
    #[error("renouncing is irreversible, pass --yes to make {program} immutable")]
    NeedsConfirmation { program: Address },
    #[error("cannot run `solana program set-upgrade-authority`, is the Solana CLI installed")]
    SolanaCli(#[source] io::Error),
    #[error("`solana program set-upgrade-authority` exited with {status}")]
    SolanaCliStatus { status: ExitStatus },
    #[error("cannot read the new authority keypair {path}")]
    NewAuthorityKeypair { path: String },
    #[error("sending set_authority failed")]
    SetAuthority(#[source] Box<zolana_client::ClientError>),
}

pub fn run(ctx: &Context, command: AuthorityCommand) -> Result<(), AuthorityError> {
    let authority = ctx.config.authority()?;
    let program = ctx.ring.program_id();
    match command {
        AuthorityCommand::Transfer { new_authority } => {
            let current = deployed_program_data(&ctx.rpc, ctx.ring)?;
            SetUpgradeAuthority {
                ring: ctx.ring,
                authority_keypair: &expand_tilde(&ctx.config.authority_keypair)?,
                authority: authority.pubkey(),
                current: &current,
            }
            .transfer(new_authority, &ctx.rpc)?;
            println!(
                "upgrade authority of {program} is now {new_authority}, point authority_keypair in {} at its keypair",
                ctx.config_path.display()
            );
        }
        AuthorityCommand::TransferConfig {
            new_authority_keypair,
        } => {
            let path = expand_tilde(&new_authority_keypair)?;
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
                "ring config authority of {program} is now {}, point authority_keypair in {} at its keypair",
                new_authority.pubkey(),
                ctx.config_path.display()
            );
        }
        AuthorityCommand::Renounce { yes } => {
            if !yes {
                return Err(AuthorityError::NeedsConfirmation { program });
            }
            let current = deployed_program_data(&ctx.rpc, ctx.ring)?;
            SetUpgradeAuthority {
                ring: ctx.ring,
                authority_keypair: &expand_tilde(&ctx.config.authority_keypair)?,
                authority: authority.pubkey(),
                current: &current,
            }
            .renounce(&ctx.rpc)?;
            println!("{program} is immutable");
        }
    }
    Ok(())
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

    /// Irreversible, and `create_config` falls back to plain authority gating afterwards.
    pub fn renounce(self, rpc: &SolanaRpc) -> Result<(), AuthorityError> {
        self.check_current()?;
        self.run(rpc, &["--final"])
    }

    fn check_current(&self) -> Result<(), AuthorityError> {
        let program = self.ring.program_id();
        match self.current.upgrade_authority {
            Some(authority) if authority == self.authority => Ok(()),
            Some(authority) => Err(AuthorityError::ForeignAuthority {
                program,
                authority,
                expected: self.authority,
            }),
            None => Err(AuthorityError::Immutable { program }),
        }
    }

    fn run(&self, rpc: &SolanaRpc, args: &[&str]) -> Result<(), AuthorityError> {
        let status = Command::new("solana")
            .args([
                "program",
                "set-upgrade-authority",
                "--url",
                &rpc.client().url(),
                "--keypair",
            ])
            .arg(self.authority_keypair)
            .arg(self.ring.program_id().to_string())
            .args(args)
            .status()
            .map_err(AuthorityError::SolanaCli)?;
        if !status.success() {
            return Err(AuthorityError::SolanaCliStatus { status });
        }
        Ok(())
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
