//! The Solana CLI owns the loader v3 write protocol.

use std::{
    io,
    path::{Path, PathBuf},
    process::{Command, ExitStatus},
};

use custom_ring_sdk::CustomRing;
use solana_address::Address;
use solana_keypair::read_keypair_file;
use solana_loader_v3_interface::state::UpgradeableLoaderState;
use solana_signer::Signer;
use thiserror::Error;
use zolana_client::{ClientError, Rpc, SolanaRpc};

use crate::{config::expand_tilde, Context, ContextError, DeployArgs};

pub struct Deploy<'a> {
    pub ring: CustomRing,
    pub authority_keypair: &'a Path,
    pub authority: Address,
    /// Read on the first deploy only.
    pub program_keypair: &'a Path,
    pub program_so: &'a Path,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeployOutcome {
    Deployed,
    Upgraded,
}

pub struct ProgramDataInfo {
    pub upgrade_authority: Option<Address>,
    pub capacity: usize,
}

#[derive(Debug, Error)]
pub enum DeployError {
    #[error(transparent)]
    Context(#[from] ContextError),
    #[error("{label} not found at {path}")]
    MissingFile { label: &'static str, path: PathBuf },
    #[error("cannot read {path}")]
    Metadata {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("program {program} is upgradeable by {authority}, ring.toml names {expected}")]
    ForeignAuthority {
        program: Address,
        authority: Address,
        expected: Address,
    },
    #[error("program {program} is immutable, it cannot be upgraded")]
    Immutable { program: Address },
    #[error("program keypair not found at {path}, the first deploy needs it")]
    MissingProgramKeypair { path: PathBuf },
    #[error("cannot read program keypair {path}, {message}")]
    ProgramKeypair { path: PathBuf, message: String },
    #[error("program keypair is {found}, ring.toml names {expected}")]
    ProgramKeypairMismatch { expected: Address, found: Address },
    #[error("cannot run `solana program {command}`, is the Solana CLI installed")]
    SolanaCli {
        command: &'static str,
        #[source]
        source: io::Error,
    },
    #[error("`solana program {command}` exited with {status}")]
    SolanaCliStatus {
        command: &'static str,
        status: ExitStatus,
    },
    #[error("program {program} is not executable after deploy")]
    NotExecutable {
        program: Address,
        #[source]
        source: Box<ClientError>,
    },
    #[error("{address} is not a ProgramData account")]
    ProgramData { address: Address },
    #[error(transparent)]
    Client(Box<ClientError>),
}

impl From<ClientError> for DeployError {
    fn from(error: ClientError) -> Self {
        Self::Client(Box::new(error))
    }
}

/// The smallest growth of `ProgramData` the loader accepts.
const MIN_EXTEND_BYTES: usize = 10_240;

pub fn run(ctx: &mut Context, args: DeployArgs) -> Result<(), DeployError> {
    let authority = ctx.funded_authority()?;
    let program_so = args
        .program_so
        .unwrap_or_else(|| default_program_so(&ctx.config.name));
    let outcome = Deploy {
        ring: ctx.ring,
        authority_keypair: &expand_tilde(&ctx.config.authority_keypair)
            .map_err(ContextError::from)?,
        authority: authority.pubkey(),
        program_keypair: &args.program_keypair,
        program_so: &program_so,
    }
    .run(&ctx.rpc)?;
    println!(
        "{} {} under {}",
        match outcome {
            DeployOutcome::Deployed => "deployed",
            DeployOutcome::Upgraded => "upgraded",
        },
        ctx.ring.program_id(),
        authority.pubkey()
    );
    crate::status::announce(&ctx.config);
    Ok(())
}

impl Deploy<'_> {
    pub fn run(self, rpc: &SolanaRpc) -> Result<DeployOutcome, DeployError> {
        for (label, path) in [
            ("authority keypair", self.authority_keypair),
            ("program binary", self.program_so),
        ] {
            if !path.exists() {
                return Err(DeployError::MissingFile {
                    label,
                    path: path.to_path_buf(),
                });
            }
        }
        let so_len = std::fs::metadata(self.program_so)
            .map_err(|source| DeployError::Metadata {
                path: self.program_so.to_path_buf(),
                source,
            })?
            .len() as usize;
        let program = self.ring.program_id();

        let deployed = read_program_data(rpc, self.ring)?;
        if let Some(info) = &deployed {
            match info.upgrade_authority {
                Some(authority) if authority == self.authority => {}
                Some(authority) => {
                    return Err(DeployError::ForeignAuthority {
                        program,
                        authority,
                        expected: self.authority,
                    })
                }
                None => return Err(DeployError::Immutable { program }),
            }
            if so_len > info.capacity {
                self.extend(
                    rpc.client().url(),
                    (so_len - info.capacity).max(MIN_EXTEND_BYTES),
                )?;
            }
        } else {
            self.check_program_keypair()?;
        }

        let mut command = Command::new("solana");
        command
            .args([
                "program",
                "deploy",
                "--url",
                &rpc.client().url(),
                "--keypair",
            ])
            .arg(self.authority_keypair)
            .arg("--upgrade-authority")
            .arg(self.authority_keypair)
            .arg("--program-id");
        if deployed.is_some() {
            command.arg(program.to_string());
        } else {
            command.arg(self.program_keypair);
        }
        let status =
            command
                .arg(self.program_so)
                .status()
                .map_err(|source| DeployError::SolanaCli {
                    command: "deploy",
                    source,
                })?;
        if !status.success() {
            return Err(DeployError::SolanaCliStatus {
                command: "deploy",
                status,
            });
        }
        rpc.assert_executable(&program)
            .map_err(|source| DeployError::NotExecutable {
                program,
                source: Box::new(source),
            })?;
        Ok(if deployed.is_some() {
            DeployOutcome::Upgraded
        } else {
            DeployOutcome::Deployed
        })
    }

    fn check_program_keypair(&self) -> Result<(), DeployError> {
        if !self.program_keypair.exists() {
            return Err(DeployError::MissingProgramKeypair {
                path: self.program_keypair.to_path_buf(),
            });
        }
        let found = read_keypair_file(self.program_keypair)
            .map_err(|error| DeployError::ProgramKeypair {
                path: self.program_keypair.to_path_buf(),
                message: error.to_string(),
            })?
            .pubkey();
        if found != self.ring.program_id() {
            return Err(DeployError::ProgramKeypairMismatch {
                expected: self.ring.program_id(),
                found,
            });
        }
        Ok(())
    }

    fn extend(&self, url: String, additional_bytes: usize) -> Result<(), DeployError> {
        println!("extending program data by {additional_bytes} bytes");
        let status = Command::new("solana")
            .args(["program", "extend", "--url", &url, "--keypair"])
            .arg(self.authority_keypair)
            .arg(self.ring.program_id().to_string())
            .arg(additional_bytes.to_string())
            .status()
            .map_err(|source| DeployError::SolanaCli {
                command: "extend",
                source,
            })?;
        if !status.success() {
            return Err(DeployError::SolanaCliStatus {
                command: "extend",
                status,
            });
        }
        Ok(())
    }
}

/// `None` when the program is not deployed under the upgradeable loader.
pub fn read_program_data<R: Rpc>(
    rpc: &R,
    ring: CustomRing,
) -> Result<Option<ProgramDataInfo>, DeployError> {
    if rpc.get_account(ring.program_id())?.is_none() {
        return Ok(None);
    }
    let address = ring.program_data_pda();
    let Some(account) = rpc.get_account(address)? else {
        return Ok(None);
    };
    let (state, _) = bincode::serde::decode_from_slice::<UpgradeableLoaderState, _>(
        &account.data,
        bincode::config::legacy(),
    )
    .map_err(|_| DeployError::ProgramData { address })?;
    let UpgradeableLoaderState::ProgramData {
        upgrade_authority_address,
        ..
    } = state
    else {
        return Err(DeployError::ProgramData { address });
    };
    Ok(Some(ProgramDataInfo {
        upgrade_authority: upgrade_authority_address
            .map(|key| Address::new_from_array(key.to_bytes()))
            .filter(|key| *key != Address::default()),
        capacity: account
            .data
            .len()
            .saturating_sub(UpgradeableLoaderState::size_of_programdata_metadata()),
    }))
}

fn default_program_so(name: &str) -> PathBuf {
    PathBuf::from(format!(
        "target/deploy/{}_program.so",
        name.replace('-', "_")
    ))
}
