//! The Solana CLI owns the loader v3 write protocol.

use std::{
    path::{Path, PathBuf},
    process::Command,
    thread,
    time::{Duration, Instant},
};

use custom_ring_sdk::CustomRing;
use sha2::{Digest, Sha256};
use solana_address::Address;
use solana_loader_v3_interface::state::UpgradeableLoaderState;
use solana_signer::Signer;
use thiserror::Error;
use zolana_client::{ClientError, Rpc, SolanaRpc};

use crate::{
    config::expand_tilde,
    file::{self, FileError},
    line,
    release::{ReleaseError, RingProgram, RingTier},
    tool::{ToolError, SOLANA},
    Context, ContextError, DeployArgs,
};

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
    Present,
}

pub struct ProgramDataInfo {
    pub upgrade_authority: Option<Address>,
    pub capacity: usize,
    /// The loader serves the program only after this slot.
    pub slot: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProgramBinary {
    pub len: usize,
    pub sha256: [u8; 32],
}

pub enum DeployPlan {
    Present,
    Upload {
        binary: ProgramBinary,
        /// `None` on the first deploy.
        deployed: Option<ProgramDataInfo>,
        required_balance: u64,
    },
}

#[derive(Debug, Error)]
pub enum DeployError {
    #[error(transparent)]
    Context(#[from] ContextError),
    #[error("{label} not found at {path}")]
    MissingFile { label: &'static str, path: PathBuf },
    #[error(transparent)]
    File(#[from] FileError),
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
    #[error("program keypair is {found}, ring.toml names {expected}")]
    ProgramKeypairMismatch { expected: Address, found: Address },
    #[error(transparent)]
    Tool(#[from] ToolError),
    #[error(transparent)]
    Release(#[from] ReleaseError),
    #[error("program {program} is not executable after deploy")]
    NotExecutable {
        program: Address,
        #[source]
        source: Box<ClientError>,
    },
    #[error("{address} is not a ProgramData account")]
    ProgramData { address: Address },
    #[error(
        "program {program} deployed at slot {slot} stays unusable, the validator does not advance"
    )]
    NotUsable { program: Address, slot: u64 },
    #[error("program {program} holds {found} on chain, expected {expected}")]
    DeployedMismatch {
        program: Address,
        expected: String,
        found: String,
    },
    #[error(transparent)]
    Client(Box<ClientError>),
}

/// The smallest growth of `ProgramData` the loader accepts.
const MIN_EXTEND_BYTES: usize = 10_240;
/// A deploy is hundreds of writes plus the loader calls.
const DEPLOY_FEE_BUDGET: u64 = 20_000_000;
const USABLE_TIMEOUT: Duration = Duration::from_secs(60);
const SLOT_POLL: Duration = Duration::from_millis(400);

pub fn run(ctx: &mut Context, args: DeployArgs) -> Result<(), DeployError> {
    let program_so = match args.program_so {
        Some(path) => ctx.project_path(&path),
        None => released_program_so(RingTier::of(ctx.config.policy.as_ref()))?,
    };
    line("binary", program_so.display());
    let program_keypair = ctx.project_path(&args.program_keypair);
    let authority = ctx.config.upgrade_authority().map_err(ContextError::from)?;
    let authority_keypair =
        expand_tilde(ctx.config.upgrade_authority_keypair()).map_err(ContextError::from)?;
    let deploy = Deploy {
        ring: ctx.ring,
        authority_keypair: &authority_keypair,
        authority: authority.pubkey(),
        program_keypair: &program_keypair,
        program_so: &program_so,
    };
    let planned = deploy.plan(&ctx.rpc)?;
    if let DeployPlan::Upload {
        required_balance, ..
    } = &planned
    {
        // A short balance fails before the loader writes.
        ctx.fund_authority(&authority, *required_balance)?;
    }
    let outcome = deploy.apply(&ctx.rpc, planned)?;
    println!(
        "{} {} under {}",
        match outcome {
            DeployOutcome::Deployed => "deployed",
            DeployOutcome::Upgraded => "upgraded",
            DeployOutcome::Present => "present",
        },
        ctx.ring.program_id(),
        authority.pubkey()
    );
    Ok(())
}

impl Deploy<'_> {
    pub fn plan(&self, rpc: &SolanaRpc) -> Result<DeployPlan, DeployError> {
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
        let binary = ProgramBinary::read(self.program_so)?;
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
        } else {
            self.check_program_keypair()?;
        }
        if deployed.is_some() && binary.deployed_sha256(rpc, self.ring)? == Some(binary.sha256) {
            return Ok(DeployPlan::Present);
        }
        let required_balance = required_balance(rpc, binary.len, deployed.as_ref())?;
        Ok(DeployPlan::Upload {
            binary,
            deployed,
            required_balance,
        })
    }

    pub fn apply(self, rpc: &SolanaRpc, plan: DeployPlan) -> Result<DeployOutcome, DeployError> {
        let DeployPlan::Upload {
            binary, deployed, ..
        } = plan
        else {
            return Ok(DeployOutcome::Present);
        };
        let program = self.ring.program_id();
        if let Some(info) = &deployed {
            if binary.len > info.capacity {
                self.extend(
                    rpc.client().url(),
                    (binary.len - info.capacity).max(MIN_EXTEND_BYTES),
                )?;
            }
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
        SOLANA
            .named("solana program deploy")
            .run(command.arg(self.program_so))?;
        rpc.assert_executable(&program)
            .map_err(|source| DeployError::NotExecutable {
                program,
                source: Box::new(source),
            })?;
        binary.verify_deployed(rpc, self.ring)?;
        let upgraded = deployed.is_some();
        let deployed = read_program_data(rpc, self.ring)?.ok_or(DeployError::ProgramData {
            address: self.ring.program_data_pda(),
        })?;
        wait_until_usable(rpc, program, deployed.slot)?;
        Ok(if upgraded {
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
        let found = file::read_keypair(self.program_keypair)?.pubkey();
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
        Ok(SOLANA.named("solana program extend").run(
            Command::new("solana")
                .args(["program", "extend", "--url", &url, "--keypair"])
                .arg(self.authority_keypair)
                .arg(self.ring.program_id().to_string())
                .arg(additional_bytes.to_string()),
        )?)
    }
}

impl ProgramBinary {
    pub fn read(path: &Path) -> Result<Self, FileError> {
        let bytes = std::fs::read(path).map_err(|source| FileError::Read {
            path: path.to_path_buf(),
            source,
        })?;
        Ok(Self {
            len: bytes.len(),
            sha256: Sha256::digest(&bytes).into(),
        })
    }

    /// `None` when the program data holds fewer bytes than the binary.
    pub fn deployed_sha256<R: Rpc>(
        &self,
        rpc: &R,
        ring: CustomRing,
    ) -> Result<Option<[u8; 32]>, DeployError> {
        let address = ring.program_data_pda();
        let account = rpc
            .get_account(address)?
            .ok_or(DeployError::ProgramData { address })?;
        Ok(deployed_bytes(&account.data, self.len).map(|deployed| Sha256::digest(deployed).into()))
    }

    pub fn verify_deployed<R: Rpc>(&self, rpc: &R, ring: CustomRing) -> Result<(), DeployError> {
        let address = ring.program_data_pda();
        let found = self
            .deployed_sha256(rpc, ring)?
            .ok_or(DeployError::ProgramData { address })?;
        if found != self.sha256 {
            return Err(DeployError::DeployedMismatch {
                program: ring.program_id(),
                expected: hex::encode(self.sha256),
                found: hex::encode(found),
            });
        }
        Ok(())
    }
}

/// A first deploy pays rent for the program and its data account, an upgrade
/// only for the growth. Both pay for the write buffer, refunded when the
/// deploy finishes.
pub fn required_balance<R: Rpc>(
    rpc: &R,
    so_len: usize,
    deployed: Option<&ProgramDataInfo>,
) -> Result<u64, DeployError> {
    let rent = |bytes: usize| rpc.get_minimum_balance_for_rent_exemption(bytes);
    let mut lamports = DEPLOY_FEE_BUDGET + rent(UpgradeableLoaderState::size_of_buffer(so_len))?;
    match deployed {
        None => {
            lamports += rent(UpgradeableLoaderState::size_of_program())?;
            lamports += rent(UpgradeableLoaderState::size_of_programdata(so_len))?;
        }
        Some(info) if so_len > info.capacity => {
            let grown = (so_len - info.capacity).max(MIN_EXTEND_BYTES);
            lamports += rent(UpgradeableLoaderState::size_of_programdata(
                info.capacity + grown,
            ))?
            .saturating_sub(rent(UpgradeableLoaderState::size_of_programdata(
                info.capacity,
            ))?);
        }
        Some(_) => {}
    }
    Ok(lamports)
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
        slot,
        upgrade_authority_address,
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
        slot,
    }))
}

/// The loader refuses a program in the slot it was deployed in.
fn wait_until_usable<R: Rpc>(
    rpc: &R,
    program: Address,
    deployed_slot: u64,
) -> Result<(), DeployError> {
    let started = Instant::now();
    loop {
        if rpc.get_slot()? > deployed_slot {
            return Ok(());
        }
        if started.elapsed() > USABLE_TIMEOUT {
            return Err(DeployError::NotUsable {
                program,
                slot: deployed_slot,
            });
        }
        thread::sleep(SLOT_POLL);
    }
}

/// The loader writes the binary as given, padded to the account's capacity.
fn deployed_bytes(program_data: &[u8], so_len: usize) -> Option<&[u8]> {
    let start = UpgradeableLoaderState::size_of_programdata_metadata();
    program_data.get(start..start.checked_add(so_len)?)
}

fn released_program_so(tier: RingTier) -> Result<PathBuf, ReleaseError> {
    let program = RingProgram::from_lock_tier(tier)?;
    line(
        "release",
        format_args!("{} {}", program.tag, program.asset.name),
    );
    program.ensure()
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;

    use super::*;

    /// Rent as the cluster prices it, 3480 lamports per byte-year over two years.
    struct Rent;

    impl Rpc for Rent {
        fn get_minimum_balance_for_rent_exemption(
            &self,
            data_len: usize,
        ) -> Result<u64, ClientError> {
            Ok((128 + data_len as u64) * 3480 * 2)
        }
    }

    fn rent(data_len: usize) -> u64 {
        Rent.get_minimum_balance_for_rent_exemption(data_len)
            .expect("priced")
    }

    #[test]
    fn deployed_bytes_skip_the_metadata_and_stop_at_the_binary_length() {
        let meta = UpgradeableLoaderState::size_of_programdata_metadata();
        let mut data = vec![0u8; meta];
        data.extend_from_slice(b"elf");
        data.extend_from_slice(&[0u8; 8]);
        assert_eq!(deployed_bytes(&data, 3), Some(&b"elf"[..]));
        assert_eq!(deployed_bytes(&data, 3 + 8), Some(&data[meta..]));
        assert_eq!(deployed_bytes(&data, 3 + 9), None);
        assert_eq!(deployed_bytes(&data[..meta - 1], 0), None);
    }

    #[test]
    fn a_first_deploy_pays_program_data_and_buffer() {
        let so_len = 300_000;
        assert_eq!(
            required_balance(&Rent, so_len, None).expect("priced"),
            DEPLOY_FEE_BUDGET
                + rent(UpgradeableLoaderState::size_of_buffer(so_len))
                + rent(UpgradeableLoaderState::size_of_program())
                + rent(UpgradeableLoaderState::size_of_programdata(so_len))
        );
    }

    #[test]
    fn an_upgrade_pays_the_buffer_and_only_the_growth() {
        let deployed = ProgramDataInfo {
            upgrade_authority: None,
            capacity: 300_000,
            slot: 0,
        };
        let fits = required_balance(&Rent, deployed.capacity, Some(&deployed)).expect("priced");
        assert_eq!(
            fits,
            DEPLOY_FEE_BUDGET + rent(UpgradeableLoaderState::size_of_buffer(deployed.capacity))
        );
        // One byte too big still extends by the loader's minimum.
        let grows =
            required_balance(&Rent, deployed.capacity + 1, Some(&deployed)).expect("priced");
        assert_eq!(
            grows - fits,
            (rent(MIN_EXTEND_BYTES) - rent(0)) + (rent(1) - rent(0))
        );
    }

    #[test]
    fn a_deploy_is_usable_from_the_next_slot() {
        struct Advancing(Cell<u64>);
        impl Rpc for Advancing {
            fn get_slot(&self) -> Result<u64, ClientError> {
                let slot = self.0.get();
                self.0.set(slot + 1);
                Ok(slot)
            }
        }
        let rpc = Advancing(Cell::new(7));
        wait_until_usable(&rpc, Address::default(), 8).expect("usable");
        assert_eq!(rpc.0.get(), 10);
    }
}
