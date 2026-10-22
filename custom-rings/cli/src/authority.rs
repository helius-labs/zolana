//! `authority`, the program's upgrade authority and the ring config's authority.

use std::path::PathBuf;

use anyhow::{anyhow, Context as _, Result};
use custom_ring_sdk::SetAuthority;
use solana_address::Address;
use solana_loader_v3_interface::instruction as loader;
use solana_signer::Signer;

use crate::{
    config::expand_tilde,
    controls::{self, require_initialized},
    deploy::{self, ProgramBinary},
    release::RingProgram,
    AuthorityCommand, Context,
};

pub fn run(ctx: &Context, command: AuthorityCommand) -> Result<()> {
    let program = ctx.ring.program_id();
    let declined = format!("{program} keeps its upgrade authority, the change was not confirmed");
    match command {
        AuthorityCommand::Transfer { new_authority, yes } => {
            let target = ctx.config.target;
            ctx.confirm(
                yes,
                &format!("hand {program} on {target} to {new_authority}? only that key can hand it back"),
                format!("pass --yes to hand {program} on {target} to {new_authority}, only that key can hand it back"),
                declined,
            )?;
            require_initialized(ctx)?;
            set_upgrade_authority(ctx, Some(new_authority))?;
            println!(
                "upgrade authority of {program} is now {new_authority}, set upgrade_authority_keypair in {}",
                ctx.config_path.display()
            );
        }
        AuthorityCommand::TransferConfig {
            new_authority_keypair,
        } => {
            let authority = ctx.authority()?;
            let path = expand_tilde(&ctx.path(&new_authority_keypair))?;
            let new_authority = solana_keypair::read_keypair_file(&path)
                .map_err(|_| anyhow!("cannot read the new authority keypair {}", path.display()))?;
            let hand_over = SetAuthority {
                ring: ctx.ring,
                authority: authority.pubkey(),
                new_authority: new_authority.pubkey(),
            }
            .instruction();
            ctx.send(&[authority, &new_authority], &[hand_over])
                .context("sending set_authority failed")?;
            println!(
                "ring config authority of {program} is now {}, set config_authority_keypair in {} to {}",
                new_authority.pubkey(),
                ctx.config_path.display(),
                new_authority_keypair.display()
            );
        }
        AuthorityCommand::Pause => controls::pause(ctx, true)?,
        AuthorityCommand::Resume => controls::pause(ctx, false)?,
        AuthorityCommand::Renounce { yes, program_so } => {
            ctx.confirm(
                yes,
                &format!("make {program} immutable? nothing can upgrade it again"),
                format!("renouncing is irreversible, pass --yes to make {program} immutable"),
                declined,
            )?;
            require_initialized(ctx)?;
            expected_binary(ctx, program_so)?.verify_deployed(ctx)?;
            set_upgrade_authority(ctx, None)?;
            println!("{program} is immutable");
        }
    }
    Ok(())
}

/// The release lock pins the binary unless the operator names one.
fn expected_binary(ctx: &Context, program_so: Option<PathBuf>) -> Result<ProgramBinary> {
    if let Some(path) = program_so {
        return ProgramBinary::read(&ctx.path(&path));
    }
    let asset = RingProgram::from_lock()?.asset;
    let sha256 = hex::decode(&asset.sha256)
        .ok()
        .and_then(|bytes| bytes.try_into().ok())
        .with_context(|| format!("release lock sha256 {} is not hex", asset.sha256))?;
    Ok(ProgramBinary {
        len: asset.size as usize,
        sha256,
    })
}

/// `None` renounces, the program stays as deployed for good.
fn set_upgrade_authority(ctx: &Context, new_authority: Option<Address>) -> Result<()> {
    let authority = ctx.config.upgrade_authority()?;
    let program = ctx.ring.program_id();
    let current = deploy::program_data(ctx)?.with_context(|| {
        format!("program {program} is not deployed under the upgradeable loader")
    })?;
    deploy::check_upgrade_authority(program, &current, authority.pubkey())?;
    let instruction =
        loader::set_upgrade_authority(&program, &authority.pubkey(), new_authority.as_ref());
    ctx.send(&[&authority], &[instruction])?;
    Ok(())
}
