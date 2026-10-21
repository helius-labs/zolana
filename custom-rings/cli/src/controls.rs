//! The ring's operating controls, each read back from the chain after a change.

use std::path::Path;

use anyhow::{bail, ensure, Context as _, Result};
use custom_ring_sdk::{
    CoSignThreshold, CustomRingCoSigner, CustomRingConfig, RingMode, RingRegistration,
};
use solana_signer::Signer;
use zolana_keypair::X25519Keypair;

use crate::{
    config::{Base58Address, CoSignClass, CoSignerSpec, Mint},
    fund::MIN_AUTHORITY_BALANCE,
    keys, line, policy,
    records::NO_MEMBER_REGISTRY,
    ui::{self, icon},
    CoSignerCommand, Context, DelegateCommand, InsertFeeCommand, ReaderCommand, AUDITOR_KEY_FILE,
};

#[must_use]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Setup {
    NoConfig,
    AuditOnly,
    PolicyUnpinned,
    PolicyPinned,
}

pub fn cosigner(ctx: &Context, command: CoSignerCommand) -> Result<()> {
    match command {
        CoSignerCommand::Set {
            signer,
            scope,
            threshold,
        } => {
            let spec = match signer {
                Some(signer) => CoSignerSpec {
                    key: Base58Address(signer),
                    scope,
                    thresholds: threshold,
                },
                None => ctx
                    .config
                    .cosigner
                    .clone()
                    .context("no signer given and ring.toml has no [cosigner] table")?,
            };
            let (authority, scope) = (ctx.funded_authority()?, spec.scope());
            let scope = scope.context("the co-signer gates no operation class")?;
            let thresholds: Vec<_> = (spec.thresholds.iter())
                .map(|row| CoSignThreshold {
                    mint: row.mint.0,
                    amount: row.above,
                })
                .collect();
            let set = ctx
                .ring
                .set_cosigner(authority.pubkey(), spec.key.0, scope, &thresholds)?;
            ctx.send(&[authority], &[set])?;
            line("co-signer", format_args!("{} set", spec.key));
        }
        CoSignerCommand::Clear => {
            let authority = ctx.funded_authority()?;
            ensure!(
                ctx.ring_config()?.co_signer.is_some(),
                "the ring has no co-signer"
            );
            ctx.send(&[authority], &[ctx.ring.clear_cosigner(authority.pubkey())])?;
            line("co-signer", "cleared");
        }
        CoSignerCommand::Show => {}
    }
    match ctx.ring_config()?.co_signer {
        Some(cosigner) => print_cosigner(&cosigner),
        None => line("co-signer", "none"),
    }
    Ok(())
}

pub(crate) fn print_cosigner(cosigner: &CustomRingCoSigner) {
    let scope: Vec<_> = CoSignClass::ALL
        .into_iter()
        .filter(|class| cosigner.scope.contains(class.scope()))
        .map(CoSignClass::as_str)
        .collect();
    line("co-signer", cosigner.signer);
    line("scope", scope.join(","));
    for threshold in &cosigner.thresholds {
        line(
            "threshold",
            format_args!("{} above {}", Mint(threshold.mint), threshold.amount),
        );
    }
}

pub fn insert_fee(ctx: &Context, command: InsertFeeCommand) -> Result<()> {
    if let InsertFeeCommand::Set { lamports } = command {
        let authority = ctx.funded_authority()?;
        let set = ctx.ring.set_insert_fee(authority.pubkey(), lamports);
        ctx.send(&[authority], &[set])?;
    }
    print_insert_fee(&ctx.ring_config()?);
    Ok(())
}

pub(crate) fn print_insert_fee(config: &CustomRingConfig) {
    line(
        "insert fee",
        format_args!("{} lamports per member write", config.insert_fee),
    );
}

/// A grant of a granted reader and a revoke of an absent one send nothing.
pub fn reader(ctx: &Context, command: ReaderCommand) -> Result<()> {
    let authority = ctx.funded_authority()?;
    let a = authority.pubkey();
    let (ReaderCommand::Grant { reader } | ReaderCommand::Revoke { reader }) = command;
    let granted = ctx.block(ctx.ring.access_record(ctx.chain(), &reader))?;
    let outcome = match (command, granted.is_some()) {
        (ReaderCommand::Grant { .. }, true) => "already granted",
        (ReaderCommand::Grant { .. }, false) => {
            ctx.send(&[authority], &[ctx.ring.grant_read_access(a, a, reader)?])?;
            "granted"
        }
        (ReaderCommand::Revoke { .. }, true) => {
            ctx.send(&[authority], &[ctx.ring.revoke_read_access(a, reader, a)?])?;
            "revoked"
        }
        (ReaderCommand::Revoke { .. }, false) => "not granted",
    };
    line("reader", format_args!("{reader} {outcome}"));
    line("record", ctx.ring.read_access_record_pda(&reader));
    Ok(())
}

pub fn pause(ctx: &Context, paused: bool) -> Result<()> {
    let registration = require_initialized(ctx)?;
    let authority = ctx.authority()?;
    let outcome = match (registration.paused == paused, paused) {
        (true, true) => "already paused",
        (true, false) => "already open",
        (false, _) => {
            let set = ctx.ring.set_paused(authority.pubkey(), paused)?;
            ctx.send(&[authority], &[set])?;
            ["resumed", "paused"][usize::from(paused)]
        }
    };
    line("spp ring", outcome);
    let program = ctx.ring.program_id();
    match paused {
        true => ui::heading(
            icon::PAUSE,
            &format!("ring {program} refuses every operation"),
        ),
        false => ui::heading(icon::RESUME, &format!("ring {program} is open")),
    }
    Ok(())
}

pub fn delegate(ctx: &Context, command: DelegateCommand) -> Result<()> {
    match command {
        DelegateCommand::Set { delegate } => {
            let config = ctx.ring_config()?;
            if let Some(current) = config.delegate {
                bail!("the ring's delegate {current} is permanent");
            }
            ensure!(
                config.has_policy && config.mode != RingMode::Anonymous,
                "a delegate escrows keys only on a confidential policy ring"
            );
            ring_auditor_key(ctx, Path::new(AUDITOR_KEY_FILE))?;
            ctx.block(ctx.ring.registry(ctx.chain()))?
                .context(NO_MEMBER_REGISTRY)?;
            let authority = ctx.config.upgrade_authority()?;
            ctx.fund(authority.pubkey(), MIN_AUTHORITY_BALANCE)?;
            ctx.send(
                &[&authority],
                &[ctx.ring.set_delegate(authority.pubkey(), delegate)],
            )?;
            line("delegate", format_args!("{delegate} set"));
            ui::warn("every later transfer escrows its output keys");
        }
        DelegateCommand::Show => {}
        DelegateCommand::Move(args) => return crate::delegate::run_move(ctx, *args),
    }
    match ctx.ring_config()?.delegate {
        Some(delegate) => line("delegate", delegate),
        None => line("delegate", "none"),
    }
    Ok(())
}

/// The auditor read key opens recovery material, it cannot authorize a transfer.
pub(crate) fn ring_auditor_key(ctx: &Context, path: &Path) -> Result<X25519Keypair> {
    let config = ctx.ring_config()?;
    let path = ctx.path(path);
    let auditor = keys::read(&path)?;
    ensure!(
        auditor.pubkey() == config.auditor_pubkey,
        "{} does not hold the ring auditor read key {}",
        path.display(),
        hex::encode(config.auditor_pubkey.as_bytes())
    );
    Ok(auditor)
}

pub(crate) fn require_initialized(ctx: &Context) -> Result<RingRegistration> {
    let setup = match ctx.block(ctx.ring.config(ctx.chain()))? {
        None => Setup::NoConfig,
        Some(config) if !config.has_policy => Setup::AuditOnly,
        Some(_) => match policy::pinned_if_any(ctx)? {
            Some(_) => Setup::PolicyPinned,
            None => Setup::PolicyUnpinned,
        },
    };
    let registration = ctx.block(ctx.ring.registration(ctx.chain()))?;
    registration.filter(|_| setup.complete()).with_context(|| {
        format!(
            "ring {} is not initialized, run `init` first",
            ctx.ring.program_id()
        )
    })
}

impl Setup {
    #[must_use]
    const fn complete(self) -> bool {
        matches!(self, Self::AuditOnly | Self::PolicyPinned)
    }
}

#[cfg(test)]
mod tests {
    use custom_ring_sdk::CoSignScope;

    use super::*;

    #[test]
    fn setup_completes_with_the_policy_only_on_a_policy_ring() {
        assert!(Setup::AuditOnly.complete());
        assert!(Setup::PolicyPinned.complete());
        assert!(!Setup::PolicyUnpinned.complete());
        assert!(!Setup::NoConfig.complete());
    }

    #[test]
    fn a_spec_scope_unions_its_classes() {
        let spec = CoSignerSpec {
            key: Base58Address(solana_address::Address::default()),
            scope: vec![CoSignClass::Deposits, CoSignClass::Withdrawals],
            thresholds: Vec::new(),
        };
        assert_eq!(
            spec.scope(),
            Some(CoSignScope::DEPOSITS | CoSignScope::WITHDRAWALS)
        );
        let empty = CoSignerSpec {
            scope: Vec::new(),
            ..spec
        };
        assert_eq!(empty.scope(), None);
    }
}
