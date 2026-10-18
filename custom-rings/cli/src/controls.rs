//! The ring's operating controls, each read back from the chain after a change.

use std::path::Path;

use anyhow::{bail, ensure, Context as _, Result};
use custom_ring_sdk::{CoSignThreshold, CustomRingCoSigner};
use solana_signer::Signer;
use zolana_interface::state::RingConfig as SppRingConfig;
use zolana_keypair::X25519Secret;

use crate::{
    config::{Base58Address, CoSignClass, CoSignerSpec, Mint, RingConfig},
    fund::MIN_AUTHORITY_BALANCE,
    keys, line,
    ui::{self, icon},
    CoSignerCommand, Context, DelegateCommand, DepositAuditCommand, ReaderCommand,
    AUDITOR_KEY_FILE,
};

pub const NO_MEMBER_REGISTRY: &str =
    "the ring has no member registry, its authority must run `zolana-ring init` first";

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
            let a = authority.pubkey();
            let set = ctx
                .ring
                .set_cosigner(a, a, spec.key.0, scope, &thresholds)?;
            ctx.send(&[authority], &[set])?;
            line("co-signer", format_args!("{} set", spec.key));
        }
        CoSignerCommand::Clear => {
            let authority = ctx.funded_authority()?;
            let set = ctx.block(ctx.ring.cosigner(ctx.chain()))?.is_some();
            ensure!(set, "the ring has no co-signer");
            let a = authority.pubkey();
            ctx.send(&[authority], &[ctx.ring.clear_cosigner(a, a)])?;
            line("co-signer", "cleared");
        }
        CoSignerCommand::Show => {}
    }
    match ctx.block(ctx.ring.cosigner(ctx.chain()))? {
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

pub fn deposit_audit(ctx: &Context, command: DepositAuditCommand) -> Result<()> {
    let required = match command {
        DepositAuditCommand::Set { required } => {
            let authority = ctx.funded_authority()?;
            let a = authority.pubkey();
            ctx.send(&[authority], &[ctx.ring.set_deposit_audit(a, a, required)?])?;
            RingConfig::set_deposit_audit(&ctx.config_path, required)?;
            required
        }
        DepositAuditCommand::Show => ctx.block(ctx.ring.deposit_audit(ctx.chain()))?,
    };
    line(
        "legacy deposit flag",
        crate::status::stored_audit_flag(required),
    );
    line("deposit audit", "required");
    Ok(())
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
    let spp_ring = require_initialized(ctx)?;
    let authority = ctx.authority()?;
    let outcome = match (spp_ring.is_paused() == paused, paused) {
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
            let config = ctx
                .block(ctx.ring.config(ctx.chain()))?
                .context("the ring has no config, run `zolana-ring init` first")?;
            ensure!(
                config.has_policy,
                "the ring has no policy, a delegate escrows keys only on a policy ring"
            );
            ring_auditor_key(ctx, Path::new(AUDITOR_KEY_FILE))?;
            ctx.block(ctx.ring.member_registry_root(ctx.chain()))?
                .context(NO_MEMBER_REGISTRY)?;
            let authority = ctx.config.upgrade_authority()?;
            let a = authority.pubkey();
            ctx.fund(a, MIN_AUTHORITY_BALANCE)?;
            ctx.send(&[&authority], &[ctx.ring.set_delegate(a, a, delegate)])?;
            line("delegate", format_args!("{delegate} set"));
        }
        DelegateCommand::Show => {}
        DelegateCommand::Move(args) => return crate::delegate::run_move(ctx, *args),
    }
    match ctx.block(ctx.ring.delegate(ctx.chain()))? {
        Some(delegate) => line("delegate", delegate),
        None => line("delegate", "none"),
    }
    Ok(())
}

/// The auditor read key opens recovery material, it cannot authorize a transfer.
pub(crate) fn ring_auditor_key(ctx: &Context, path: &Path) -> Result<X25519Secret> {
    let config = ctx
        .block(ctx.ring.config(ctx.chain()))?
        .context("the ring has no config, run `zolana-ring init` first")?;
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

/// A policy ring counts once its policy is pinned, an audit-only ring pins none.
pub(crate) fn require_initialized(ctx: &Context) -> Result<SppRingConfig> {
    let config = ctx.block(ctx.ring.config(ctx.chain()))?;
    let has_policy = config.as_ref().is_some_and(|config| config.has_policy);
    let pinned = has_policy && ctx.block(ctx.ring.policy_config(ctx.chain()))?.is_some();
    let spp_ring = ctx.block(ctx.ring.spp_ring_config(ctx.chain()))?;
    match initialized(config.is_some(), has_policy, pinned, spp_ring) {
        Some(spp_ring) => Ok(spp_ring),
        None => bail!(
            "ring {} is not initialized, run `init` before renouncing",
            ctx.ring.program_id()
        ),
    }
}

fn initialized<R>(config: bool, has_policy: bool, pinned: bool, spp_ring: Option<R>) -> Option<R> {
    spp_ring.filter(|_| config && (!has_policy || pinned))
}

#[cfg(test)]
mod tests {
    use custom_ring_sdk::CoSignScope;

    use super::*;

    #[test]
    fn renounce_requires_the_policy_only_for_a_policy_ring() {
        for (config, pinned, spp_ring) in [
            (false, false, None),
            (true, false, None),
            (false, false, Some(())),
            (true, false, Some(())),
        ] {
            assert_eq!(initialized(config, true, pinned, spp_ring), None);
        }
        assert_eq!(initialized(true, true, true, Some(())), Some(()));
        assert_eq!(initialized(true, false, false, Some(())), Some(()));
        assert_eq!(initialized(true, false, false, None::<()>), None);
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
