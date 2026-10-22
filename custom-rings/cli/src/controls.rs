//! The ring's operating controls, each read back from the chain after a change.

use std::path::Path;

use anyhow::{bail, ensure, Context as _, Result};
use custom_ring_sdk::{
    CoSignScope, CoSignThreshold, CustomRingCoSigner, CustomRingConfig, GrantReader, RevokeReader,
    RingMode, RingRegistration, SetCoSigner, SetDelegate,
};
use solana_address::Address;
use solana_signer::Signer;
use zolana_client::Rpc;
use zolana_keypair::X25519Keypair;

use crate::{
    config::{Base58Address, CoSignClass, CoSignerSpec, Mint},
    file,
    fund::MIN_AUTHORITY_BALANCE,
    keys, line, policy,
    records::NO_MEMBER_REGISTRY,
    ui::{self, icon},
    CoSignerCommand, Context, DelegateCommand, InsertFeeCommand, ReaderCommand, AUDITOR_KEY_FILE,
};

#[must_use]
pub(crate) struct DualControl {
    pub cosigner: Option<Address>,
    pub delegate: Option<Address>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct RentFloor(u64);

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
            let scope = spec
                .scope()
                .context("the co-signer gates no operation class")?;
            let thresholds: Vec<_> = (spec.thresholds.iter())
                .map(|row| CoSignThreshold {
                    mint: row.mint.0,
                    amount: row.above,
                })
                .collect();
            check_thresholds(scope, &thresholds)?;
            DualControl {
                cosigner: Some(spec.key.0),
                delegate: ctx.ring_config()?.delegate,
            }
            .check()?;
            let authority = ctx.funded_authority()?;
            let set = SetCoSigner {
                ring: ctx.ring,
                authority: authority.pubkey(),
                signer: spec.key.0,
                scope,
                thresholds: &thresholds,
            }
            .instruction()?;
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
        RentFloor(ctx.rpc().get_minimum_balance_for_rent_exemption(0)?).admits(lamports)?;
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
            let grant = GrantReader {
                ring: ctx.ring,
                payer: a,
                authority: a,
                reader,
            };
            ctx.send(&[authority], &[grant.instruction()?])?;
            "granted"
        }
        (ReaderCommand::Revoke { .. }, true) => {
            let revoke = RevokeReader {
                ring: ctx.ring,
                authority: a,
                reader,
                rent_recipient: a,
            };
            ctx.send(&[authority], &[revoke.instruction()?])?;
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
            let set = match paused {
                true => ctx.ring.pause(authority.pubkey())?,
                false => ctx.ring.resume(authority.pubkey())?,
            };
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
        DelegateCommand::Set { delegate_keypair } => {
            let delegate = file::read_keypair(&ctx.path(&delegate_keypair))?;
            let config = ctx.ring_config()?;
            if let Some(current) = config.delegate {
                bail!("the ring's delegate {current} is permanent");
            }
            DualControl {
                cosigner: config.co_signer.as_ref().map(|cosigner| cosigner.signer),
                delegate: Some(delegate.pubkey()),
            }
            .check()?;
            ensure!(
                config.has_policy && config.mode != RingMode::Anonymous,
                "a delegate escrows keys only on a confidential policy ring"
            );
            ring_auditor_key(ctx, Path::new(AUDITOR_KEY_FILE))?;
            ctx.block(ctx.ring.registry(ctx.chain()))?
                .context(NO_MEMBER_REGISTRY)?;
            let authority = ctx.config.upgrade_authority()?;
            ctx.fund(authority.pubkey(), MIN_AUTHORITY_BALANCE)?;
            let set = SetDelegate {
                ring: ctx.ring,
                authority: authority.pubkey(),
                delegate: delegate.pubkey(),
            };
            ctx.send(&[&authority, &delegate], &[set.instruction()])?;
            line("delegate", format_args!("{} set", delegate.pubkey()));
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

impl DualControl {
    pub(crate) fn check(self) -> Result<()> {
        if let (Some(cosigner), Some(delegate)) = (self.cosigner, self.delegate) {
            ensure!(
                cosigner != delegate,
                "{delegate} is the ring's delegate, dual control needs a co-signer other than it"
            );
        }
        Ok(())
    }
}

impl RentFloor {
    fn admits(self, fee: u64) -> Result<()> {
        let RentFloor(floor) = self;
        ensure!(
            fee == 0 || fee >= floor,
            "an insert fee of {fee} lamports is below the {floor} an empty account needs, set 0 or at least {floor}"
        );
        Ok(())
    }
}

fn check_thresholds(scope: CoSignScope, thresholds: &[CoSignThreshold]) -> Result<()> {
    ensure!(
        thresholds.is_empty() || scope.contains(CoSignScope::WITHDRAWALS),
        "co-signer thresholds bound withdrawals, add the withdrawals class to the scope"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_nonzero_insert_fee_below_the_rent_floor_is_refused() {
        let floor = RentFloor(890_880);
        assert!(floor.admits(0).is_ok());
        assert!(floor.admits(890_880).is_ok());
        let refused = floor.admits(890_879).unwrap_err().to_string();
        assert!(refused.contains("890880"), "{refused}");
    }

    #[test]
    fn co_signer_thresholds_need_the_withdrawal_scope() {
        let row = [CoSignThreshold {
            mint: Address::default(),
            amount: 5,
        }];
        assert!(check_thresholds(CoSignScope::TRANSFERS, &row).is_err());
        let withdrawals = CoSignScope::TRANSFERS | CoSignScope::WITHDRAWALS;
        assert!(check_thresholds(withdrawals, &row).is_ok());
        assert!(check_thresholds(CoSignScope::TRANSFERS, &[]).is_ok());
    }

    #[test]
    fn the_delegate_never_co_signs_its_own_moves() {
        let (key, other) = (
            Address::new_from_array([1; 32]),
            Address::new_from_array([2; 32]),
        );
        let control = |cosigner, delegate| DualControl { cosigner, delegate }.check();
        assert!(control(Some(key), Some(key)).is_err());
        assert!(control(Some(key), Some(other)).is_ok());
        assert!(control(None, Some(key)).is_ok());
        assert!(control(Some(key), None).is_ok());
    }

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
