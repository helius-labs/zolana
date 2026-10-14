//! `spend`, the sender's spend record on a velocity ring.

use custom_ring_sdk::{
    compute_unit_limit, policy_config_table, CustomRing, InstructionTag, LiveSpendRecord,
    PolicyConfig, ReadSpendRecord, RegisterSpend, RingError,
};
use solana_signer::Signer;
use thiserror::Error;
use zolana_keypair::KeypairError;
use zolana_ring_policy::{Member, MemberError};

use crate::{
    error::boxed_from,
    file::FileError,
    line,
    step::{no_hint, IdempotentStep, Observed, StepError},
    transact::{sender_keypair_file, wait_for, Probe, WaitError, SENDER_FEE_BUDGET},
    ui::{self, Icon},
    Context, ContextError, SpendCommand, Zolana,
};

#[derive(Debug, Error)]
pub enum SpendError {
    #[error(transparent)]
    Context(#[from] ContextError),
    #[error(transparent)]
    Ring(Box<RingError>),
    #[error(transparent)]
    Member(#[from] MemberError),
    #[error(transparent)]
    Keypair(#[from] KeypairError),
    #[error(transparent)]
    Step(#[from] StepError),
    #[error(transparent)]
    File(#[from] FileError),
    #[error("timed out waiting for {label}")]
    Timeout {
        label: String,
        #[source]
        last: Option<Box<SpendError>>,
    },
    #[error("the ring has no policy config, run `zolana-ring init` first")]
    NoPolicy,
    #[error("the ring has no velocity window, nothing to register")]
    NotVelocity,
}

boxed_from!(SpendError { Ring(RingError) });

pub(crate) enum RegistrationOutcome {
    Registered,
    Present { version: u64 },
}

pub(crate) struct Registration<'a> {
    pub ring: CustomRing,
    pub sender: &'a dyn Signer,
    pub config: &'a PolicyConfig,
    pub zolana: &'a Zolana,
}

struct RecordQuery<'a> {
    ring: CustomRing,
    config: &'a PolicyConfig,
    member: Member,
}

pub fn run(ctx: &mut Context, command: SpendCommand) -> Result<(), SpendError> {
    let sender = sender_keypair_file(ctx)?;
    let config = windowed_config(ctx.ring, &ctx.rpc)?;
    let zolana = ctx.zolana();
    match command {
        SpendCommand::Register => {
            ctx.fund_authority(&sender, SENDER_FEE_BUDGET)?;
            let registration = Registration {
                ring: ctx.ring,
                sender: &sender,
                config: &config,
                zolana: &zolana,
            }
            .ensure()?;
            line("member", sender.pubkey());
            line("record", registration.label());
        }
        SpendCommand::Show => {
            let live = RecordQuery {
                ring: ctx.ring,
                config: &config,
                member: Member::owner_tag(sender.pubkey().as_array())?,
            }
            .read(&zolana)?;
            ui::heading(
                Icon::Policy,
                &format!("spend record of {}", sender.pubkey()),
            );
            match live {
                None => line("record", "not registered"),
                Some(live) => {
                    line("version", live.record.version);
                    line("window", live.record.window);
                    line("commitment", hex::encode(live.record.counters_commitment));
                }
            }
        }
    }
    Ok(())
}

impl RegistrationOutcome {
    pub(crate) fn label(&self) -> String {
        match self {
            Self::Registered => "registered".to_owned(),
            Self::Present { version } => format!("already registered at version {version}"),
        }
    }
}

impl Registration<'_> {
    /// The record is claimed once, an existing record is kept.
    pub(crate) fn ensure(self) -> Result<RegistrationOutcome, SpendError> {
        let member = self.sender.pubkey();
        let query = RecordQuery {
            ring: self.ring,
            config: self.config,
            member: Member::owner_tag(member.as_array())?,
        };
        let zolana = self.zolana;
        if let Some(live) = query.read(zolana)? {
            return Ok(RegistrationOutcome::Present {
                version: live.record.version,
            });
        }
        let registration = RegisterSpend {
            ring: self.ring,
            payer: member,
        };
        let proven = zolana.block_on(registration.prove(zolana.as_async()))?;
        IdempotentStep {
            rpc: zolana.rpc(),
            authority: self.sender,
            co_signers: &[],
            name: "register_spend",
            compute_unit_limit: compute_unit_limit(InstructionTag::RegisterSpend),
            hint: no_hint,
        }
        .ensure_present(Observed::Absent, &[proven.instruction()?])?;
        wait_for(format!("spend record of {member}"), || {
            query
                .read(zolana)
                .map(|record| record.map_or(Probe::NotYet, |_| Probe::Ready(())))
        })
        .map_err(timed_out)?;
        Ok(RegistrationOutcome::Registered)
    }
}

pub(crate) fn windowed_config(
    ring: CustomRing,
    rpc: &zolana_client::SolanaRpc,
) -> Result<PolicyConfig, SpendError> {
    let config = crate::read_account::<PolicyConfig>(rpc, ring, ring.policy_config_pda())?
        .ok_or(SpendError::NoPolicy)?;
    if policy_config_table(&config)?.window_slots() == 0 {
        return Err(SpendError::NotVelocity);
    }
    Ok(config)
}

impl RecordQuery<'_> {
    fn read(&self, zolana: &Zolana) -> Result<Option<LiveSpendRecord>, SpendError> {
        let read = ReadSpendRecord::new(self.ring, self.config.address_tree_id(), self.member);
        Ok(zolana.block_on(read.read_current(zolana.as_async()))?)
    }
}

fn timed_out<E: Into<SpendError> + std::error::Error + 'static>(error: WaitError<E>) -> SpendError {
    match error {
        WaitError::Failed(error) => error.into(),
        WaitError::Timeout { label, last } => SpendError::Timeout {
            label,
            last: last.map(|error| Box::new((*error).into())),
        },
    }
}
