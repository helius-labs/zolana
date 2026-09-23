//! `spend`, the sender's spend record on a velocity ring.

use custom_ring_sdk::{
    policy_config_table, AccountReadError, CustomRing, EntryError, EntryProofError,
    LiveSpendRecord, PolicyConfig, PolicyMatchError, ReadEnvironment, ReadSpendRecord,
    RegisterSpend, TransferProofEnvironment, REGISTER_SPEND_COMPUTE_UNIT_LIMIT,
};
use solana_signer::Signer;
use thiserror::Error;
use zolana_client::{ClientError, ProverClient, SolanaRpc, ZolanaIndexer};
use zolana_keypair::KeypairError;
use zolana_ring_policy::{Member, MemberError};

use crate::{
    error::boxed_from,
    file::FileError,
    line,
    step::{no_hint, IdempotentStep, Observed, StepError},
    transact::{sender_keypair_file, wait_for, Probe, WaitError, SENDER_FEE_BUDGET},
    ui::{self, Icon},
    Context, ContextError, SpendCommand,
};

#[derive(Debug, Error)]
pub enum SpendError {
    #[error(transparent)]
    Context(#[from] ContextError),
    #[error(transparent)]
    AccountRead(#[from] AccountReadError),
    #[error(transparent)]
    PolicyMatch(Box<PolicyMatchError>),
    #[error(transparent)]
    Member(#[from] MemberError),
    #[error(transparent)]
    Keypair(#[from] KeypairError),
    #[error(transparent)]
    Proof(Box<EntryProofError>),
    #[error(transparent)]
    Build(Box<EntryError>),
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

boxed_from!(SpendError {
    PolicyMatch(PolicyMatchError),
    Proof(EntryProofError),
    Build(EntryError),
});

pub(crate) enum RegistrationOutcome {
    Registered,
    Present { version: u64 },
}

pub(crate) struct Registration<'a> {
    pub ring: CustomRing,
    pub sender: &'a dyn Signer,
    pub config: &'a PolicyConfig,
    pub rpc: &'a SolanaRpc,
    pub indexer: &'a ZolanaIndexer,
    pub prover: &'a ProverClient,
}

struct RecordQuery<'a> {
    ring: CustomRing,
    config: &'a PolicyConfig,
    member: Member,
}

pub fn run(ctx: &mut Context, command: SpendCommand) -> Result<(), SpendError> {
    let sender = sender_keypair_file(ctx)?;
    let config = windowed_config(ctx.ring, &ctx.rpc)?;
    match command {
        SpendCommand::Register => {
            ctx.fund_authority(&sender, SENDER_FEE_BUDGET)?;
            let registration = Registration {
                ring: ctx.ring,
                sender: &sender,
                config: &config,
                rpc: &ctx.rpc,
                indexer: &ctx.indexer(),
                prover: &ctx.prover(),
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
            .read(ReadEnvironment {
                indexer: &ctx.indexer(),
                rpc: &ctx.rpc,
            })?;
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
        let env = ReadEnvironment {
            indexer: self.indexer,
            rpc: self.rpc,
        };
        if let Some(live) = query.read(env)? {
            return Ok(RegistrationOutcome::Present {
                version: live.record.version,
            });
        }
        let proven = RegisterSpend {
            ring: self.ring,
            payer: member,
        }
        .prove(TransferProofEnvironment {
            indexer: self.indexer,
            rpc: self.rpc,
            prover: self.prover,
        })?;
        IdempotentStep {
            rpc: self.rpc,
            authority: self.sender,
            co_signers: &[],
            name: "register_spend",
            compute_unit_limit: REGISTER_SPEND_COMPUTE_UNIT_LIMIT,
            hint: no_hint,
        }
        .ensure_present(Observed::Absent, &[proven.instruction()?])?;
        wait_for(format!("spend record of {member}"), || {
            query
                .read(env)
                .map(|record| record.map_or(Probe::NotYet, |_| Probe::Ready(())))
        })
        .map_err(timed_out)?;
        Ok(RegistrationOutcome::Registered)
    }
}

pub(crate) fn windowed_config(
    ring: CustomRing,
    rpc: &SolanaRpc,
) -> Result<PolicyConfig, SpendError> {
    let config = ring.read_policy_config(rpc)?.ok_or(SpendError::NoPolicy)?;
    if policy_config_table(&config)?.window_slots() == 0 {
        return Err(SpendError::NotVelocity);
    }
    Ok(config)
}

impl RecordQuery<'_> {
    fn read(
        &self,
        env: ReadEnvironment<'_, ZolanaIndexer, SolanaRpc>,
    ) -> Result<Option<LiveSpendRecord>, SpendError> {
        wait_for(
            format!("spend record projection of {:?}", self.member),
            || {
                let read = ReadSpendRecord {
                    ring: self.ring,
                    address_tree_id: self.config.address_tree_id(),
                    member: self.member,
                };
                match read.read_current(env) {
                    Ok(live) => Ok(Probe::Ready(live)),
                    Err(EntryProofError::Client(error))
                        if matches!(*error, ClientError::RingSpendRecordOutOfSync) =>
                    {
                        Ok(Probe::Retry(EntryProofError::Client(error)))
                    }
                    Err(error) => Err(error),
                }
            },
        )
        .map_err(timed_out)
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
