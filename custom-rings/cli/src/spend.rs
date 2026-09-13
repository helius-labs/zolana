//! `spend`, the sender's spend record on a velocity ring.

use custom_ring_sdk::{
    policy_config_table, AccountReadError, CustomRing, EntryError, EntryProofError,
    LiveSpendRecord, PolicyMatchError, ReadSpendRecord, RegisterSpend, SpendProofEnvironment,
    REGISTER_SPEND_COMPUTE_UNIT_LIMIT,
};
use solana_signer::Signer;
use thiserror::Error;
use zolana_client::{ClientError, ProverClient, SolanaRpc, ZolanaIndexer};
use zolana_keypair::KeypairError;
use zolana_ring_policy::{Member, MemberError};

use crate::{
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
    Indexer(#[from] WaitError<ClientError>),
    #[error(transparent)]
    File(#[from] FileError),
    #[error("the ring has no policy config, run `zolana-ring init` first")]
    NoPolicy,
    #[error("the ring has no velocity window, nothing to register")]
    NotVelocity,
    #[error("the ring has no head map, its authority must run `zolana-ring init` first")]
    MissingHeadMap,
}

impl From<PolicyMatchError> for SpendError {
    fn from(error: PolicyMatchError) -> Self {
        Self::PolicyMatch(Box::new(error))
    }
}

impl From<EntryProofError> for SpendError {
    fn from(error: EntryProofError) -> Self {
        Self::Proof(Box::new(error))
    }
}

impl From<EntryError> for SpendError {
    fn from(error: EntryError) -> Self {
        Self::Build(Box::new(error))
    }
}

pub fn run(ctx: &mut Context, command: SpendCommand) -> Result<(), SpendError> {
    let sender = sender_keypair_file(ctx)?;
    match command {
        SpendCommand::Register => {
            ctx.fund_authority(&sender, SENDER_FEE_BUDGET)?;
            let registration = Registration {
                ring: ctx.ring,
                sender: &sender,
                rpc: &ctx.rpc,
                indexer: &ctx.indexer(),
                prover: &ctx.prover(),
            }
            .ensure()?;
            line("member", sender.pubkey());
            line("record", registration.label());
        }
        SpendCommand::Show => {
            let live = read_record(ctx.ring, &ctx.rpc, &ctx.indexer(), &sender.pubkey())?;
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

pub enum RegistrationOutcome {
    Registered,
    Present { version: u64 },
}

impl RegistrationOutcome {
    pub(crate) fn label(&self) -> String {
        match self {
            Self::Registered => "registered".to_owned(),
            Self::Present { version } => format!("already registered at version {version}"),
        }
    }
}

/// A member's record, registered by the sender itself when absent.
pub(crate) struct Registration<'a> {
    pub ring: CustomRing,
    pub sender: &'a dyn Signer,
    pub rpc: &'a SolanaRpc,
    pub indexer: &'a ZolanaIndexer,
    pub prover: &'a ProverClient,
}

impl Registration<'_> {
    pub(crate) fn ensure(self) -> Result<RegistrationOutcome, SpendError> {
        if self.ring.read_head_map_root(self.rpc)?.is_none() {
            return Err(SpendError::MissingHeadMap);
        }
        let member = self.sender.pubkey();
        if let Some(live) = read_record(self.ring, self.rpc, self.indexer, &member)? {
            return Ok(RegistrationOutcome::Present {
                version: live.record.version,
            });
        }
        let proven = RegisterSpend {
            ring: self.ring,
            payer: member,
        }
        .prove(SpendProofEnvironment {
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
        // The transfer discovers the record through the indexer.
        wait_for(format!("spend record of {member}"), || {
            Ok(
                match read_record(self.ring, self.rpc, self.indexer, &member) {
                    Ok(Some(_)) => Probe::Ready(()),
                    Ok(None) => Probe::NotYet,
                    Err(error) => return Err(error),
                },
            )
        })
        .map_err(|error| match error {
            WaitError::Failed(error) => error,
            WaitError::Timeout { label, .. } => {
                SpendError::Indexer(WaitError::Timeout { label, last: None })
            }
        })?;
        Ok(RegistrationOutcome::Registered)
    }
}

fn read_record(
    ring: CustomRing,
    rpc: &SolanaRpc,
    indexer: &ZolanaIndexer,
    member: &solana_address::Address,
) -> Result<Option<LiveSpendRecord>, SpendError> {
    let config = ring.read_policy_config(rpc)?.ok_or(SpendError::NoPolicy)?;
    if policy_config_table(&config)?.window_slots() == 0 {
        return Err(SpendError::NotVelocity);
    }
    let member = Member::owner_tag(member.as_array())?;
    wait_for(
        "current compressed spend record".to_owned(),
        || match (ReadSpendRecord {
            entries_tree: config.entries_tree,
            entries_tree_id: config.entries_tree_id(),
            namespace: ring.namespace_pda(),
            member,
        })
        .read_current(ring, indexer, rpc)
        {
            Ok(record) => Ok(Probe::Ready(record)),
            Err(error) if is_head_map_retryable(&error) => Ok(Probe::Retry(error)),
            Err(error) => Err(error),
        },
    )
    .map_err(|error| match error {
        WaitError::Failed(error) => error.into(),
        WaitError::Timeout { label, .. } => {
            SpendError::Indexer(WaitError::Timeout { label, last: None })
        }
    })
}

fn is_head_map_retryable(error: &EntryProofError) -> bool {
    matches!(error, EntryProofError::Client(error) if matches!(
        error.as_ref(), ClientError::RingHeadMapOutOfSync | ClientError::RingHeadRootChanged
    ))
}
