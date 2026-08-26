use custom_ring_sdk::{
    read_record, AccountReadError, CreatePolicy, CreateRecord, CustomRing, LiveRecord,
    PolicySource, RecordError as SdkRecordError, RecordProofEnvironment, RecordProofError,
    SetPolicySource, UpdateRecord, CREATE_POLICY_COMPUTE_UNIT_LIMIT,
    RECORD_MUTATION_COMPUTE_UNIT_LIMIT, SET_POLICY_SOURCE_COMPUTE_UNIT_LIMIT,
};
use solana_address::Address;
use solana_signer::Signer;
use thiserror::Error;
use zolana_ring_policy::{Member, MemberError, RecordKind, RecordState};

use crate::{
    config::PolicyTable,
    line,
    step::{no_hint, IdempotentStep, Observed, StepError, StepOutcome},
    Context, ContextError, RecordCommand,
};

#[derive(Debug, Error)]
pub enum RecordError {
    #[error(transparent)]
    Context(#[from] ContextError),
    #[error(transparent)]
    AccountRead(#[from] AccountReadError),
    #[error(transparent)]
    Sdk(#[from] Box<SdkRecordError>),
    #[error(transparent)]
    Proof(#[from] Box<RecordProofError>),
    #[error(transparent)]
    Member(#[from] MemberError),
    #[error(transparent)]
    Step(#[from] StepError),
    #[error("the ring has no policy config, run `zolana-ring record init` first")]
    NoPolicy,
    #[error("{kind:?} record for {member} does not exist")]
    NoRecord { kind: RecordKind, member: Address },
    #[error("{kind:?} reads curator {curator} records, mutate it on the curator ring")]
    SharedKind { kind: RecordKind, curator: Address },
    #[error("ring.toml names an unknown source kind {name}")]
    UnknownSourceKind { name: String },
}

/// The `[policy.sources]` block as builder input.
pub fn shared_sources(
    policy: Option<&PolicyTable>,
) -> Result<Vec<(RecordKind, CustomRing)>, RecordError> {
    let Some(policy) = policy else {
        return Ok(Vec::new());
    };
    policy
        .sources
        .iter()
        .map(|(name, curator)| {
            let kind = match name.as_str() {
                "allow" => RecordKind::Allow,
                "block" => RecordKind::Block,
                "frozen" => RecordKind::Frozen,
                _ => return Err(RecordError::UnknownSourceKind { name: name.clone() }),
            };
            Ok((kind, CustomRing::new(curator.0)))
        })
        .collect()
}

impl From<SdkRecordError> for RecordError {
    fn from(error: SdkRecordError) -> Self {
        Self::Sdk(Box::new(error))
    }
}

impl From<RecordProofError> for RecordError {
    fn from(error: RecordProofError) -> Self {
        Self::Proof(Box::new(error))
    }
}

pub fn run(ctx: &mut Context, command: RecordCommand) -> Result<(), RecordError> {
    match command {
        RecordCommand::Init { records_tree } => init(ctx, records_tree),
        RecordCommand::Add { kind, member } => {
            mutate(ctx, kind.into(), member, RecordState::Active)
        }
        RecordCommand::Clear { kind, member } => {
            mutate(ctx, kind.into(), member, RecordState::Cleared)
        }
        RecordCommand::Show { kind, member } => show(ctx, kind.into(), member),
        RecordCommand::SetSource { kind, curator, own } => {
            let source = match (curator, own) {
                (Some(curator), false) => PolicySource::Shared(CustomRing::new(curator)),
                _ => PolicySource::Own,
            };
            set_source(ctx, kind.into(), source)
        }
    }
}

fn set_source(
    ctx: &mut Context,
    kind: RecordKind,
    source: PolicySource,
) -> Result<(), RecordError> {
    let authority = ctx.funded_authority()?;
    IdempotentStep {
        rpc: &ctx.rpc,
        authority: &authority,
        co_signers: &[],
        name: "set_policy_source",
        compute_unit_limit: SET_POLICY_SOURCE_COMPUTE_UNIT_LIMIT,
        hint: no_hint,
    }
    .ensure_present(
        Observed::Absent,
        &[SetPolicySource {
            ring: ctx.ring,
            authority: authority.pubkey(),
            kind,
            source,
        }
        .instruction()?],
    )?;
    let records = ctx
        .ring
        .read_policy_config(&ctx.rpc)?
        .ok_or(RecordError::NoPolicy)?
        .source_for(kind as u8)
        .ok_or(RecordError::NoPolicy)?;
    line("kind", format_args!("{kind:?}"));
    line("records", records);
    Ok(())
}

fn init(ctx: &mut Context, records_tree: Address) -> Result<(), RecordError> {
    let authority = ctx.funded_authority()?;
    let observed = Observed::of(&ctx.ring.read_policy_config(&ctx.rpc)?);
    let outcome = IdempotentStep {
        rpc: &ctx.rpc,
        authority: &authority,
        co_signers: &[],
        name: "create_policy",
        compute_unit_limit: CREATE_POLICY_COMPUTE_UNIT_LIMIT,
        hint: no_hint,
    }
    .ensure_present(
        observed,
        &[CreatePolicy {
            ring: ctx.ring,
            payer: authority.pubkey(),
            authority: authority.pubkey(),
            records_tree,
            shared_sources: shared_sources(ctx.config.policy.as_ref())?,
        }
        .instruction()?],
    )?;
    line("policy", outcome_label(outcome));
    line("records", ctx.ring.records_pda());
    line("tree", records_tree);
    Ok(())
}

fn mutate(
    ctx: &mut Context,
    kind: RecordKind,
    member: Address,
    state: RecordState,
) -> Result<(), RecordError> {
    let authority = ctx.funded_authority()?;
    let config = ctx
        .ring
        .read_policy_config(&ctx.rpc)?
        .ok_or(RecordError::NoPolicy)?;
    let records_tree = config.records_tree;
    // Mutations serve the ring's own records only, the program refuses the rest.
    if let Some(records) = config.source_for(kind as u8) {
        if records != ctx.ring.records_pda() {
            return Err(RecordError::SharedKind {
                kind,
                curator: records,
            });
        }
    }
    let member_field = Member::owner_tag(member.as_array())?;
    let indexer = ctx.indexer();
    let prover = ctx.prover();
    let environment = RecordProofEnvironment {
        indexer: &indexer,
        rpc: &ctx.rpc,
        prover: &prover,
    };

    let live = read_record(&indexer, ctx.ring.records_pda(), kind, &member_field)?;
    line("record", format_args!("{kind:?} {member}"));
    let proven = match live {
        None => {
            line("action", format_args!("claiming at state {state:?}"));
            CreateRecord {
                ring: ctx.ring,
                payer: authority.pubkey(),
                records_tree,
                kind,
                member: member_field,
                state,
                payload_hash: [0u8; 32],
            }
            .prove(environment)?
        }
        Some(LiveRecord { record, .. }) if record.state == state => {
            line("action", format_args!("already {state:?}"));
            return Ok(());
        }
        Some(LiveRecord { record, .. }) => {
            line("action", format_args!("moving to {state:?}"));
            UpdateRecord {
                ring: ctx.ring,
                payer: authority.pubkey(),
                records_tree,
                spent: record,
                state,
                payload_hash: [0u8; 32],
            }
            .prove(environment)?
        }
    };
    let version = proven.record().version;
    IdempotentStep {
        rpc: &ctx.rpc,
        authority: &authority,
        co_signers: &[],
        name: "record_mutation",
        compute_unit_limit: RECORD_MUTATION_COMPUTE_UNIT_LIMIT,
        hint: no_hint,
    }
    .ensure_present(Observed::Absent, &[proven.instruction()?])?;
    line("version", version);
    Ok(())
}

fn show(ctx: &mut Context, kind: RecordKind, member: Address) -> Result<(), RecordError> {
    let member_field = Member::owner_tag(member.as_array())?;
    let records = ctx
        .ring
        .read_policy_config(&ctx.rpc)?
        .ok_or(RecordError::NoPolicy)?
        .source_for(kind as u8)
        .unwrap_or_else(|| ctx.ring.records_pda());
    let indexer = ctx.indexer();
    let live = read_record(&indexer, records, kind, &member_field)?
        .ok_or(RecordError::NoRecord { kind, member })?;
    line("record", format_args!("{kind:?} {member}"));
    line("state", format_args!("{:?}", live.record.state));
    line("version", live.record.version);
    Ok(())
}

fn outcome_label(outcome: StepOutcome) -> &'static str {
    match outcome {
        StepOutcome::Created => "created",
        StepOutcome::Present => "already created",
        StepOutcome::Closed => "closed",
        StepOutcome::Absent => "absent",
    }
}
