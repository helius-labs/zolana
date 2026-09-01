use custom_ring_sdk::{
    read_entry, AccountReadError, CreateEntry, CreatePolicy, CustomRing,
    EntryError as SdkEntryError, EntryProofEnvironment, EntryProofError, LiveEntry, SetSourceOwner,
    SourceOwner, UpdateEntry, CREATE_POLICY_COMPUTE_UNIT_LIMIT, ENTRY_MUTATION_COMPUTE_UNIT_LIMIT,
    SET_POLICY_SOURCE_COMPUTE_UNIT_LIMIT,
};
use solana_address::Address;
use solana_signer::Signer;
use thiserror::Error;
use zolana_ring_policy::{EntryState, ListId, Member, MemberError};

use crate::{
    config::PolicyTable,
    line,
    step::{no_hint, IdempotentStep, Observed, StepError, StepOutcome},
    Context, ContextError, ListCommand,
};

#[derive(Debug, Error)]
pub enum ListError {
    #[error(transparent)]
    Context(#[from] ContextError),
    #[error(transparent)]
    AccountRead(#[from] AccountReadError),
    #[error(transparent)]
    Sdk(#[from] Box<SdkEntryError>),
    #[error(transparent)]
    Proof(#[from] Box<EntryProofError>),
    #[error(transparent)]
    Member(#[from] MemberError),
    #[error(transparent)]
    Step(#[from] StepError),
    #[error("the ring has no policy config, run `zolana-ring list init` first")]
    NoPolicy,
    #[error("{list_id:?} entry for {member} does not exist")]
    NoEntry { list_id: ListId, member: Address },
    #[error("{list_id:?} reads curator {curator} entries, mutate it on the curator ring")]
    SharedList { list_id: ListId, curator: Address },
    #[error("ring.toml names an unknown source list {name}")]
    UnknownSourceList { name: String },
}

/// The `[policy.sources]` block as builder input.
pub fn shared_sources(
    policy: Option<&PolicyTable>,
) -> Result<Vec<(ListId, CustomRing)>, ListError> {
    let Some(policy) = policy else {
        return Ok(Vec::new());
    };
    policy
        .sources
        .iter()
        .map(|(name, curator)| {
            let list_id = match name.as_str() {
                "allow" => ListId::Allow,
                "block" => ListId::Block,
                "frozen" => ListId::Frozen,
                _ => return Err(ListError::UnknownSourceList { name: name.clone() }),
            };
            Ok((list_id, CustomRing::new(curator.0)))
        })
        .collect()
}

impl From<SdkEntryError> for ListError {
    fn from(error: SdkEntryError) -> Self {
        Self::Sdk(Box::new(error))
    }
}

impl From<EntryProofError> for ListError {
    fn from(error: EntryProofError) -> Self {
        Self::Proof(Box::new(error))
    }
}

pub fn run(ctx: &mut Context, command: ListCommand) -> Result<(), ListError> {
    match command {
        ListCommand::Init { entries_tree } => init(ctx, entries_tree),
        ListCommand::Add { list_id, member } => {
            mutate(ctx, list_id.into(), member, EntryState::Active)
        }
        ListCommand::Clear { list_id, member } => {
            mutate(ctx, list_id.into(), member, EntryState::Cleared)
        }
        ListCommand::Show { list_id, member } => show(ctx, list_id.into(), member),
        ListCommand::SetSource {
            list_id,
            curator,
            own,
        } => {
            let source = match (curator, own) {
                (Some(curator), false) => SourceOwner::Shared(CustomRing::new(curator)),
                _ => SourceOwner::Own,
            };
            set_source(ctx, list_id.into(), source)
        }
    }
}

fn set_source(ctx: &mut Context, list_id: ListId, source: SourceOwner) -> Result<(), ListError> {
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
        &[SetSourceOwner {
            ring: ctx.ring,
            authority: authority.pubkey(),
            list_id,
            source,
        }
        .instruction()?],
    )?;
    let entries = ctx
        .ring
        .read_policy_config(&ctx.rpc)?
        .ok_or(ListError::NoPolicy)?
        .source_for(list_id as u8)
        .ok_or(ListError::NoPolicy)?;
    line("list_id", format_args!("{list_id:?}"));
    line("entries", entries);
    Ok(())
}

fn init(ctx: &mut Context, entries_tree: Address) -> Result<(), ListError> {
    let payer = ctx.funded_authority()?;
    // create_policy is gated on the upgrade authority, not the config authority.
    let upgrade_authority = ctx.config.upgrade_authority().map_err(ContextError::from)?;
    let co_signers: [&dyn Signer; 1] = [&upgrade_authority];
    let observed = Observed::of(&ctx.ring.read_policy_config(&ctx.rpc)?);
    let outcome = IdempotentStep {
        rpc: &ctx.rpc,
        authority: &payer,
        co_signers: &co_signers,
        name: "create_policy",
        compute_unit_limit: CREATE_POLICY_COMPUTE_UNIT_LIMIT,
        hint: no_hint,
    }
    .ensure_present(
        observed,
        &[CreatePolicy {
            ring: ctx.ring,
            payer: payer.pubkey(),
            authority: upgrade_authority.pubkey(),
            entries_tree,
            shared_sources: shared_sources(ctx.config.policy.as_ref())?,
        }
        .instruction()?],
    )?;
    line("policy", outcome_label(outcome));
    line("entries", ctx.ring.namespace_pda());
    line("tree", entries_tree);
    Ok(())
}

fn mutate(
    ctx: &mut Context,
    list_id: ListId,
    member: Address,
    state: EntryState,
) -> Result<(), ListError> {
    let authority = ctx.funded_authority()?;
    let config = ctx
        .ring
        .read_policy_config(&ctx.rpc)?
        .ok_or(ListError::NoPolicy)?;
    let entries_tree = config.entries_tree;
    // Mutations serve the ring's own entries only, the program refuses the rest.
    if let Some(entries) = config.source_for(list_id as u8) {
        if entries != ctx.ring.namespace_pda() {
            return Err(ListError::SharedList {
                list_id,
                curator: entries,
            });
        }
    }
    let member_field = Member::owner_tag(member.as_array())?;
    let indexer = ctx.indexer();
    let prover = ctx.prover();
    let environment = EntryProofEnvironment {
        indexer: &indexer,
        rpc: &ctx.rpc,
        prover: &prover,
    };

    let live = read_entry(&indexer, ctx.ring.namespace_pda(), list_id, &member_field)?;
    line("entry", format_args!("{list_id:?} {member}"));
    let proven = match live {
        None => {
            line("action", format_args!("claiming at state {state:?}"));
            CreateEntry {
                ring: ctx.ring,
                payer: authority.pubkey(),
                entries_tree,
                list_id,
                member: member_field,
                state,
                content_hash: [0u8; 32],
            }
            .prove(environment)?
        }
        Some(LiveEntry { entry, .. }) if entry.state == state => {
            line("action", format_args!("already {state:?}"));
            return Ok(());
        }
        Some(LiveEntry { entry, .. }) => {
            line("action", format_args!("moving to {state:?}"));
            UpdateEntry {
                ring: ctx.ring,
                payer: authority.pubkey(),
                entries_tree,
                spent: entry,
                state,
                content_hash: [0u8; 32],
            }
            .prove(environment)?
        }
    };
    let version = proven.entry().version;
    IdempotentStep {
        rpc: &ctx.rpc,
        authority: &authority,
        co_signers: &[],
        name: "entry_mutation",
        compute_unit_limit: ENTRY_MUTATION_COMPUTE_UNIT_LIMIT,
        hint: no_hint,
    }
    .ensure_present(Observed::Absent, &[proven.instruction()?])?;
    line("version", version);
    Ok(())
}

fn show(ctx: &mut Context, list_id: ListId, member: Address) -> Result<(), ListError> {
    let member_field = Member::owner_tag(member.as_array())?;
    let entries = ctx
        .ring
        .read_policy_config(&ctx.rpc)?
        .ok_or(ListError::NoPolicy)?
        .source_for(list_id as u8)
        .unwrap_or_else(|| ctx.ring.namespace_pda());
    let indexer = ctx.indexer();
    let live = read_entry(&indexer, entries, list_id, &member_field)?
        .ok_or(ListError::NoEntry { list_id, member })?;
    line("entry", format_args!("{list_id:?} {member}"));
    line("state", format_args!("{:?}", live.entry.state));
    line("version", live.entry.version);
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
