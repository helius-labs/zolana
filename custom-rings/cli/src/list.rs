use custom_ring_interface::RULES;
use custom_ring_sdk::{
    AccountReadError, CreateEntry, CreatePolicy, CustomRing, EntryError as SdkEntryError,
    EntryProofEnvironment, EntryProofError, LiveEntry, ReadEntry, SetSourceOwner, SourceOwner,
    UpdateEntry, CREATE_POLICY_COMPUTE_UNIT_LIMIT, ENTRY_MUTATION_COMPUTE_UNIT_LIMIT,
    SET_POLICY_SOURCE_COMPUTE_UNIT_LIMIT,
};
use solana_address::Address;
use solana_signer::Signer;
use thiserror::Error;
use zolana_client::{SolanaRpc, ZolanaIndexer};
use zolana_ring_policy::{EntryState, ListId, Member, MemberError};

use crate::{
    config::PolicyTable,
    line,
    step::{no_hint, IdempotentStep, Observed, StepError, StepOutcome},
    Context, ContextError, ListCommand, ListIdArg,
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

#[must_use]
pub struct EntryMutation<'a> {
    pub ring: CustomRing,
    pub authority: &'a dyn Signer,
    pub list_id: ListId,
    pub member: Member,
    pub state: EntryState,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[must_use]
pub struct EntryOutcome {
    pub version: u64,
    pub change: EntryChange,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntryChange {
    Unchanged,
    Claimed,
    Moved,
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
            let list_id = <ListIdArg as clap::ValueEnum>::from_str(name, true)
                .map_err(|_| ListError::UnknownSourceList { name: name.clone() })?;
            Ok((list_id.into(), CustomRing::new(curator.0)))
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
        ListCommand::Add { list_id, member } => EntryArg {
            list_id: list_id.into(),
            member,
        }
        .set(ctx, EntryState::Active),
        ListCommand::Clear { list_id, member } => EntryArg {
            list_id: list_id.into(),
            member,
        }
        .set(ctx, EntryState::Cleared),
        ListCommand::Show { list_id, member } => EntryArg {
            list_id: list_id.into(),
            member,
        }
        .show(ctx),
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

impl EntryMutation<'_> {
    pub fn apply(
        self,
        environment: EntryProofEnvironment<'_, ZolanaIndexer, SolanaRpc>,
    ) -> Result<EntryOutcome, ListError> {
        let rpc = environment.rpc;
        let config = self
            .ring
            .read_policy_config(rpc)?
            .ok_or(ListError::NoPolicy)?;
        // Mutations serve the ring's own entries only, the program refuses the rest.
        if let Some(curator) = config
            .source_for(self.list_id)
            .filter(|entries| *entries != self.ring.namespace_pda())
        {
            return Err(ListError::SharedList {
                list_id: self.list_id,
                curator,
            });
        }
        let live = ReadEntry {
            entries_tree: config.entries_tree,
            namespace: self.ring.namespace_pda(),
            list_id: self.list_id,
            member: self.member,
        }
        .read(environment.indexer)?;
        let proven = match live {
            None => CreateEntry {
                ring: self.ring,
                payer: self.authority.pubkey(),
                entries_tree: config.entries_tree,
                list_id: self.list_id,
                member: self.member,
                state: self.state,
                content_hash: [0u8; 32],
            }
            .prove(environment)?,
            Some(LiveEntry { entry, .. }) if entry.state == self.state => {
                return Ok(EntryOutcome {
                    version: entry.version,
                    change: EntryChange::Unchanged,
                });
            }
            Some(LiveEntry { entry, .. }) => UpdateEntry {
                ring: self.ring,
                payer: self.authority.pubkey(),
                entries_tree: config.entries_tree,
                spent: entry,
                state: self.state,
                content_hash: [0u8; 32],
            }
            .prove(environment)?,
        };
        let version = proven.entry().version;
        IdempotentStep {
            rpc,
            authority: self.authority,
            co_signers: &[],
            name: "entry_mutation",
            compute_unit_limit: ENTRY_MUTATION_COMPUTE_UNIT_LIMIT,
            hint: no_hint,
        }
        .ensure_present(Observed::Absent, &[proven.instruction()?])?;
        Ok(EntryOutcome {
            version,
            change: match live {
                None => EntryChange::Claimed,
                Some(_) => EntryChange::Moved,
            },
        })
    }
}

impl EntryChange {
    pub fn label(self) -> &'static str {
        match self {
            Self::Unchanged => "already there",
            Self::Claimed => "claimed",
            Self::Moved => "moved",
        }
    }
}

struct EntryArg {
    list_id: ListId,
    member: Address,
}

impl EntryArg {
    fn member(&self) -> Result<Member, MemberError> {
        Member::owner_tag(self.member.as_array())
    }

    fn set(self, ctx: &mut Context, state: EntryState) -> Result<(), ListError> {
        let authority = ctx.funded_authority()?;
        let indexer = ctx.indexer();
        let prover = ctx.prover();
        line("entry", format_args!("{:?} {}", self.list_id, self.member));
        let outcome = EntryMutation {
            ring: ctx.ring,
            authority: &authority,
            list_id: self.list_id,
            member: self.member()?,
            state,
        }
        .apply(EntryProofEnvironment {
            indexer: &indexer,
            rpc: &ctx.rpc,
            prover: &prover,
        })?;
        line(
            "state",
            format_args!("{state:?} {}", outcome.change.label()),
        );
        line("version", outcome.version);
        Ok(())
    }

    fn show(self, ctx: &Context) -> Result<(), ListError> {
        let config = ctx
            .ring
            .read_policy_config(&ctx.rpc)?
            .ok_or(ListError::NoPolicy)?;
        let live = ReadEntry {
            entries_tree: config.entries_tree,
            namespace: config
                .source_for(self.list_id)
                .unwrap_or_else(|| ctx.ring.namespace_pda()),
            list_id: self.list_id,
            member: self.member()?,
        }
        .read(&ctx.indexer())?
        .ok_or(ListError::NoEntry {
            list_id: self.list_id,
            member: self.member,
        })?;
        line("entry", format_args!("{:?} {}", self.list_id, self.member));
        line("state", format_args!("{:?}", live.entry.state));
        line("version", live.entry.version);
        Ok(())
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
        .source_for(list_id)
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
            rules: &RULES,
            shared_sources: shared_sources(ctx.config.policy.as_ref())?,
        }
        .instruction()?],
    )?;
    line("policy", outcome_label(outcome));
    line("entries", ctx.ring.namespace_pda());
    line("tree", entries_tree);
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

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use crate::config::Base58Address;

    use super::*;

    fn sources(names: &[&str]) -> Result<Vec<ListId>, ListError> {
        let curator = Base58Address(Address::new_from_array([1; 32]));
        let policy = PolicyTable {
            sources: names
                .iter()
                .map(|name| ((*name).to_owned(), curator))
                .collect::<BTreeMap<_, _>>(),
        };
        Ok(shared_sources(Some(&policy))?
            .into_iter()
            .map(|(list_id, _)| list_id)
            .collect())
    }

    #[test]
    fn source_names_are_the_cli_list_arms_in_any_case() {
        assert_eq!(
            sources(&["allow", "block", "frozen"]).expect("known lists"),
            vec![ListId::Allow, ListId::Block, ListId::Frozen]
        );
        assert_eq!(
            sources(&["Block"]).expect("case-insensitive name"),
            vec![ListId::Block]
        );
        assert!(matches!(
            sources(&["reader"]),
            Err(ListError::UnknownSourceList { name }) if name == "reader"
        ));
        assert!(shared_sources(None).expect("no policy").is_empty());
    }
}
