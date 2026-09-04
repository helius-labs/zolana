use std::{fmt, str::FromStr};

use clap::Args;
use custom_ring_sdk::{
    AccountReadError, CreateEntry, CustomRing, EntryError as SdkEntryError, EntryProofEnvironment,
    EntryProofError, LiveEntry, ReadEntry, SetSourceOwner, SourceOwner, UpdateEntry,
    ENTRY_MUTATION_COMPUTE_UNIT_LIMIT, SET_POLICY_SOURCE_COMPUTE_UNIT_LIMIT,
};
use solana_address::{error::ParseAddressError, Address};
use solana_signer::Signer;
use thiserror::Error;
use zolana_client::{SolanaRpc, ZolanaIndexer};
use zolana_ring_policy::{EntryState, ListId, Member, MemberError};
use zolana_transaction::SOL_MINT;

use crate::{
    catalogue::{Catalogue, CatalogueError, CuratorCheck, CuratorError},
    line,
    policy::list_name,
    step::{no_hint, IdempotentStep, Observed, StepError},
    ui::{self, Icon},
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
    #[error("pass --owner or --asset")]
    MemberFlag,
    #[error(transparent)]
    Step(#[from] StepError),
    #[error(transparent)]
    Catalogue(#[from] Box<CatalogueError>),
    #[error(transparent)]
    Curator(#[from] CuratorError),
    #[error("the ring has no policy config, run `zolana-ring init` first")]
    NoPolicy,
    #[error("{} entry for {member} does not exist", list_name(*list_id))]
    NoEntry { list_id: ListId, member: MemberKind },
    #[error("the {} list reads curator {curator} entries, mutate it on the curator ring", list_name(*list_id))]
    SharedList { list_id: ListId, curator: Address },
}

#[derive(Debug, Clone, Copy, Args)]
#[group(required = true, multiple = false)]
pub struct MemberArg {
    /// The member's owner tag, base58.
    #[arg(long, value_name = "TAG")]
    owner: Option<Address>,
    /// A mint, base58, or `sol` for the native token.
    #[arg(long, value_name = "MINT")]
    asset: Option<Mint>,
}

#[derive(Debug, Clone, Copy)]
pub struct Mint(Address);

#[derive(Debug, Clone, Copy)]
pub enum MemberKind {
    Owner(Address),
    Asset(Mint),
}

const SOL: &str = "sol";

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

impl From<CatalogueError> for ListError {
    fn from(error: CatalogueError) -> Self {
        Self::Catalogue(Box::new(error))
    }
}

pub fn run(ctx: &mut Context, command: ListCommand) -> Result<(), ListError> {
    match command {
        ListCommand::Add { list_id, member } => EntryArg {
            list_id: list_id.id(),
            member: member.try_into()?,
        }
        .set(ctx, EntryState::Active),
        ListCommand::Clear { list_id, member } => EntryArg {
            list_id: list_id.id(),
            member: member.try_into()?,
        }
        .set(ctx, EntryState::Cleared),
        ListCommand::Show { list_id, member } => EntryArg {
            list_id: list_id.id(),
            member: member.try_into()?,
        }
        .show(ctx),
        ListCommand::SetSource {
            list_id,
            curator,
            own,
        } => {
            let source = match (curator, own) {
                (Some(curator), false) => SourceOwner::Shared(
                    Catalogue::load(ctx.catalogue.as_deref())?
                        .resolve(ctx.config.target, &curator)?,
                ),
                _ => SourceOwner::Own,
            };
            set_source(ctx, list_id.id(), source)
        }
    }
}

impl TryFrom<MemberArg> for MemberKind {
    type Error = ListError;

    fn try_from(arg: MemberArg) -> Result<Self, ListError> {
        match (arg.owner, arg.asset) {
            (Some(tag), None) => Ok(Self::Owner(tag)),
            (None, Some(mint)) => Ok(Self::Asset(mint)),
            _ => Err(ListError::MemberFlag),
        }
    }
}

impl MemberKind {
    pub fn member(&self) -> Result<Member, MemberError> {
        match self {
            Self::Owner(tag) => Member::owner_tag(tag.as_array()),
            Self::Asset(Mint(mint)) => Member::asset(mint),
        }
    }
}

impl fmt::Display for MemberKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Owner(tag) => write!(f, "owner {tag}"),
            Self::Asset(mint) => write!(f, "asset {mint}"),
        }
    }
}

impl FromStr for Mint {
    type Err = ParseAddressError;

    fn from_str(text: &str) -> Result<Self, ParseAddressError> {
        if text == SOL {
            return Ok(Self(SOL_MINT));
        }
        text.parse().map(Self)
    }
}

impl fmt::Display for Mint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.0 == SOL_MINT {
            f.write_str(SOL)
        } else {
            fmt::Display::fmt(&self.0, f)
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
    member: MemberKind,
}

impl EntryArg {
    fn set(self, ctx: &mut Context, state: EntryState) -> Result<(), ListError> {
        let authority = ctx.funded_authority()?;
        let indexer = ctx.indexer();
        let prover = ctx.prover();
        line(
            "entry",
            format_args!("{} {}", list_name(self.list_id), self.member),
        );
        let outcome = EntryMutation {
            ring: ctx.ring,
            authority: &authority,
            list_id: self.list_id,
            member: self.member.member()?,
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
            member: self.member.member()?,
        }
        .read(&ctx.indexer())?
        .ok_or(ListError::NoEntry {
            list_id: self.list_id,
            member: self.member,
        })?;
        line(
            "entry",
            format_args!("{} {}", list_name(self.list_id), self.member),
        );
        line("state", format_args!("{:?}", live.entry.state));
        line("version", live.entry.version);
        Ok(())
    }
}

fn set_source(ctx: &mut Context, list_id: ListId, source: SourceOwner) -> Result<(), ListError> {
    let config = ctx
        .ring
        .read_policy_config(&ctx.rpc)?
        .ok_or(ListError::NoPolicy)?;
    let expected = match source {
        SourceOwner::Own => ctx.ring.namespace_pda(),
        SourceOwner::Shared(curator) => {
            CuratorCheck {
                curator,
                list: list_id,
                entries_tree: config.entries_tree,
            }
            .run(&ctx.rpc)?;
            curator.namespace_pda()
        }
    };
    let observed = if config.source_for(list_id) == Some(expected) {
        Observed::Present
    } else {
        Observed::Absent
    };
    let authority = ctx.funded_authority()?;
    let outcome = IdempotentStep {
        rpc: &ctx.rpc,
        authority: &authority,
        co_signers: &[],
        name: "set_policy_source",
        compute_unit_limit: SET_POLICY_SOURCE_COMPUTE_UNIT_LIMIT,
        hint: no_hint,
    }
    .ensure_present(
        observed,
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
    match source {
        SourceOwner::Own => ui::heading(
            Icon::Lists,
            &format!("the {} list reads its own entries", list_name(list_id)),
        ),
        SourceOwner::Shared(curator) => ui::heading(
            Icon::Curator,
            &format!(
                "the {} list reads curator {}",
                list_name(list_id),
                curator.program_id()
            ),
        ),
    }
    line("source", outcome.label());
    line("entries", entries);
    Ok(())
}

#[cfg(test)]
mod tests {
    use clap::{error::ErrorKind, Parser};

    use super::*;
    use crate::{Cli, Command, ListCommand};

    const TAG: &str = "9vyTbYGyh3cwxkAQpjjFQGXmdJP6p9B6YcQ5pNuXPNbh";
    const MINT: &str = "So11111111111111111111111111111111111111112";

    fn parse(verb: &str, flags: &[&str]) -> Result<MemberKind, clap::Error> {
        let argv = ["zolana-ring", "list", verb, "block"]
            .into_iter()
            .chain(flags.iter().copied());
        let Command::List(command) = Cli::try_parse_from(argv)?.command else {
            panic!("a list command");
        };
        let member = match command {
            ListCommand::Add { member, .. }
            | ListCommand::Clear { member, .. }
            | ListCommand::Show { member, .. } => member,
            ListCommand::SetSource { .. } => panic!("an entry command"),
        };
        Ok(MemberKind::try_from(member).expect("one flag"))
    }

    #[test]
    fn every_entry_command_takes_an_owner_tag_or_a_mint() {
        let tag = Member::owner_tag(Address::from_str_const(TAG).as_array()).expect("member");
        let mint = Member::asset(&Address::from_str_const(MINT)).expect("member");
        for verb in ["add", "clear", "show"] {
            let owner = parse(verb, &["--owner", TAG]).expect(verb);
            assert_eq!(owner.member().expect("member"), tag);
            assert_eq!(owner.to_string(), format!("owner {TAG}"));
            let asset = parse(verb, &["--asset", MINT]).expect(verb);
            assert_eq!(asset.member().expect("member"), mint);
            assert_eq!(asset.to_string(), format!("asset {MINT}"));
        }
    }

    #[test]
    fn sol_names_the_native_token() {
        let sol = Member::asset(&SOL_MINT).expect("member");
        let literal = parse("add", &["--asset", "sol"]).expect("sol");
        assert_eq!(literal.member().expect("member"), sol);
        assert_eq!(literal.to_string(), "asset sol");
        let zero = parse("add", &["--asset", &SOL_MINT.to_string()]).expect("zero mint");
        assert_eq!(zero.member().expect("member"), sol);
        assert_eq!(zero.to_string(), "asset sol");
        assert_eq!(
            parse("add", &["--asset", "SOL"])
                .expect_err("lowercase only")
                .kind(),
            ErrorKind::ValueValidation
        );
    }

    #[test]
    fn exactly_one_member_flag_is_taken() {
        assert_eq!(
            parse("add", &[]).expect_err("no flag").kind(),
            ErrorKind::MissingRequiredArgument
        );
        assert_eq!(
            parse("add", &["--owner", TAG, "--asset", MINT])
                .expect_err("both flags")
                .kind(),
            ErrorKind::ArgumentConflict
        );
    }
}
