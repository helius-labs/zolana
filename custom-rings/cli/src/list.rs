//! `list`, the entries of the ring's policy lists and where each list reads them.

use anyhow::{bail, Context as _, Result};
use clap::Args;
use custom_ring_sdk::{
    CreateEntry, LiveEntry, PolicyConfig, PoolTree, ReadEntry, SourceOwner, UpdateEntry,
};
use solana_address::Address;
use solana_keypair::Keypair;
use solana_signer::Signer;
use zolana_client::{IndexerRpcConfig, Rpc};
use zolana_ring_policy::{EntryState, ListId, Member};

use crate::{
    catalogue::{check_curator, Catalogue},
    config::Mint,
    line,
    ui::{self, icon},
    Context, EntryArgs, ListCommand,
};

const NO_POLICY: &str = "the ring has no policy config, run `zolana-ring init` first";

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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EntryOutcome {
    pub version: u64,
    /// `already there`, `claimed` or `moved`.
    pub change: &'static str,
}

impl MemberArg {
    pub fn member(&self) -> Result<(Member, String)> {
        Ok(match (self.owner, self.asset) {
            (Some(tag), None) => (Member::owner_tag(tag.as_array())?, format!("owner {tag}")),
            (None, Some(mint)) => (Member::asset(&mint.0)?, format!("asset {mint}")),
            _ => bail!("pass --owner or --asset"),
        })
    }
}

pub fn run(ctx: &Context, command: ListCommand) -> Result<()> {
    match command {
        ListCommand::Add(entry) => set(ctx, entry, EntryState::Active),
        ListCommand::Clear(entry) => set(ctx, entry, EntryState::Cleared),
        ListCommand::Show(EntryArgs { list_id, member }) => show(ctx, list_id.id(), member),
        ListCommand::SetSource {
            list_id,
            curator,
            own,
        } => {
            let source = match curator.filter(|_| !own) {
                Some(curator) => SourceOwner::Shared(
                    Catalogue::load(ctx.catalogue.as_deref())?
                        .resolve(ctx.config.target, &curator)?,
                ),
                None => SourceOwner::Own,
            };
            set_source(ctx, list_id.id(), source)
        }
    }
}

fn set(ctx: &Context, entry: EntryArgs, state: EntryState) -> Result<()> {
    let (member, label) = entry.member.member()?;
    let authority = ctx.funded_authority()?;
    line("entry", format_args!("{} {label}", entry.list_id));
    let outcome = set_entry(ctx, authority, entry.list_id.id(), member, state)?;
    line("state", format_args!("{state:?} {}", outcome.change));
    line("version", outcome.version);
    Ok(())
}

/// Writes the ring's own entries only, the program refuses a list a curator serves.
pub(crate) fn set_entry(
    ctx: &Context,
    authority: &Keypair,
    list_id: ListId,
    member: Member,
    state: EntryState,
) -> Result<EntryOutcome> {
    let (config, own) = (policy_config(ctx)?, ctx.ring.namespace_pda());
    if let Some(curator) = config.source_for(list_id).filter(|entries| *entries != own) {
        bail!(
            "the {} list reads curator {curator} entries, mutate it on the curator ring",
            list_id.name()
        );
    }
    let tree = PoolTree::address_tree(&config);
    // An indexer behind the last update would read back the state before it.
    let live = ReadEntry::new(tree.id, own, list_id, member)
        .with_indexer_config(IndexerRpcConfig::at_slot(ctx.rpc().get_slot()?));
    let live = ctx.block(live.read(ctx.chain()))?;
    let (proven, change) = match live {
        Some(LiveEntry { entry, .. }) if entry.state == state => {
            return Ok(EntryOutcome {
                version: entry.version,
                change: "already there",
            })
        }
        None => {
            let create = CreateEntry {
                ring: ctx.ring,
                payer: authority.pubkey(),
                address_tree: tree,
                output_tree: tree,
                list_id,
                member,
                state,
                content_hash: [0; 32],
            };
            (ctx.block(create.prove(ctx.chain()))?, "claimed")
        }
        Some(spent) => {
            let update = UpdateEntry {
                ring: ctx.ring,
                payer: authority.pubkey(),
                address_tree: tree,
                output_tree: tree,
                spent,
                state,
                content_hash: [0; 32],
            };
            (ctx.block(update.prove(ctx.chain()))?, "moved")
        }
    };
    let version = proven.entry().version;
    ctx.send(&[authority], &[proven.instruction()?])?;
    Ok(EntryOutcome { version, change })
}

fn show(ctx: &Context, list_id: ListId, member: MemberArg) -> Result<()> {
    let config = policy_config(ctx)?;
    let (member, label) = member.member()?;
    let namespace = config
        .source_for(list_id)
        .unwrap_or_else(|| ctx.ring.namespace_pda());
    let live = ReadEntry::new(config.address_tree_id(), namespace, list_id, member)
        .with_indexer_config(IndexerRpcConfig::at_slot(ctx.rpc().get_slot()?));
    let live = ctx
        .block(live.read(ctx.chain()))?
        .with_context(|| format!("{} entry for {label} does not exist", list_id.name()))?;
    line("entry", format_args!("{} {label}", list_id.name()));
    line("state", format_args!("{:?}", live.entry.state));
    line("version", live.entry.version);
    Ok(())
}

fn policy_config(ctx: &Context) -> Result<PolicyConfig> {
    ctx.block(ctx.ring.policy_config(ctx.chain()))?
        .context(NO_POLICY)
}

fn set_source(ctx: &Context, list_id: ListId, source: SourceOwner) -> Result<()> {
    let config = policy_config(ctx)?;
    let expected = match source {
        SourceOwner::Own => ctx.ring.namespace_pda(),
        SourceOwner::Shared(curator) => {
            check_curator(ctx, curator, list_id, config.address_tree)?;
            curator.namespace_pda()
        }
    };
    let authority = ctx.funded_authority()?;
    let outcome = if config.source_for(list_id) == Some(expected) {
        "already present"
    } else {
        let point = ctx
            .ring
            .set_source_owner(authority.pubkey(), list_id, source)?;
        ctx.send(&[authority], &[point])?;
        "created"
    };
    let entries = policy_config(ctx)?.source_for(list_id).context(NO_POLICY)?;
    let (glyph, reads) = match source {
        SourceOwner::Own => (icon::LISTS, "its own entries".to_owned()),
        SourceOwner::Shared(curator) => {
            (icon::CURATOR, format!("curator {}", curator.program_id()))
        }
    };
    ui::heading(glyph, &format!("the {} list reads {reads}", list_id.name()));
    line("source", outcome);
    line("entries", entries);
    Ok(())
}

#[cfg(test)]
mod tests {
    use clap::{error::ErrorKind, Parser};
    use zolana_transaction::SOL_MINT;

    use super::*;
    use crate::{Cli, Command, ListCommand};

    const TAG: &str = "9vyTbYGyh3cwxkAQpjjFQGXmdJP6p9B6YcQ5pNuXPNbh";
    const MINT: &str = "So11111111111111111111111111111111111111112";

    fn parse(verb: &str, flags: &[&str]) -> Result<(Member, String), clap::Error> {
        let argv = ["zolana-ring", "list", verb, "block"]
            .into_iter()
            .chain(flags.iter().copied());
        let Command::List(command) = Cli::try_parse_from(argv)?.command else {
            panic!("a list command");
        };
        let member = match command {
            ListCommand::Add(entry) | ListCommand::Clear(entry) | ListCommand::Show(entry) => {
                entry.member
            }
            ListCommand::SetSource { .. } => panic!("an entry command"),
        };
        Ok(member.member().expect("one flag"))
    }

    #[test]
    fn every_entry_command_takes_an_owner_tag_or_a_mint() {
        let tag = Member::owner_tag(Address::from_str_const(TAG).as_array()).expect("member");
        let mint = Member::asset(&Address::from_str_const(MINT)).expect("member");
        for verb in ["add", "clear", "show"] {
            let owner = parse(verb, &["--owner", TAG]).expect(verb);
            assert_eq!(owner, (tag, format!("owner {TAG}")));
            let asset = parse(verb, &["--asset", MINT]).expect(verb);
            assert_eq!(asset, (mint, format!("asset {MINT}")));
        }
    }

    #[test]
    fn sol_in_any_case_names_the_native_token() {
        let sol = (
            Member::asset(&SOL_MINT).expect("member"),
            "asset sol".to_owned(),
        );
        for spelling in ["sol", "SOL", &SOL_MINT.to_string()] {
            assert_eq!(parse("add", &["--asset", spelling]).expect("sol"), sol);
        }
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
