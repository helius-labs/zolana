//! `list`, the member records of the ring's registry and where each list reads them.

use anyhow::{bail, Context as _, Result};
use clap::Args;
use custom_ring_sdk::{
    CustomRing, ListRegistry, MemberWrite, PolicyConfig, ReadMemberRecord, SourceOwner,
    UpdateMembers,
};
use solana_address::Address;
use solana_keypair::Keypair;
use solana_signer::Signer;
use zolana_ring_policy::{ListId, Member, Writer};

use crate::{
    catalogue::{check_curator, Catalogue},
    controls::NO_MEMBER_REGISTRY,
    line,
    ui::{self, icon},
    Context, EntryArgs, ListCommand,
};

const NO_POLICY: &str = "the ring has no policy config, run `zolana-ring init` first";

#[derive(Debug, Clone, Copy, Args)]
pub struct MemberArg {
    /// The member's owner tag, base58.
    #[arg(long, value_name = "TAG")]
    owner: Address,
}

impl MemberArg {
    pub fn member(&self) -> Result<(Member, String)> {
        let tag = self.owner;
        Ok((Member::owner_tag(tag.as_array())?, format!("owner {tag}")))
    }
}

pub fn run(ctx: &Context, command: ListCommand) -> Result<()> {
    match command {
        ListCommand::Add(entry) => set(ctx, entry, true),
        ListCommand::Clear(entry) => set(ctx, entry, false),
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

fn set(ctx: &Context, entry: EntryArgs, present: bool) -> Result<()> {
    let (member, label) = entry.member.member()?;
    let authority = ctx.funded_authority()?;
    line("member", format_args!("{} {label}", entry.list_id));
    let change = set_list(ctx, authority, entry.list_id.id(), member, present)?;
    line("list", change);
    Ok(())
}

/// Writes the ring's own registry only, a curator's list is written on the curator ring.
pub(crate) fn set_list(
    ctx: &Context,
    authority: &Keypair,
    list_id: ListId,
    member: Member,
    present: bool,
) -> Result<&'static str> {
    let config = policy_config(ctx)?;
    if let Some(ListRegistry::Curator(registry)) = config.registry_for(list_id) {
        bail!(
            "the {} list reads curator registry {registry}, write it on the curator ring",
            list_id.name()
        );
    }
    if list_id.writer() == Writer::Member {
        bail!(
            "the member writes the {} list, the authority cannot",
            list_id.name()
        );
    }
    let read = ReadMemberRecord {
        ring: ctx.ring,
        member,
    };
    let record = ctx
        .block(read.read(ctx.chain()))?
        .context(NO_MEMBER_REGISTRY)?;
    if record.opening.list_set().contains(list_id) == present {
        return Ok("already there");
    }
    let write = match present {
        true => MemberWrite::add(member, list_id),
        false => MemberWrite::remove(member, list_id),
    };
    let update = UpdateMembers {
        ring: ctx.ring,
        writes: vec![write],
        signers: vec![authority.pubkey()],
    };
    ctx.submit(update, authority, &[])?;
    Ok(if present { "added" } else { "removed" })
}

fn show(ctx: &Context, list_id: ListId, member: MemberArg) -> Result<()> {
    let config = policy_config(ctx)?;
    let (member, label) = member.member()?;
    let (ring, source) = match config.registry_for(list_id) {
        Some(ListRegistry::Curator(registry)) => (
            ctx.block(CustomRing::curator_registry(ctx.chain(), registry))?
                .0,
            format!("curator registry {registry}"),
        ),
        _ => (ctx.ring, "own registry".to_owned()),
    };
    let read = ReadMemberRecord { ring, member };
    let record = ctx
        .block(read.read(ctx.chain()))?
        .context(NO_MEMBER_REGISTRY)?;
    line("member", format_args!("{} {label}", list_id.name()));
    line("source", source);
    line("listed", record.opening.list_set().contains(list_id));
    line(
        "record",
        if record.opening.is_present() {
            "present"
        } else {
            "absent"
        },
    );
    Ok(())
}

fn policy_config(ctx: &Context) -> Result<PolicyConfig> {
    ctx.block(ctx.ring.policy_config(ctx.chain()))?
        .context(NO_POLICY)
}

/// The registry a source names, as the policy config stores it.
pub(crate) fn expected_registry(source: SourceOwner) -> ListRegistry {
    match source {
        SourceOwner::Own => ListRegistry::Own,
        SourceOwner::Shared(curator) => ListRegistry::Curator(curator.member_registry_root_pda()),
    }
}

fn set_source(ctx: &Context, list_id: ListId, source: SourceOwner) -> Result<()> {
    let config = policy_config(ctx)?;
    if let SourceOwner::Shared(curator) = source {
        check_curator(ctx, curator, list_id)?;
    }
    let authority = ctx.funded_authority()?;
    let outcome = if config.registry_for(list_id) == Some(expected_registry(source)) {
        "already present"
    } else {
        let point = ctx
            .ring
            .set_source_owner(authority.pubkey(), list_id, source)?;
        ctx.send(&[authority], &[point])?;
        "created"
    };
    let registry = policy_config(ctx)?
        .registry_for(list_id)
        .context(NO_POLICY)?;
    let (glyph, reads) = match source {
        SourceOwner::Own => (icon::LISTS, "its own registry".to_owned()),
        SourceOwner::Shared(curator) => {
            (icon::CURATOR, format!("curator {}", curator.program_id()))
        }
    };
    ui::heading(glyph, &format!("the {} list reads {reads}", list_id.name()));
    line("source", outcome);
    line(
        "registry",
        match registry {
            ListRegistry::Own => ctx.ring.member_registry_root_pda(),
            ListRegistry::Curator(registry) => registry,
        },
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use clap::{error::ErrorKind, Parser};

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
            ListCommand::SetSource { .. } => panic!("a member command"),
        };
        Ok(member.member().expect("one flag"))
    }

    #[test]
    fn every_member_command_takes_an_owner_tag() {
        let tag = Member::owner_tag(Address::from_str_const(TAG).as_array()).expect("member");
        for verb in ["add", "clear", "show"] {
            let owner = parse(verb, &["--owner", TAG]).expect(verb);
            assert_eq!(owner, (tag, format!("owner {TAG}")));
        }
    }

    /// Assets have no member record, an asset rule reads the inline pool.
    #[test]
    fn an_asset_is_not_a_list_member() {
        assert_eq!(
            parse("add", &[]).expect_err("no flag").kind(),
            ErrorKind::MissingRequiredArgument
        );
        assert_eq!(
            parse("add", &["--asset", MINT])
                .expect_err("an asset")
                .kind(),
            ErrorKind::UnknownArgument
        );
    }

    #[test]
    fn a_source_names_the_registry_root_account() {
        let curator = CustomRing::new(Address::new_from_array([4; 32]));
        assert_eq!(expected_registry(SourceOwner::Own), ListRegistry::Own);
        assert_eq!(
            expected_registry(SourceOwner::Shared(curator)),
            ListRegistry::Curator(curator.member_registry_root_pda())
        );
    }
}
