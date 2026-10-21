//! `list`, the member records of the ring's registry and where each list reads them.

use anyhow::{bail, ensure, Context as _, Result};
use clap::{builder::PossibleValue, Args, ValueEnum};
use custom_ring_interface::{
    CustomRingError, ListRegistry, RecordQueue, APPLY_DELAY_SLOTS, MEMBER_QUEUE_LIMIT,
};
use custom_ring_sdk::{
    AuthorityListWrite, CustomRing, MemberListWrite, MemberRecords, RecordApplication, RingError,
    SourceOwner,
};
use solana_address::Address;
use solana_keypair::Keypair;
use solana_signer::Signer;
use zolana_client::Rpc;
use zolana_ring_policy::{ListId, ListSet, ListWrite, ListWriteError, Member};

use crate::{
    catalogue::{check_curator, Catalogue},
    line,
    policy::{self, Pinned},
    records::{self, insert_fee, queue, write_budget, PendingWrites, Queued, Stage},
    transact::SENDER_FEE_BUDGET,
    ui::{self, icon},
    Context, EntryArgs, ListCommand,
};

#[derive(Debug, Clone, Args)]
#[group(required = true, multiple = true)]
pub struct MemberArgs {
    /// A member's Solana address, repeatable.
    #[arg(long = "owner", value_name = "ADDRESS")]
    owners: Vec<Address>,
    /// A mint the list screens, repeatable.
    #[arg(long = "asset", value_name = "MINT")]
    assets: Vec<Address>,
}

/// The escrow bit comes only from `key register`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MemberList(ListId);

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Subject {
    pub member: Member,
    pub label: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ListChange {
    Set,
    Clear,
}

#[must_use]
pub(crate) struct ListUpdate<'a> {
    pub authority: &'a Keypair,
    pub list_id: ListId,
    pub subjects: &'a [Subject],
    pub change: ListChange,
}

#[derive(Clone, Copy, Debug)]
struct MemberLists {
    applied: u64,
    queued: u64,
}

/// The authority's writes in queue order.
#[must_use]
struct ListWrites<'a> {
    ring: CustomRing,
    authority: Address,
    changes: &'a [(Member, ListWrite)],
}

pub fn run(ctx: &Context, command: ListCommand) -> Result<()> {
    match command {
        ListCommand::Add(entry) => entry.write(ctx, ListChange::Set),
        ListCommand::Clear(entry) => entry.write(ctx, ListChange::Clear),
        ListCommand::Show(entry) => entry.show(ctx),
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
        ListCommand::Apply => apply(ctx),
        ListCommand::Join { list } => list.write(ctx, ListChange::Set),
        ListCommand::Leave { list } => list.write(ctx, ListChange::Clear),
    }
}

impl MemberArgs {
    pub(crate) fn subjects(&self) -> Result<Vec<Subject>> {
        let owners = self.owners.iter().map(|tag| {
            Ok(Subject {
                member: Member::owner_tag(tag.as_array())?,
                label: format!("owner {tag}"),
            })
        });
        let assets = self.assets.iter().map(|mint| {
            Ok(Subject {
                member: Member::asset(mint)?,
                label: format!("asset {mint}"),
            })
        });
        owners.chain(assets).collect()
    }
}

impl MemberList {
    /// In `ListId::ALL` order.
    pub const ALL: [Self; 2] = [Self(ListId::RingViewing), Self(ListId::Recovery)];

    pub const fn id(self) -> ListId {
        self.0
    }

    fn write(self, ctx: &Context, change: ListChange) -> Result<()> {
        let list_id = self.0;
        let config = ctx.ring_config()?;
        let sender = ctx.sender()?;
        let member = Member::owner_tag(sender.pubkey().as_array())?;
        line(
            "member",
            format_args!("{} {}", list_id.name(), sender.pubkey()),
        );
        let pending = PendingWrites::read(ctx)?;
        let read = records::read_one(
            &ctx.zolana,
            MemberRecords {
                ring: ctx.ring,
                members: &[member],
            },
        )?;
        let lists = MemberLists {
            applied: read.record().map_or(0, |record| record.lists),
            queued: pending.record_after(&member, read.record()).lists,
        };
        let queued = match change.stage(list_id, lists) {
            Stage::Applied => {
                line("list", "already there");
                return Ok(());
            }
            Stage::Queued => {
                line("list", "already queued");
                ctx.fund(sender.pubkey(), SENDER_FEE_BUDGET)?;
                Queued::now(ctx)?
            }
            Stage::Unsent => {
                let write = MemberListWrite {
                    ring: ctx.ring,
                    payer: sender.pubkey(),
                    member: sender.pubkey(),
                    lists: change.write(list_id)?,
                };
                ctx.fund(sender.pubkey(), write_budget(&config, &sender.pubkey()))?;
                ctx.send(&[&sender], &[write.instruction(&config)?])?;
                line("list", change.outcome());
                let fee = insert_fee(&config, &sender.pubkey());
                line("insert fee", format_args!("{fee} lamports"));
                Queued::now(ctx)?
            }
        };
        queued.apply(ctx, &sender)?;
        line("queue", "applied");
        Ok(())
    }
}

impl ValueEnum for MemberList {
    fn value_variants<'a>() -> &'a [Self] {
        &Self::ALL
    }

    fn to_possible_value(&self) -> Option<PossibleValue> {
        Some(PossibleValue::new(self.0.name()))
    }
}

impl ListChange {
    fn write(self, list_id: ListId) -> Result<ListWrite, ListWriteError> {
        let list = ListSet::single(list_id);
        match self {
            Self::Set => ListWrite::new(list, ListSet::EMPTY),
            Self::Clear => ListWrite::new(ListSet::EMPTY, list),
        }
    }

    const fn present(self) -> bool {
        matches!(self, Self::Set)
    }

    /// A write lands after every pending one, only the state the queue leaves counts.
    fn stage(self, list_id: ListId, lists: MemberLists) -> Stage {
        let holds = |lists: u64| (lists & list_id.record_bit() != 0) == self.present();
        if !holds(lists.queued) {
            Stage::Unsent
        } else if holds(lists.applied) {
            Stage::Applied
        } else {
            Stage::Queued
        }
    }

    const fn outcome(self) -> &'static str {
        match self {
            Self::Set => "added",
            Self::Clear => "removed",
        }
    }
}

impl EntryArgs {
    fn write(self, ctx: &Context, change: ListChange) -> Result<()> {
        let list_id = self.list_id.id();
        let subjects = self.members.subjects()?;
        let outcomes = ListUpdate {
            authority: ctx.funded_authority()?,
            list_id,
            subjects: &subjects,
            change,
        }
        .send(ctx)?;
        for (subject, outcome) in subjects.iter().zip(outcomes) {
            line(
                "member",
                format_args!("{} {}", list_id.name(), subject.label),
            );
            line("list", outcome);
        }
        Ok(())
    }

    fn show(self, ctx: &Context) -> Result<()> {
        let list_id = self.list_id.id();
        let subjects = self.members.subjects()?;
        let (ring, source) = match policy::pinned(ctx)?.registry.registry_for(list_id) {
            Some(ListRegistry::Curator(registry)) => (
                curator_ring(ctx, registry)?,
                format!("curator registry {registry}"),
            ),
            _ => (ctx.ring, "own registry".to_owned()),
        };
        let members: Vec<Member> = subjects.iter().map(|subject| subject.member).collect();
        let reads = records::read(
            &ctx.zolana,
            MemberRecords {
                ring,
                members: &members,
            },
        )?;
        line("source", source);
        for (subject, read) in subjects.iter().zip(&reads) {
            line(
                "member",
                format_args!("{} {}", list_id.name(), subject.label),
            );
            line("listed", read.listed(list_id));
            let record = match read.record() {
                Some(_) => "present",
                None => "absent",
            };
            line("record", record);
        }
        Ok(())
    }
}

impl ListUpdate<'_> {
    /// Writes the ring's own registry only, a curator's list is written on the curator ring.
    pub(crate) fn send(self, ctx: &Context) -> Result<Vec<&'static str>> {
        let list_id = self.list_id;
        if let Some(ListRegistry::Curator(registry)) =
            policy::pinned(ctx)?.registry.registry_for(list_id)
        {
            bail!(
                "the {} list reads curator registry {registry}, write it on the curator ring",
                list_id.name()
            );
        }
        let members: Vec<Member> = self.subjects.iter().map(|subject| subject.member).collect();
        let reads = records::read(
            &ctx.zolana,
            MemberRecords {
                ring: ctx.ring,
                members: &members,
            },
        )?;
        let mut writes = Vec::new();
        let mut outcomes = Vec::with_capacity(self.subjects.len());
        for (subject, read) in self.subjects.iter().zip(&reads) {
            if read.listed(list_id) == self.change.present() {
                outcomes.push("already there");
                continue;
            }
            writes.push((subject.member, self.change.write(list_id)?));
            outcomes.push(self.change.outcome());
        }
        ListWrites {
            ring: ctx.ring,
            authority: self.authority.pubkey(),
            changes: &writes,
        }
        .send(
            || Ok(queue(ctx)?.pending()),
            |batch| ctx.submit(batch, self.authority, &[]).map(drop),
        )?;
        Ok(outcomes)
    }
}

impl ListWrites<'_> {
    /// The queue is re-read before each batch, its pending writes share the proof.
    fn send(
        self,
        mut pending: impl FnMut() -> Result<u64>,
        mut send: impl FnMut(AuthorityListWrite) -> Result<()>,
    ) -> Result<()> {
        let mut sent = 0;
        while sent < self.changes.len() {
            let rest = self.changes[sent..].iter().try_fold(
                AuthorityListWrite::new(self.ring, self.authority),
                |write, (member, lists)| write.with_write(*member, *lists),
            )?;
            let batch = rest
                .batches(pending()?)
                .into_iter()
                .next()
                .context("no batch takes the remaining writes")?;
            sent += batch.writes().len();
            send(batch)?;
        }
        Ok(())
    }
}

/// A policy source names the curator by its registry account.
fn curator_ring(ctx: &Context, registry: Address) -> Result<CustomRing> {
    let account = ctx
        .rpc()
        .get_account(registry)?
        .with_context(|| format!("curator registry {registry} does not exist"))?;
    let curator = CustomRing::new(account.owner);
    ensure!(
        curator.registry_pda() == registry,
        "{registry} is not the member registry of {}",
        account.owner
    );
    Ok(curator)
}

/// The registry a source names, as the policy stores it.
pub(crate) fn expected_registry(source: SourceOwner) -> ListRegistry {
    match source {
        SourceOwner::Own => ListRegistry::Own,
        SourceOwner::Shared(curator) => ListRegistry::Curator(curator.registry_pda()),
    }
}

fn set_source(ctx: &Context, list_id: ListId, source: SourceOwner) -> Result<()> {
    let Pinned { registry, .. } = policy::pinned(ctx)?;
    if let SourceOwner::Shared(curator) = source {
        check_curator(ctx, curator, list_id)?;
    }
    let authority = ctx.funded_authority()?;
    let outcome = if registry.registry_for(list_id) == Some(expected_registry(source)) {
        "already present"
    } else {
        let point = ctx
            .ring
            .set_source_owner(authority.pubkey(), list_id, source)?;
        ctx.send(&[authority], &[point])?;
        "created"
    };
    let registry = policy::pinned(ctx)?
        .registry
        .registry_for(list_id)
        .with_context(|| format!("the policy does not reference the {} list", list_id.name()))?;
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
            ListRegistry::Own => ctx.ring.registry_pda(),
            ListRegistry::Curator(registry) => registry,
        },
    );
    Ok(())
}

/// Anyone may apply a due queue, the sender pays.
fn apply(ctx: &Context) -> Result<()> {
    let queue = queue(ctx)?;
    line("pending", queue.pending());
    match queue.apply_due(ctx.rpc().get_slot()?) {
        Ok(()) => {
            let payer = ctx.sender()?;
            ctx.fund(payer.pubkey(), SENDER_FEE_BUDGET)?;
            let signature = ctx.submit(RecordApplication::new(ctx.ring), &payer, &[])?;
            line("queue", "applied");
            line("application", signature);
        }
        Err(CustomRingError::ApplyNotDue) => line("queue", not_due(&queue)),
        Err(CustomRingError::ApplyTooSoon) => line(
            "queue",
            format_args!(
                "due, the next application lands from slot {}",
                queue.next_apply_slot()
            ),
        ),
        Err(error) => return Err(RingError::from(error).into()),
    }
    Ok(())
}

fn not_due(queue: &RecordQueue) -> String {
    match queue.pending() {
        0 => "empty".to_owned(),
        pending => format!(
            "{pending} pending, due at {MEMBER_QUEUE_LIMIT} or once the oldest is {APPLY_DELAY_SLOTS} slots old"
        ),
    }
}

#[cfg(test)]
mod tests {
    use clap::{error::ErrorKind, Parser};

    use super::*;
    use crate::{Cli, Command, ListCommand};

    const TAG: &str = "9vyTbYGyh3cwxkAQpjjFQGXmdJP6p9B6YcQ5pNuXPNbh";
    const MINT: &str = "So11111111111111111111111111111111111111112";

    fn parse(verb: &str, flags: &[&str]) -> Result<Vec<Subject>, clap::Error> {
        let argv = ["zolana-ring", "list", verb, "block"]
            .into_iter()
            .chain(flags.iter().copied());
        let Command::List(command) = Cli::try_parse_from(argv)?.command else {
            panic!("a list command");
        };
        let members = match command {
            ListCommand::Add(entry) | ListCommand::Clear(entry) | ListCommand::Show(entry) => {
                entry.members
            }
            _ => panic!("a member command"),
        };
        Ok(members.subjects().expect("members"))
    }

    fn subject(member: Member, label: String) -> Subject {
        Subject { member, label }
    }

    #[test]
    fn every_member_command_takes_repeated_owners_and_assets() {
        let tag = Member::owner_tag(Address::from_str_const(TAG).as_array()).expect("member");
        let mint = Member::asset(&Address::from_str_const(MINT)).expect("mint");
        for verb in ["add", "clear", "show"] {
            assert_eq!(
                parse(verb, &["--owner", TAG]).expect(verb),
                [subject(tag, format!("owner {TAG}"))]
            );
            assert_eq!(
                parse(verb, &["--asset", MINT, "--owner", TAG, "--owner", TAG]).expect(verb),
                [
                    subject(tag, format!("owner {TAG}")),
                    subject(tag, format!("owner {TAG}")),
                    subject(mint, format!("asset {MINT}")),
                ]
            );
        }
        assert_eq!(
            parse("add", &[]).expect_err("no member").kind(),
            ErrorKind::MissingRequiredArgument
        );
    }

    #[test]
    fn a_member_writes_only_its_own_lists() {
        let join = |list: &str| Cli::try_parse_from(["zolana-ring", "list", "join", list]);
        for list in MemberList::ALL {
            assert!(join(list.0.name()).is_ok(), "{}", list.0.name());
        }
        for list in ["allow", "escrow", "block"] {
            assert!(join(list).is_err(), "{list}");
        }
    }

    #[test]
    fn a_member_write_the_queue_already_holds_is_not_sent_again() {
        let bit = ListId::RingViewing.record_bit();
        let stage = |change: ListChange, applied, queued| {
            change.stage(ListId::RingViewing, MemberLists { applied, queued })
        };
        assert_eq!(stage(ListChange::Set, 0, bit), Stage::Queued);
        assert_eq!(stage(ListChange::Set, bit, bit), Stage::Applied);
        assert_eq!(stage(ListChange::Set, 0, 0), Stage::Unsent);
        assert_eq!(stage(ListChange::Clear, bit, 0), Stage::Queued);
        // A pending join undoes an applied leave, the leave goes out again.
        assert_eq!(stage(ListChange::Clear, 0, bit), Stage::Unsent);
        assert_eq!(stage(ListChange::Set, bit, 0), Stage::Unsent);
    }

    #[test]
    fn the_member_lists_are_the_lists_a_member_writes() {
        let lists: Vec<ListId> = MemberList::ALL.into_iter().map(MemberList::id).collect();
        let written: Vec<ListId> = ListId::ALL
            .into_iter()
            .filter(|list_id| ListSet::MEMBER_WRITES.contains(*list_id))
            .collect();
        assert_eq!(lists, written);
    }

    fn allow() -> ListWrite {
        ListChange::Set.write(ListId::Allow).unwrap()
    }

    struct Batches {
        sizes: Vec<usize>,
        order: Vec<Member>,
    }

    fn batches(writes: &[(Member, ListWrite)], pending: &[u64]) -> Batches {
        let mut pending = pending.iter().copied();
        let mut batches = Batches {
            sizes: Vec::new(),
            order: Vec::new(),
        };
        ListWrites {
            ring: CustomRing::new(Address::new_from_array([9; 32])),
            authority: Address::new_from_array([3; 32]),
            changes: writes,
        }
        .send(
            || Ok(pending.next().expect("one queue read per batch")),
            |batch| {
                batches.sizes.push(batch.writes().len());
                batches
                    .order
                    .extend(batch.writes().iter().map(|(member, _)| *member));
                Ok(())
            },
        )
        .unwrap();
        batches
    }

    #[test]
    fn list_write_splits_at_one_batch() {
        let writes: Vec<(Member, ListWrite)> = (1..=20u8)
            .map(|byte| (Member::owner_tag(&[byte; 32]).unwrap(), allow()))
            .collect();
        assert_eq!(batches(&writes[..16], &[0]).sizes, [16]);
        assert_eq!(batches(&writes, &[0, 0]).sizes, [16, 4]);
        // The first batch takes the room the pending member writes leave, its proof applies them.
        assert_eq!(batches(&writes, &[8, 0]).sizes, [8, 12]);
        // A member write queued between two batches shrinks the next.
        let interleaved = batches(&writes, &[10, 6, 0]);
        assert_eq!(interleaved.sizes, [6, 10, 4]);
        let members: Vec<Member> = writes.iter().map(|(member, _)| *member).collect();
        assert_eq!(
            interleaved.order, members,
            "the writes keep their order across batches"
        );
    }

    #[test]
    fn a_list_write_names_each_member_once() {
        let member = Member::owner_tag(&[1; 32]).unwrap();
        let writes = [(member, allow()), (member, allow())];
        let refused = ListWrites {
            ring: CustomRing::new(Address::new_from_array([9; 32])),
            authority: Address::new_from_array([3; 32]),
            changes: &writes,
        }
        .send(|| Ok(0), |_| Ok(()))
        .unwrap_err();
        assert!(matches!(
            refused.downcast_ref::<RingError>(),
            Some(RingError::DuplicateListWrite { .. })
        ));
    }

    #[test]
    fn a_source_names_the_registry_account() {
        let curator = CustomRing::new(Address::new_from_array([4; 32]));
        assert_eq!(expected_registry(SourceOwner::Own), ListRegistry::Own);
        assert_eq!(
            expected_registry(SourceOwner::Shared(curator)),
            ListRegistry::Curator(curator.registry_pda())
        );
    }
}
