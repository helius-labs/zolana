//! `policy`, the pinned rule table read, checked against `ring.toml` and replaced.

#[cfg(test)]
mod example_tests;
pub mod grammar;
pub mod render;

pub use grammar::{
    describe, describe_limit, Alternative, AssetLimitSpec, CompiledPolicy, LimitSpec, ListName,
    PolicyError, PolicySpec, RuleSpec, SourceSpec, Sources, SubjectName,
};
pub use render::render;

use anyhow::{ensure, Context as _, Result};
use custom_ring_interface::{ListRegistry, MemberRegistry};
use custom_ring_sdk::{CustomRing, PinnedPolicy, PolicyRules};
use solana_signer::Signer;
use zolana_ring_policy::RuleTable;

use crate::{
    catalogue::check_curator,
    line,
    ui::{self, icon},
    Context, PolicyCommand,
};

const NO_POLICY: &str =
    "the ring pins no policy, `zolana-ring init` pins the table of a policy ring";

pub(crate) struct Pinned {
    pub registry: Box<MemberRegistry>,
    pub policy: PinnedPolicy,
}

#[derive(Debug, PartialEq, Eq)]
struct Line {
    label: String,
    text: String,
}

pub fn run(ctx: &Context, command: PolicyCommand) -> Result<()> {
    match command {
        PolicyCommand::Show => {
            let pinned = pinned(ctx)?;
            let title = format!("policy {}", ctx.ring.registry_pda());
            ui::heading(icon::POLICY, &title);
            print_pinned(ctx.ring, &pinned);
        }
        PolicyCommand::Check => {
            let (compiled, pinned) = (compiled(ctx)?, pinned(ctx)?);
            verify_rows(&compiled, &pinned)?;
            verify_sources(ctx.ring, &compiled, &pinned)?;
            line("policy", "matches ring.toml");
            line("generation", pinned.registry.generation());
        }
        PolicyCommand::Set { yes } => set(ctx, yes)?,
    }
    Ok(())
}

pub(crate) fn pinned(ctx: &Context) -> Result<Pinned> {
    pinned_if_any(ctx)?.context(NO_POLICY)
}

/// `None` on an audit-only ring and before `init` pins the table.
pub(crate) fn pinned_if_any(ctx: &Context) -> Result<Option<Pinned>> {
    match ctx.block(ctx.ring.registry(ctx.chain()))? {
        Some(registry) => Pinned::of(registry),
        None => Ok(None),
    }
}

impl Pinned {
    /// `None` before the first policy write.
    pub(crate) fn of(registry: Box<MemberRegistry>) -> Result<Option<Self>> {
        if registry.policy_hash().is_err() {
            return Ok(None);
        }
        let policy = PinnedPolicy::of(&registry)?;
        Ok(Some(Self { registry, policy }))
    }
}

/// The rows and their hash, what a source re-point never changes.
pub(crate) fn verify_rows(compiled: &CompiledPolicy, pinned: &Pinned) -> Result<()> {
    pinned
        .policy
        .matches(&compiled.rules)
        .context("the pinned table differs from ring.toml")
}

/// Every referenced list reads the registry ring.toml names.
pub(crate) fn verify_sources(
    ring: CustomRing,
    compiled: &CompiledPolicy,
    pinned: &Pinned,
) -> Result<()> {
    let registry = |source: Option<ListRegistry>| match source {
        Some(ListRegistry::Own) => ring.registry_pda(),
        Some(ListRegistry::Curator(registry)) => registry,
        None => Default::default(),
    };
    for list_id in compiled.rules.referenced().iter() {
        let expected = compiled
            .curator(list_id)
            .map_or(ListRegistry::Own, |curator| {
                ListRegistry::Curator(curator.registry_pda())
            });
        let chain = pinned.registry.registry_for(list_id);
        ensure!(
            chain == Some(expected),
            "the {} list reads registry {} on chain, ring.toml expects {}",
            list_id.name(),
            registry(chain),
            registry(Some(expected))
        );
    }
    Ok(())
}

pub(crate) fn print_pinned(ring: CustomRing, pinned: &Pinned) {
    let registry = &pinned.registry;
    let (generation, slot) = (registry.generation(), registry.generation_slot());
    line("generation", format_args!("{generation} at slot {slot}"));
    line("hash", hex::encode(pinned.policy.policy_hash));
    let table = &pinned.policy.table;
    let rows = table_lines(table);
    if rows.is_empty() {
        line("rules", "none, an empty table");
    }
    rows.iter().for_each(Line::print);
    let referenced = table.referenced();
    if !referenced.is_empty() {
        ui::heading(icon::LISTS, "sources");
    }
    for list_id in referenced.iter() {
        let source = match registry.registry_for(list_id) {
            Some(ListRegistry::Own) => format!("own registry {}", ring.registry_pda()),
            Some(ListRegistry::Curator(registry)) => format!("curator registry {registry}"),
            None => "no source".to_owned(),
        };
        line(list_id.name(), source);
    }
}

fn compiled(ctx: &Context) -> Result<CompiledPolicy> {
    let audit_only = "ring.toml has no [policy] table, the ring is audit-only";
    let spec = ctx.config.policy.as_ref().context(audit_only)?;
    Ok(spec.compile(ctx.config.target)?)
}

fn set(ctx: &Context, yes: bool) -> Result<()> {
    let program = ctx.ring.program_id();
    let (compiled, current) = (compiled(ctx)?, pinned(ctx)?);
    let verified = verify_rows(&compiled, &current)
        .and_then(|()| verify_sources(ctx.ring, &compiled, &current));
    if verified.is_ok() {
        line("policy", "already present");
        return Ok(());
    }
    for (list_id, curator) in &compiled.shared_sources {
        check_curator(ctx, *curator, *list_id)?;
    }
    ui::heading(icon::PIN, &format!("re-pin the table of {program}"));
    print_diff(&current.policy.table, &compiled.rules);
    for (list_id, curator) in &compiled.shared_sources {
        let curator = curator.program_id();
        line(list_id.name(), format_args!("curator {curator}"));
    }
    ui::warn("proofs built against the old table are refused from now on");
    ctx.confirm(
        yes,
        "replace the pinned table?",
        format_args!("pass --yes to replace the table of {program}, proofs built against the old table are refused from now on"),
        format_args!("the table of {program} stays, the change was not confirmed"),
    )?;
    let authority = ctx.funded_authority()?;
    let replace = PolicyRules {
        ring: ctx.ring,
        authority: authority.pubkey(),
        rules: &compiled.rules,
        shared_sources: &compiled.shared_sources(),
    }
    .replace()?;
    ctx.send(&[authority], &[replace])?;
    let (before, after) = (
        current.registry.generation(),
        pinned(ctx)?.registry.generation(),
    );
    line("policy", "replaced");
    line("generation", format_args!("{after} replaces {before}"));
    Ok(())
}

fn table_lines(table: &RuleTable) -> Vec<Line> {
    let mut lines: Vec<Line> = table
        .rules()
        .iter()
        .enumerate()
        .map(|(index, rule)| Line {
            label: format!("rule {}", index + 1),
            text: describe(rule),
        })
        .collect();
    if !table.is_empty() {
        lines.extend(amount_guard_lines(table));
    }
    lines.extend(limit_lines(table));
    lines
}

fn amount_guard_lines(table: &RuleTable) -> Vec<Line> {
    let count = Line {
        label: "amount guards".to_owned(),
        text: format!("{} mint thresholds", table.inline_assets().len()),
    };
    let guard = |(asset, threshold): (&[u8; 32], &u64)| Line {
        label: "guard".to_owned(),
        text: format!("asset {} above {threshold}", hex::encode(asset)),
    };
    let guards = table.inline_assets().iter().zip(table.inline_limits());
    std::iter::once(count).chain(guards.map(guard)).collect()
}

fn limit_lines(table: &RuleTable) -> Vec<Line> {
    table
        .limits()
        .iter()
        .map(|limit| Line {
            label: "limit".to_owned(),
            text: describe_limit(limit),
        })
        .collect()
}

fn print_diff(old: &RuleTable, new: &RuleTable) {
    for (label, from, to) in [("removed", old, new), ("added", new, old)] {
        for rule in from
            .rules()
            .iter()
            .filter(|rule| !to.rules().contains(rule))
        {
            line(label, describe(rule));
        }
    }
    if old.inline_assets() != new.inline_assets() || old.inline_limits() != new.inline_limits() {
        amount_guard_lines(new).iter().for_each(Line::print);
    }
    if old.limits() != new.limits() {
        limit_lines(new).iter().for_each(Line::print);
    }
}

impl Line {
    fn print(&self) {
        line(&self.label, &self.text);
    }
}

#[cfg(test)]
mod tests {
    use zolana_ring_policy::{ListId, OutflowLimit, Rule, Subject};

    use super::*;

    #[test]
    fn a_table_of_outflow_limits_alone_lists_each_limit() {
        let limit = OutflowLimit {
            asset: [3; 32],
            cap: 1000,
            cosign_above: 0,
        };
        let limits_only = RuleTable::builder().limits(&[limit]).build();
        assert_eq!(
            table_lines(&limits_only),
            [Line {
                label: "limit".to_owned(),
                text: describe_limit(&limit),
            }]
        );
        let with_rule = RuleTable::builder()
            .rule(Rule::forbid(Subject::Sender, ListId::Frozen))
            .limits(&[limit])
            .build();
        let labels: Vec<String> = table_lines(&with_rule)
            .into_iter()
            .map(|line| line.label)
            .collect();
        assert_eq!(labels, ["rule 1", "amount guards", "limit"]);
        assert!(table_lines(&RuleTable::empty()).is_empty());
    }
}
