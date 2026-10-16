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
use custom_ring_sdk::{client_rules_match, CustomRing, ListRegistry, PolicyConfig};
use solana_signer::Signer;
use zolana_ring_policy::RuleTable;

use crate::{
    catalogue::check_curator,
    fund::MIN_AUTHORITY_BALANCE,
    line,
    ui::{self, icon},
    Context, PolicyCommand,
};

pub fn run(ctx: &Context, command: PolicyCommand) -> Result<()> {
    match command {
        PolicyCommand::Show => {
            let config = pinned(ctx)?;
            let title = format!("policy {}", ctx.ring.policy_config_pda());
            ui::heading(icon::POLICY, &title);
            print_pinned(ctx.ring, &config);
        }
        PolicyCommand::Check => {
            let (compiled, config) = (compiled(ctx)?, pinned(ctx)?);
            verify_rows(&compiled, &config)?;
            verify_sources(ctx.ring, &compiled, &config)?;
            line("policy", "matches ring.toml");
            line("generation", config.generation());
        }
        PolicyCommand::Set { yes } => set(ctx, yes)?,
    }
    Ok(())
}

/// Rows, hash and tree, what a source re-point never changes.
pub fn verify_rows(compiled: &CompiledPolicy, config: &PolicyConfig) -> Result<()> {
    client_rules_match(&compiled.rules, config)
        .context("the pinned table differs from ring.toml")?;
    verify_tree(compiled, config)
}

/// Every referenced list reads the registry ring.toml names.
pub fn verify_sources(
    ring: CustomRing,
    compiled: &CompiledPolicy,
    config: &PolicyConfig,
) -> Result<()> {
    let registry = |source: Option<ListRegistry>| match source {
        Some(ListRegistry::Own) => ring.member_registry_root_pda(),
        Some(ListRegistry::Curator(registry)) => registry,
        None => Default::default(),
    };
    for list_id in compiled.rules.referenced().iter() {
        let expected = compiled
            .curator(list_id)
            .map_or(ListRegistry::Own, |curator| {
                ListRegistry::Curator(curator.member_registry_root_pda())
            });
        let chain = config.registry_for(list_id);
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

/// No re-pin moves the tree, it is fixed at init.
fn verify_tree(compiled: &CompiledPolicy, config: &PolicyConfig) -> Result<()> {
    ensure!(
        config.address_tree == compiled.address_tree,
        "ring.toml names address tree {}, the policy config pins {}, it is fixed at init",
        compiled.address_tree,
        config.address_tree
    );
    Ok(())
}

pub fn print_pinned(ring: CustomRing, config: &PolicyConfig) {
    ui::heading(icon::TREE, &format!("tree {}", config.address_tree));
    let (generation, slot) = (config.generation(), config.generation_slot());
    line("generation", format_args!("{generation} at slot {slot}"));
    line("hash", hex::encode(config.policy_hash));
    match config.rule_table() {
        Ok(table) if table.is_empty() => line("rules", "none, an empty table"),
        Ok(table) => {
            for (index, rule) in table.rules().iter().enumerate() {
                line(&format!("rule {}", index + 1), describe(rule));
            }
            if let count @ 1.. = table.inline_assets().len() {
                line("assets", format_args!("{count} listed inline"));
            }
            print_limits(&table);
        }
        Err(error) => line("rules", format_args!("undecodable ({error})")),
    }
    let referenced = config.rules.referenced();
    if referenced.iter().next().is_some() {
        ui::heading(icon::LISTS, "sources");
    }
    for list_id in referenced.iter() {
        let source = match config.registry_for(list_id) {
            Some(ListRegistry::Own) => format!("own registry {}", ring.member_registry_root_pda()),
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

fn pinned(ctx: &Context) -> Result<PolicyConfig> {
    ctx.block(ctx.ring.policy_config(ctx.chain()))?
        .context("the ring has no policy config, run `zolana-ring init` first")
}

fn set(ctx: &Context, yes: bool) -> Result<()> {
    let program = ctx.ring.program_id();
    let (compiled, config) = (compiled(ctx)?, pinned(ctx)?);
    verify_tree(&compiled, &config)?;
    let verified =
        verify_rows(&compiled, &config).and_then(|()| verify_sources(ctx.ring, &compiled, &config));
    if verified.is_ok() {
        line("policy", "already present");
        return Ok(());
    }
    for (list_id, curator) in &compiled.shared_sources {
        check_curator(ctx, *curator, *list_id)?;
    }
    ui::heading(icon::PIN, &format!("re-pin the table of {program}"));
    match config.rule_table() {
        Ok(old) => print_diff(&old, &compiled.rules),
        Err(error) => line("rules", format_args!("undecodable on chain ({error})")),
    }
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
    let authority = ctx.config.upgrade_authority()?;
    ctx.fund(authority.pubkey(), MIN_AUTHORITY_BALANCE)?;
    let replace = ctx.ring.set_policy_rules(
        authority.pubkey(),
        &compiled.rules,
        &compiled.shared_sources(),
    )?;
    ctx.send(&[&authority], &[replace])?;
    let (before, after) = (config.generation(), pinned(ctx)?.generation());
    line("policy", "replaced");
    line("generation", format_args!("{after} replaces {before}"));
    Ok(())
}

fn print_limits(table: &RuleTable) {
    for limit in table.limits() {
        line("limit", describe_limit(limit));
    }
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
    if old.inline_assets() != new.inline_assets() {
        let count = new.inline_assets().len();
        line("assets", format_args!("{count} listed inline"));
    }
    if old.limits() != new.limits() {
        print_limits(new);
    }
}
