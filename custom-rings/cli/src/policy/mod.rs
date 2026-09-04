//! `policy`, the pinned rule table read, checked against `ring.toml` and replaced.

#[cfg(test)]
mod examples;
pub mod grammar;
pub mod render;

pub use grammar::{
    compile_rows, describe, list_name, Alternative, AssetLimitSpec, CompiledPolicy, ListName,
    PolicyError, PolicySpec, RuleSpec, SourceSpec, Sources, SubjectName,
};
pub use render::render;

use custom_ring_sdk::{
    client_rules_match, AccountReadError, CustomRing, EntryError, PolicyConfig, PolicyMatchError,
    SetPolicyRules, SET_POLICY_RULES_COMPUTE_UNIT_LIMIT,
};
use solana_address::Address;
use solana_signer::Signer;
use thiserror::Error;
use zolana_ring_policy::RuleTable;

use crate::{
    catalogue::{CuratorCheck, CuratorError},
    fund::MIN_AUTHORITY_BALANCE,
    line,
    step::{no_hint, IdempotentStep, Observed, StepError},
    ui::{self, AskError, Icon},
    Context, ContextError, PolicyCommand,
};

#[derive(Debug, Error)]
pub enum PolicyCommandError {
    #[error(transparent)]
    Context(#[from] ContextError),
    #[error(transparent)]
    AccountRead(#[from] AccountReadError),
    #[error(transparent)]
    Grammar(#[from] PolicyError),
    #[error(transparent)]
    Build(Box<EntryError>),
    #[error(transparent)]
    Step(#[from] StepError),
    #[error(transparent)]
    Ask(#[from] AskError),
    #[error(transparent)]
    Curator(#[from] CuratorError),
    #[error("ring.toml has no [policy] table, the ring is audit-only")]
    NoPolicyInToml,
    #[error("the ring has no policy config, run `zolana-ring init` first")]
    NotPinned,
    #[error("the pinned table differs from ring.toml")]
    Drift(#[source] PolicyMatchError),
    #[error(
        "ring.toml names tree {toml}, the policy config pins {chain}, a tree is fixed at init"
    )]
    TreeDrift { toml: Address, chain: Address },
    #[error("the {list} list reads {chain} on chain, ring.toml expects {expected}")]
    SourceDrift {
        list: &'static str,
        chain: Address,
        expected: Address,
    },
    #[error("pass --yes to replace the table of {program}, proofs built against the old table are refused from now on")]
    NeedsConfirmation { program: Address },
    #[error("the table of {program} stays, the change was not confirmed")]
    Declined { program: Address },
}

pub fn run(ctx: &mut Context, command: PolicyCommand) -> Result<(), PolicyCommandError> {
    match command {
        PolicyCommand::Show => show(ctx),
        PolicyCommand::Check => check(ctx),
        PolicyCommand::Set { yes } => set(ctx, yes),
    }
}

pub fn verify(
    ring: CustomRing,
    compiled: &CompiledPolicy,
    config: &PolicyConfig,
) -> Result<(), PolicyCommandError> {
    verify_rows(compiled, config)?;
    verify_sources(ring, compiled, config)
}

/// Rows, hash and tree, what a source re-point never changes.
pub fn verify_rows(
    compiled: &CompiledPolicy,
    config: &PolicyConfig,
) -> Result<(), PolicyCommandError> {
    client_rules_match(&compiled.rules, config).map_err(PolicyCommandError::Drift)?;
    if config.entries_tree != compiled.entries_tree {
        return Err(PolicyCommandError::TreeDrift {
            toml: compiled.entries_tree,
            chain: config.entries_tree,
        });
    }
    Ok(())
}

/// Every referenced list reads the namespace ring.toml names.
pub fn verify_sources(
    ring: CustomRing,
    compiled: &CompiledPolicy,
    config: &PolicyConfig,
) -> Result<(), PolicyCommandError> {
    for list_id in compiled.rules.referenced().iter() {
        let expected = compiled
            .curator(list_id)
            .map_or_else(|| ring.namespace_pda(), CustomRing::namespace_pda);
        let chain = config.source_for(list_id).unwrap_or_default();
        if chain != expected {
            return Err(PolicyCommandError::SourceDrift {
                list: list_name(list_id),
                chain,
                expected,
            });
        }
    }
    Ok(())
}

pub fn print_pinned(ring: CustomRing, config: &PolicyConfig) {
    ui::heading(Icon::Tree, &format!("tree {}", config.entries_tree));
    line(
        "generation",
        format_args!(
            "{} at slot {}",
            config.generation(),
            config.generation_slot()
        ),
    );
    line("hash", hex::encode(config.policy_hash));
    match config.rule_table() {
        Ok(table) if table.is_empty() => line("rules", "none, an empty table"),
        Ok(table) => {
            for (index, rule) in table.rules().iter().enumerate() {
                line(&format!("rule {}", index + 1), describe(rule));
            }
            if !table.inline_assets().is_empty() {
                line(
                    "assets",
                    format_args!("{} listed inline", table.inline_assets().len()),
                );
            }
        }
        Err(error) => line("rules", format_args!("undecodable ({error})")),
    }
    let own = ring.namespace_pda();
    let sources: Vec<_> = config
        .rules
        .referenced()
        .iter()
        .map(|list_id| {
            let source = match config.source_for(list_id) {
                Some(namespace) if namespace == own => "own entries".to_owned(),
                Some(namespace) => format!("curator namespace {namespace}"),
                None => "no source".to_owned(),
            };
            (list_name(list_id), source)
        })
        .collect();
    if !sources.is_empty() {
        ui::heading(Icon::Lists, "sources");
        for (list, source) in sources {
            line(list, source);
        }
    }
}

fn compiled(ctx: &Context) -> Result<CompiledPolicy, PolicyCommandError> {
    Ok(ctx
        .config
        .policy
        .as_ref()
        .ok_or(PolicyCommandError::NoPolicyInToml)?
        .compile(ctx.config.target)?)
}

fn pinned(ctx: &Context) -> Result<PolicyConfig, PolicyCommandError> {
    ctx.ring
        .read_policy_config(&ctx.rpc)?
        .ok_or(PolicyCommandError::NotPinned)
}

fn show(ctx: &Context) -> Result<(), PolicyCommandError> {
    let config = pinned(ctx)?;
    ui::heading(
        Icon::Policy,
        &format!("policy {}", ctx.ring.policy_config_pda()),
    );
    print_pinned(ctx.ring, &config);
    Ok(())
}

fn check(ctx: &Context) -> Result<(), PolicyCommandError> {
    let compiled = compiled(ctx)?;
    let config = pinned(ctx)?;
    verify(ctx.ring, &compiled, &config)?;
    line("policy", "matches ring.toml");
    line("generation", config.generation());
    Ok(())
}

fn set(ctx: &mut Context, yes: bool) -> Result<(), PolicyCommandError> {
    let program = ctx.ring.program_id();
    let compiled = compiled(ctx)?;
    let config = pinned(ctx)?;
    match verify(ctx.ring, &compiled, &config) {
        Ok(()) => {
            line("policy", "already present");
            return Ok(());
        }
        Err(drift @ PolicyCommandError::TreeDrift { .. }) => return Err(drift),
        Err(_) => {}
    }
    for (list_id, curator) in &compiled.shared_sources {
        CuratorCheck {
            curator: *curator,
            list: *list_id,
            entries_tree: compiled.entries_tree,
        }
        .run(&ctx.rpc)?;
    }
    ui::heading(Icon::Pin, &format!("re-pin the table of {program}"));
    match config.rule_table() {
        Ok(old) => print_diff(&old, &compiled.rules),
        Err(error) => line("rules", format_args!("undecodable on chain ({error})")),
    }
    for (list_id, curator) in &compiled.shared_sources {
        line(
            list_name(*list_id),
            format_args!("curator {}", curator.program_id()),
        );
    }
    ui::warn("proofs built against the old table are refused from now on");
    if !yes {
        if !ctx.ask.interactive() {
            return Err(PolicyCommandError::NeedsConfirmation { program });
        }
        if !ctx.ask.confirm("replace the pinned table?", false)? {
            return Err(PolicyCommandError::Declined { program });
        }
    }
    let authority = ctx.config.upgrade_authority().map_err(ContextError::from)?;
    ctx.fund_authority(&authority, MIN_AUTHORITY_BALANCE)?;
    let instruction = SetPolicyRules {
        ring: ctx.ring,
        authority: authority.pubkey(),
        rules: &compiled.rules,
        shared_sources: compiled.shared_sources(),
    }
    .instruction()
    .map_err(|error| PolicyCommandError::Build(Box::new(error)))?;
    IdempotentStep {
        rpc: &ctx.rpc,
        authority: &authority,
        co_signers: &[],
        name: "set_policy_rules",
        compute_unit_limit: SET_POLICY_RULES_COMPUTE_UNIT_LIMIT,
        hint: no_hint,
    }
    .ensure_present(Observed::Absent, &[instruction])?;
    let after = pinned(ctx)?;
    line("policy", "replaced");
    line(
        "generation",
        format_args!("{} replaces {}", after.generation(), config.generation()),
    );
    Ok(())
}

fn print_diff(old: &RuleTable, new: &RuleTable) {
    for rule in old.rules() {
        if !new.rules().contains(rule) {
            line("removed", describe(rule));
        }
    }
    for rule in new.rules() {
        if !old.rules().contains(rule) {
            line("added", describe(rule));
        }
    }
    if old.inline_assets() != new.inline_assets() {
        line(
            "assets",
            format_args!("{} listed inline", new.inline_assets().len()),
        );
    }
}
