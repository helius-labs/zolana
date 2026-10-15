//! The questions `new` asks, in order, through an `Ask`.

use std::{collections::BTreeSet, str::FromStr};

use anyhow::{bail, Result};
use solana_address::Address;
use zolana_client::SolanaRpc;
use zolana_interface::pda;
use zolana_transaction::SOL_MINT;

use crate::{
    catalogue::{discover, Catalogue},
    config::{redact_url, Base58Address, Target, Urls},
    line,
    policy::{
        describe, Alternative, AssetLimitSpec, ListName, PolicySpec, RuleSpec, SourceSpec,
        SubjectName,
    },
    ui::{self, icon, Ask},
};

/// The curator catalogue of a cluster, read through its RPC URL.
pub type Curators<'a> = &'a mut dyn FnMut(Target, &str) -> Catalogue;

pub struct Wizard<'a> {
    pub ask: &'a mut dyn Ask,
    pub curators: Curators<'a>,
    pub localnet: Urls,
    pub devnet: Urls,
}

pub struct Answers {
    pub name: String,
    pub target: Target,
    pub localnet: Urls,
    pub devnet: Urls,
    pub policy: Option<PolicySpec>,
}

const POLICY_OPTIONS: [&str; 11] = [
    "participant allowlist",
    "recipient blocklist",
    "sender freeze",
    "token blocklist",
    "asset allowlist",
    "blocklist with approval exception",
    "per-mint recipient limits",
    "advanced rule",
    "remove",
    "configure policy later",
    "finish",
];
const ADVANCED_SOURCES: [&str; 5] = [
    "require a list",
    "forbid a list",
    "either-or lists",
    "inline asset allowlist",
    "discard",
];
const ALTERNATIVE_KINDS: [&str; 4] = ["require", "forbid", "done", "discard"];
const OPTIONAL_GUARDS: [&str; 2] = ["always", "above an amount"];
const OWNER_GUARDS: [&str; 3] = ["always", "above an amount", "above per-mint amounts"];
const OWN_ENTRIES: &str = "this ring manages the entries";
const ANOTHER_CURATOR: &str = "another curator manages the entries";
const OTHER_MINT: &str = "another mint address";
const OTHER_MINTS: &str = "other mint addresses";
const DEVNET_USDC: Address =
    Address::from_str_const("4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU");
/// Localnet offers only SOL, USDC is a devnet mint.
const ASSET_PRESETS: [(&str, Address); 2] = [("SOL", SOL_MINT), ("USDC", DEVNET_USDC)];

pub fn check_name(name: &str) -> Result<(), String> {
    let mut chars = name.chars();
    match chars.next() {
        Some('a'..='z') if chars.all(|c| matches!(c, 'a'..='z' | '0'..='9' | '-')) => Ok(()),
        _ => Err("use lowercase letters, digits and dashes, a letter first".to_owned()),
    }
}

fn check_url(text: &str) -> Result<(), String> {
    let rest = text
        .strip_prefix("http://")
        .or_else(|| text.strip_prefix("https://"));
    match rest.map(|rest| rest.split(['/', '?']).next().unwrap_or_default()) {
        None => Err("a URL starts with http:// or https://".to_owned()),
        Some("") => Err("a URL names a host".to_owned()),
        Some(_) => Ok(()),
    }
}

fn check_address(text: &str) -> Result<(), String> {
    Address::from_str(text)
        .map(drop)
        .map_err(|_| "not a base58 address".to_owned())
}

/// Below `i64::MAX`, the largest integer a toml file holds.
fn check_amount(text: &str) -> Result<(), String> {
    match text.parse::<i64>() {
        _ if text.is_empty() => Ok(()),
        Ok(amount) if amount > 0 => Ok(()),
        _ => Err(format!(
            "a positive whole number of base units up to {}",
            i64::MAX
        )),
    }
}

fn check_mints(text: &str) -> Result<(), String> {
    if text.split(',').next().unwrap_or_default().trim().is_empty() {
        return Err("name at least one mint".to_owned());
    }
    text.split(',').map(str::trim).try_for_each(check_address)
}

fn labels<T: ToString>(items: impl IntoIterator<Item = T>) -> Vec<String> {
    items.into_iter().map(|item| item.to_string()).collect()
}

fn asset_presets(target: Target, other: &str) -> (&'static [(&'static str, Address)], Vec<String>) {
    let presets = &ASSET_PRESETS[..if target == Target::Devnet { 2 } else { 1 }];
    let options = labels(presets.iter().map(|(name, _)| *name).chain([other]));
    (presets, options)
}

/// The rows alone, a source no row reads yet is not a refusal mid-loop.
fn rows_only(spec: &PolicySpec) -> PolicySpec {
    PolicySpec {
        sources: Default::default(),
        ..spec.clone()
    }
}

/// `source` is a catalogue path or URL, `None` for the bundled file. A failure only warns.
pub fn live_catalogue(source: Option<&str>, target: Target, rpc_url: &str) -> Catalogue {
    let shown = match source {
        None => "the bundled catalogue".to_owned(),
        Some(url) if url.starts_with("http://") || url.starts_with("https://") => redact_url(url),
        Some(path) => path.to_owned(),
    };
    ui::hint(format!("loading curator definitions from {shown}"));
    let mut catalogue = match Catalogue::load(source) {
        Ok(catalogue) => {
            line("catalogue", "loaded");
            catalogue
        }
        Err(error) => {
            let error = error.to_string();
            let error = source.map_or(error.clone(), |location| error.replace(location, &shown));
            ui::warn(format!("the catalogue is unreadable, {error}"));
            Catalogue::default()
        }
    };
    let rpc = redact_url(rpc_url);
    ui::hint(format!(
        "discovering policy rings on {target} through {rpc}"
    ));
    match discover(&SolanaRpc::new(rpc_url.to_owned())) {
        Ok(found) => {
            let rings = match found.len() {
                0 => "no policy rings".to_owned(),
                1 => "1 policy ring".to_owned(),
                count => format!("{count} policy rings"),
            };
            line("discovered", rings);
            catalogue.merge(target, found);
        }
        Err(_) => ui::warn(format!(
            "ring discovery failed through {rpc}. Catalogue and manual choices remain"
        )),
    }
    catalogue
}

impl Wizard<'_> {
    /// A supplied policy skips every policy question.
    pub fn run(mut self, name: Option<String>, preset: Option<PolicySpec>) -> Result<Answers> {
        let name = match name {
            Some(name) if check_name(&name).is_err() => {
                bail!("{name} is not kebab-case, use lowercase letters, digits and dashes")
            }
            Some(name) => name,
            None => self.ask.text("ring name", None, false, &check_name)?,
        };
        ui::heading(icon::WIZARD, "clusters");
        let localnet = self.urls("localnet", self.localnet.clone())?;
        let devnet = self.urls("devnet", self.devnet.clone())?;
        ui::heading(icon::WIZARD, "target");
        let target = Target::ALL[self.ask.pick("target", &labels(Target::ALL), 0)?];
        let rpc_url = match target {
            Target::Localnet => &localnet.rpc,
            Target::Devnet => &devnet.rpc,
        };
        let policy = match preset {
            Some(policy) => Some(policy),
            None => self.policy(target, rpc_url)?,
        };
        Ok(Answers {
            name,
            target,
            localnet,
            devnet,
            policy,
        })
    }

    fn urls(&mut self, cluster: &str, defaults: Urls) -> Result<Urls> {
        let mut url = |service: &str, default: String| {
            let prompt = format!("{cluster} {service} URL");
            self.ask.text(&prompt, Some(default), false, &check_url)
        };
        Ok(Urls {
            rpc: url("Solana RPC", defaults.rpc)?,
            indexer: url("Photon indexer", defaults.indexer)?,
            prover: url("prover", defaults.prover)?,
            ring_rpc: url("ring RPC", defaults.ring_rpc)?,
            ring_rpc_pubkey: match defaults.ring_rpc_pubkey {
                Some(key) => {
                    let prompt =
                        format!("{cluster} ring RPC service key {key}, accept no other key?");
                    self.ask.confirm(&prompt, true)?.then_some(key)
                }
                None => None,
            },
            prover_tee: None,
        })
    }

    fn policy(&mut self, target: Target, rpc_url: &str) -> Result<Option<PolicySpec>> {
        let mut spec = PolicySpec {
            address_tree: Some(Base58Address(pda::tree(0))),
            ..Default::default()
        };
        ui::heading(icon::POLICY, "policy options");
        ui::hint("pick no option for an audit-only ring");
        let options = labels(POLICY_OPTIONS);
        loop {
            let picked = self
                .ask
                .pick("policy option", &options, options.len() - 1)?;
            let rules = match POLICY_OPTIONS[picked] {
                "participant allowlist" => Some(participant_allowlist()),
                "recipient blocklist" => Some(vec![forbid(SubjectName::OutputOwner, "block")]),
                "sender freeze" => Some(vec![forbid(SubjectName::Sender, "frozen")]),
                "token blocklist" => Some(vec![forbid(SubjectName::Asset, "block")]),
                "asset allowlist" => Some(vec![self.asset_rule(target, false)?]),
                "blocklist with approval exception" => Some(vec![simple_rule(
                    SubjectName::OutputOwner,
                    SourceSpec::Any(vec![
                        Alternative::Require(named_list("approval")),
                        Alternative::Forbid(named_list("block")),
                    ]),
                )]),
                "per-mint recipient limits" => Some(vec![RuleSpec {
                    limits: Some(self.asset_limits(target)?),
                    ..require(SubjectName::OutputOwner, "allow")
                }]),
                "advanced rule" => self.advanced(target, &spec)?,
                "remove" => {
                    self.remove(&mut spec, target)?;
                    continue;
                }
                "configure policy later" if spec.rules.is_empty() => return Ok(Some(spec)),
                "configure policy later" => {
                    ui::refusal("the policy already has rules, choose finish");
                    continue;
                }
                _ if spec.rules.is_empty() => return Ok(None),
                _ => {
                    self.sources(&mut spec, target, rpc_url)?;
                    spec.compile(target)?;
                    return Ok(Some(spec));
                }
            };
            match rules {
                Some(rules) => self.add_rules(&mut spec, target, rules),
                None => ui::hint("the rule was discarded"),
            }
        }
    }

    /// An option whose rows the table refuses is not taken at all.
    fn add_rules(&self, spec: &mut PolicySpec, target: Target, rules: Vec<RuleSpec>) {
        let first = spec.rules.len();
        let mut candidate = spec.clone();
        candidate.rules.extend(rules);
        match rows_only(&candidate).compile(target) {
            Ok(policy) => {
                for (offset, row) in policy.rules.rules()[first..].iter().enumerate() {
                    line(&format!("rule {}", first + offset + 1), describe(row));
                }
                *spec = candidate;
            }
            Err(error) => ui::refusal(error),
        }
    }

    /// Each list the rows read is served by the ring itself or by a curator.
    fn sources(&mut self, spec: &mut PolicySpec, target: Target, rpc_url: &str) -> Result<()> {
        let referenced: BTreeSet<ListName> = spec
            .rules
            .iter()
            .flat_map(|rule| rule.source.lists())
            .collect();
        if referenced.is_empty() {
            return Ok(());
        }
        ui::heading(icon::LISTS, "list entry sources");
        let tree = spec.address_tree();
        line("tree", tree);
        ui::hint("a discovered curator is offered only when it serves the list and pins this tree");
        let catalogue = (self.curators)(target, rpc_url);
        for list in referenced {
            let curated: Vec<(String, Base58Address)> = catalogue
                .serving(target, list, tree)
                .map(|(name, curator)| {
                    let program = curator.program;
                    let named = match name == program.to_string() {
                        true => name.to_owned(),
                        false => format!("{name} ({program})"),
                    };
                    (format!("curator {named} manages the entries"), program)
                })
                .collect();
            let items = labels(
                [OWN_ENTRIES]
                    .into_iter()
                    .chain(curated.iter().map(|(label, _)| label.as_str()))
                    .chain([ANOTHER_CURATOR]),
            );
            let prompt = format!("who manages the {list} list entries?");
            let curator = match self.ask.pick(&prompt, &items, 0)? {
                0 => continue,
                picked if picked <= curated.len() => curated[picked - 1].1,
                _ => self
                    .ask
                    .text("curator program id", None, false, &check_address)?
                    .parse()?,
            };
            spec.sources.get_mut(target).insert(list, curator);
        }
        Ok(())
    }

    /// A removal that leaves the table refused is undone.
    fn remove(&mut self, spec: &mut PolicySpec, target: Target) -> Result<()> {
        if spec.rules.is_empty() {
            ui::refusal("no rule to remove");
            return Ok(());
        }
        let sentences: Vec<String> = spec.rows()?.rules.iter().map(describe).collect();
        let items = labels(
            (1..)
                .zip(&sentences)
                .map(|(index, sentence)| format!("{index} {sentence}")),
        );
        let picked = self.ask.pick("remove a rule", &items, 0)?;
        let removed = spec.rules.remove(picked);
        match rows_only(spec).compile(target) {
            Ok(_) => line("removed", &sentences[picked]),
            Err(error) => {
                ui::refusal(error);
                spec.rules.insert(picked, removed);
            }
        }
        Ok(())
    }

    fn advanced(&mut self, target: Target, spec: &PolicySpec) -> Result<Option<Vec<RuleSpec>>> {
        let kinds = labels(ADVANCED_SOURCES);
        let source = match self.ask.pick("rule source", &kinds, kinds.len() - 1)? {
            4 => return Ok(None),
            3 => return Ok(Some(vec![self.asset_rule(target, true)?])),
            source => source,
        };
        let subject = SubjectName::ALL[self.ask.pick("subject", &labels(SubjectName::ALL), 0)?];
        let source = match source {
            0 => SourceSpec::Require(self.list()?),
            1 => SourceSpec::Forbid(self.list()?),
            _ => match self.either_or()? {
                Some(source) => source,
                None => return Ok(None),
            },
        };
        self.guard(target, spec, simple_rule(subject, source))
            .map(Some)
    }

    fn either_or(&mut self) -> Result<Option<SourceSpec>> {
        let kinds = labels(ALTERNATIVE_KINDS);
        let mut alternatives = Vec::new();
        loop {
            let alternative = match self.ask.pick("alternative", &kinds, kinds.len() - 2)? {
                2 if alternatives.is_empty() => {
                    ui::refusal("an either-or rule needs one alternative, discard it instead");
                    continue;
                }
                2 => return Ok(Some(SourceSpec::Any(alternatives))),
                3 => return Ok(None),
                0 => Alternative::Require(self.list()?),
                _ => Alternative::Forbid(self.list()?),
            };
            alternatives.push(alternative);
        }
    }

    fn mint(&mut self, target: Target) -> Result<Base58Address> {
        let (presets, options) = asset_presets(target, OTHER_MINT);
        let picked = self.ask.pick("mint", &options, 0)?;
        if let Some((_, mint)) = presets.get(picked) {
            return Ok(Base58Address(*mint));
        }
        Ok(self
            .ask
            .text("mint address", None, false, &check_address)?
            .parse()?)
    }

    fn mints(&mut self, target: Target) -> Result<Vec<Base58Address>> {
        let (presets, options) = asset_presets(target, OTHER_MINTS);
        let picked = loop {
            match self.ask.pick_many("assets", &options)? {
                picked if picked.is_empty() => ui::refusal("select at least one asset"),
                picked => break picked,
            }
        };
        let mut mints: Vec<Base58Address> = picked
            .iter()
            .filter_map(|index| presets.get(*index))
            .map(|(_, mint)| Base58Address(*mint))
            .collect();
        if picked.contains(&presets.len()) {
            let prompt = "mint addresses, comma separated";
            for text in self.ask.text(prompt, None, false, &check_mints)?.split(',') {
                let mint = text.trim().parse()?;
                if !mints.contains(&mint) {
                    mints.push(mint);
                }
            }
        }
        Ok(mints)
    }

    fn asset_rule(&mut self, target: Target, ask_guard: bool) -> Result<RuleSpec> {
        let mints = self.mints(target)?;
        let guarded = ask_guard && self.ask.pick("amount guard", &labels(OPTIONAL_GUARDS), 0)? == 1;
        Ok(RuleSpec {
            above: guarded
                .then(|| self.amount("amount threshold"))
                .transpose()?,
            ..simple_rule(SubjectName::Asset, SourceSpec::Assets(mints))
        })
    }

    fn list(&mut self) -> Result<ListName> {
        Ok(ListName::ALL[self.ask.pick("list", &labels(ListName::ALL), 0)?])
    }

    /// An owner threshold reads its asset from the inline map, so that row comes first.
    fn guard(
        &mut self,
        target: Target,
        spec: &PolicySpec,
        mut rule: RuleSpec,
    ) -> Result<Vec<RuleSpec>> {
        let guards = match rule.subject {
            SubjectName::Sender => return Ok(vec![rule]),
            SubjectName::OutputOwner => &OWNER_GUARDS[..],
            SubjectName::Asset => &OPTIONAL_GUARDS[..],
        };
        match self.ask.pick("amount guard", &labels(guards), 0)? {
            0 => {}
            1 => {
                rule.above = Some(self.amount("amount threshold")?);
                if rule.subject == SubjectName::OutputOwner {
                    let mint = self.mint(target)?;
                    let dependency =
                        simple_rule(SubjectName::Asset, SourceSpec::Assets(vec![mint]));
                    if !spec.rules.contains(&dependency) {
                        return Ok(vec![dependency, rule]);
                    }
                }
            }
            _ => rule.limits = Some(self.asset_limits(target)?),
        }
        Ok(vec![rule])
    }

    fn amount(&mut self, prompt: &str) -> Result<u64> {
        Ok(self.ask.text(prompt, None, false, &check_amount)?.parse()?)
    }

    fn asset_limits(&mut self, target: Target) -> Result<Vec<AssetLimitSpec>> {
        let mut limits: Vec<AssetLimitSpec> = Vec::new();
        loop {
            let asset = self.mint(target)?;
            if limits.iter().any(|limit| limit.asset == asset) {
                ui::refusal("that mint already has a limit");
                continue;
            }
            let above = self.amount("amount limit")?;
            limits.push(AssetLimitSpec { asset, above });
            if limits.len() == 8 {
                ui::hint("the policy uses all 8 inline asset slots");
                return Ok(limits);
            }
            if !self.ask.confirm("add another mint limit?", false)? {
                return Ok(limits);
            }
        }
    }
}

fn named_list(name: &str) -> ListName {
    name.parse().expect("a built-in authority-written list")
}

fn simple_rule(subject: SubjectName, source: SourceSpec) -> RuleSpec {
    RuleSpec {
        subject,
        source,
        above: None,
        limits: None,
    }
}

fn require(subject: SubjectName, list: &str) -> RuleSpec {
    simple_rule(subject, SourceSpec::Require(named_list(list)))
}

fn forbid(subject: SubjectName, list: &str) -> RuleSpec {
    simple_rule(subject, SourceSpec::Forbid(named_list(list)))
}

fn participant_allowlist() -> Vec<RuleSpec> {
    vec![
        require(SubjectName::Sender, "allow"),
        require(SubjectName::OutputOwner, "allow"),
        forbid(SubjectName::Sender, "frozen"),
    ]
}

#[cfg(test)]
pub(crate) mod tests {
    use zolana_ring_policy::{ListId, ListSet, Rule, RuleTable, Subject};

    use super::*;
    use crate::{
        catalogue::Curator,
        ui::{Answer, Scripted},
    };

    pub(crate) const CURATOR: Address = Address::new_from_array([7u8; 32]);
    pub(crate) const MINT: &str = "So11111111111111111111111111111111111111112";

    pub(crate) fn urls(port: u16) -> Urls {
        Urls {
            rpc: format!("http://127.0.0.1:{port}"),
            indexer: "http://127.0.0.1:8784".to_owned(),
            prover: "http://127.0.0.1:3001".to_owned(),
            ring_rpc: "http://127.0.0.1:8785".to_owned(),
            ring_rpc_pubkey: None,
            prover_tee: None,
        }
    }

    /// A catalogue serving Block from `CURATOR` on the default tree of both clusters.
    pub(crate) fn fixed(target: Target, _rpc_url: &str) -> Catalogue {
        let mut catalogue = Catalogue::default();
        catalogue.merge(
            target,
            [Curator {
                program: Base58Address(CURATOR),
                lists: vec!["block".parse().expect("list")],
                address_tree: Base58Address(pda::tree(0)),
            }],
        );
        catalogue
    }

    /// The URL answers every run shares, defaults accepted.
    fn cluster_answers() -> Vec<Answer> {
        ["", "", "", ""]
            .iter()
            .chain(["", "", "", ""].iter())
            .map(|text| Answer::from(*text))
            .collect()
    }

    pub(crate) fn run(answers: Vec<Answer>) -> Result<Answers> {
        let mut ask = Scripted::new(answers);
        let mut curators = fixed;
        let answers = Wizard {
            ask: &mut ask,
            curators: &mut curators,
            localnet: urls(8899),
            devnet: Urls {
                ring_rpc_pubkey: Some(CURATOR.to_string()),
                ..urls(8999)
            },
        }
        .run(Some("demo".to_owned()), None)?;
        assert!(ask.is_drained(), "every scripted answer was consumed");
        Ok(answers)
    }

    fn script(policy: &[Answer]) -> Vec<Answer> {
        script_for(Target::Localnet, policy)
    }

    fn script_for(target: Target, policy: &[Answer]) -> Vec<Answer> {
        let mut answers = cluster_answers();
        answers.push(Answer::Yes(true));
        answers.push(Answer::from(target.as_str()));
        answers.extend_from_slice(policy);
        answers
    }

    #[test]
    fn devnet_usdc_uses_its_cluster_mint_and_deduplicates_manual_entries() {
        let usdc = "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU";
        let manual = format!("{usdc},{MINT}");
        let answers = run(script_for(
            Target::Devnet,
            &[
                Answer::from("asset allowlist"),
                Answer::from(["SOL", "USDC", OTHER_MINTS]),
                Answer::from(manual.as_str()),
                Answer::from("finish"),
            ],
        ))
        .expect("wizard");
        let policy = answers.policy.expect("policy");
        assert_eq!(
            policy.rules[0].source,
            SourceSpec::Assets(vec![
                Base58Address(SOL_MINT),
                Base58Address(usdc.parse().expect("devnet USDC")),
                Base58Address(MINT.parse().expect("manual mint")),
            ])
        );
        policy.compile(Target::Devnet).expect("compiles");
        assert!(
            run(script(&[
                Answer::from("asset allowlist"),
                Answer::from(["USDC"]),
            ]))
            .is_err(),
            "local mint addresses must be supplied"
        );
    }

    #[test]
    fn devnet_per_mint_limits_use_the_selected_cluster() {
        let answers = run(script_for(
            Target::Devnet,
            &[
                Answer::from("per-mint recipient limits"),
                Answer::from("USDC"),
                Answer::from("1000000"),
                Answer::Yes(false),
                Answer::from("finish"),
                Answer::from(OWN_ENTRIES),
            ],
        ))
        .expect("wizard");
        let policy = answers.policy.expect("policy");
        assert_eq!(
            policy.rules[0].limits.as_ref().expect("limits")[0].asset,
            Base58Address(
                "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU"
                    .parse()
                    .expect("devnet USDC")
            )
        );
        policy.compile(Target::Devnet).expect("compiles");
    }

    #[test]
    fn an_audit_only_ring_records_no_policy() {
        let answers = run(script(&[Answer::from("finish")])).expect("wizard");
        assert_eq!(answers.name, "demo");
        assert_eq!(answers.target, Target::Localnet);
        assert!(answers.policy.is_none());
        assert_eq!(
            answers.devnet.ring_rpc_pubkey.as_deref(),
            Some(CURATOR.to_string().as_str())
        );
    }

    #[test]
    fn configure_later_records_an_empty_policy_and_the_default_tree() {
        let answers = run(script(&[Answer::from("configure policy later")])).expect("wizard");
        let policy = answers.policy.expect("policy tier");
        assert!(policy.rules.is_empty());
        assert_eq!(policy.address_tree, Some(Base58Address(pda::tree(0))));
    }

    #[test]
    fn a_recipient_blocklist_uses_own_entries() {
        let answers = run(script(&[
            Answer::from("recipient blocklist"),
            Answer::from("finish"),
            Answer::from(OWN_ENTRIES),
        ]))
        .expect("wizard");
        let policy = answers.policy.expect("policy tier");
        assert!(policy.sources.is_empty());
        let compiled = policy.compile(Target::Localnet).expect("compiles");
        assert_eq!(
            compiled.rules,
            RuleTable::builder()
                .rule(Rule::forbid(Subject::OutputOwner, ListId::Block))
                .build()
        );
        assert_eq!(compiled.address_tree, pda::tree(0));
    }

    #[test]
    fn the_approval_exception_asks_only_for_the_lists_it_reads() {
        let answers = run(script(&[
            Answer::from("blocklist with approval exception"),
            Answer::from("finish"),
            Answer::from(&*format!("curator {CURATOR} manages the entries")),
            Answer::from(OWN_ENTRIES),
        ]))
        .expect("wizard");
        let policy = answers.policy.expect("policy tier");
        let compiled = policy.compile(Target::Localnet).expect("compiles");
        assert_eq!(
            compiled.rules.rules(),
            [Rule::any_of(
                Subject::OutputOwner,
                ListSet::single(ListId::Approval),
                ListSet::single(ListId::Block)
            )]
        );
        assert_eq!(
            compiled.shared_sources,
            vec![(ListId::Block, custom_ring_sdk::CustomRing::new(CURATOR))]
        );
        assert!(policy.sources.get(Target::Devnet).is_empty());
    }

    #[test]
    fn the_participant_allowlist_matches_the_shipped_example() {
        let answers = run(script(&[
            Answer::from("participant allowlist"),
            Answer::from("finish"),
            Answer::from(OWN_ENTRIES),
            Answer::from(OWN_ENTRIES),
        ]))
        .expect("wizard");
        let policy = answers.policy.expect("policy tier");
        assert_eq!(policy.rules, participant_allowlist());
        assert!(policy.sources.is_empty());
    }

    #[test]
    fn per_mint_recipient_limits_collect_repeated_pairs() {
        let answers = run(script(&[
            Answer::from("per-mint recipient limits"),
            Answer::from("SOL"),
            Answer::from("1000000000"),
            Answer::Yes(true),
            Answer::from(OTHER_MINT),
            Answer::from(MINT),
            Answer::from("1000000"),
            Answer::Yes(false),
            Answer::from("finish"),
            Answer::from(OWN_ENTRIES),
        ]))
        .expect("wizard");
        let policy = answers.policy.expect("policy tier");
        let compiled = policy.compile(Target::Localnet).expect("compiles");
        assert_eq!(compiled.rules.inline_assets().len(), 2);
        assert_eq!(compiled.rules.inline_limits(), [1_000_000_000, 1_000_000]);
    }

    #[test]
    fn an_advanced_owner_threshold_adds_its_asset_rule_atomically() {
        let answers = run(script(&[
            Answer::from("advanced rule"),
            Answer::from("require a list"),
            Answer::from("output-owner"),
            Answer::from("allow"),
            Answer::from("above an amount"),
            Answer::from("1000000"),
            Answer::from(OTHER_MINT),
            Answer::from(MINT),
            Answer::from("finish"),
            Answer::from(OWN_ENTRIES),
        ]))
        .expect("wizard");
        let policy = answers.policy.expect("policy tier");
        let compiled = policy.compile(Target::Localnet).expect("compiles");
        assert_eq!(compiled.rules.rules().len(), 2);
        assert_eq!(compiled.rules.inline_assets().len(), 1);
    }

    #[test]
    fn advanced_rules_cover_either_or_and_per_mint_guards() {
        let answers = run(script(&[
            Answer::from("advanced rule"),
            Answer::from("either-or lists"),
            Answer::from("output-owner"),
            Answer::from("require"),
            Answer::from("approval"),
            Answer::from("forbid"),
            Answer::from("block"),
            Answer::from("done"),
            Answer::from("above per-mint amounts"),
            Answer::from(OTHER_MINT),
            Answer::from(MINT),
            Answer::from("5"),
            Answer::Yes(false),
            Answer::from("finish"),
            Answer::from(OWN_ENTRIES),
            Answer::from(OWN_ENTRIES),
        ]))
        .expect("wizard");
        let policy = answers.policy.expect("policy tier");
        let compiled = policy.compile(Target::Localnet).expect("compiles");
        assert_eq!(compiled.rules.rules().len(), 1);
        assert_eq!(compiled.rules.inline_limits(), [5]);
    }

    #[test]
    fn an_advanced_inline_asset_rule_can_carry_a_scalar_guard() {
        let answers = run(script(&[
            Answer::from("advanced rule"),
            Answer::from("inline asset allowlist"),
            Answer::from(["SOL", OTHER_MINTS]),
            Answer::from(MINT),
            Answer::from("above an amount"),
            Answer::from("7"),
            Answer::from("finish"),
        ]))
        .expect("wizard");
        let policy = answers.policy.expect("policy tier");
        assert_eq!(policy.rules[0].above, Some(7));
        let SourceSpec::Assets(mints) = &policy.rules[0].source else {
            panic!("inline assets");
        };
        assert_eq!(
            mints.as_slice(),
            &[
                Base58Address(SOL_MINT),
                Base58Address(MINT.parse().expect("mint"))
            ]
        );
        policy.compile(Target::Localnet).expect("compiles");
    }

    #[test]
    fn removal_cannot_strand_an_owner_threshold_dependency() {
        let answers = run(script(&[
            Answer::from("advanced rule"),
            Answer::from("require a list"),
            Answer::from("output-owner"),
            Answer::from("allow"),
            Answer::from("above an amount"),
            Answer::from("1000000"),
            Answer::from(OTHER_MINT),
            Answer::from(MINT),
            Answer::from("remove"),
            Answer::from("1 each asset must be one of the listed assets"),
            Answer::from("remove"),
            Answer::from(
                "2 each output owner must be on the allow list when the amount is above 1000000",
            ),
            Answer::from("finish"),
        ]))
        .expect("wizard");
        let policy = answers.policy.expect("policy tier");
        assert_eq!(
            policy.rules.len(),
            1,
            "the guard row went, the asset row it needs stayed"
        );
        assert!(matches!(policy.rules[0].source, SourceSpec::Assets(_)));
    }

    #[test]
    fn a_ninth_inline_asset_is_refused_without_selecting_the_policy_tier() {
        let mints = (1..=9)
            .map(|byte| Address::new_from_array([byte; 32]).to_string())
            .collect::<Vec<_>>()
            .join(",");
        let answers = run(script(&[
            Answer::from("asset allowlist"),
            Answer::from([OTHER_MINTS]),
            Answer::from(mints.as_str()),
            Answer::from("finish"),
        ]))
        .expect("wizard");
        assert!(
            answers.policy.is_none(),
            "the refused option was not retained"
        );
    }

    #[test]
    fn answer_slot_exhaustion_refuses_the_whole_added_option() {
        let mut ask = Scripted::new([]);
        let mut curators = fixed;
        let wizard = Wizard {
            ask: &mut ask,
            curators: &mut curators,
            localnet: urls(1),
            devnet: urls(2),
        };
        let mut spec = PolicySpec::default();
        wizard.add_rules(
            &mut spec,
            Target::Localnet,
            vec![
                simple_rule(
                    SubjectName::OutputOwner,
                    SourceSpec::Forbid(named_list("block")),
                ),
                simple_rule(SubjectName::Asset, SourceSpec::Forbid(named_list("block"))),
                simple_rule(
                    SubjectName::Sender,
                    SourceSpec::Forbid(named_list("frozen")),
                ),
                simple_rule(
                    SubjectName::Sender,
                    SourceSpec::Require(named_list("allow")),
                ),
            ],
        );
        assert_eq!(spec.rules.len(), 4, "the table uses all 10 answer slots");
        wizard.add_rules(
            &mut spec,
            Target::Localnet,
            vec![simple_rule(
                SubjectName::Sender,
                SourceSpec::Require(named_list("approval")),
            )],
        );
        assert_eq!(spec.rules.len(), 4, "the eleventh answer was refused");
    }

    #[test]
    fn repeated_limit_pairs_stop_at_eight_and_refuse_duplicate_mints() {
        let addresses: Vec<String> = (1..=8)
            .map(|byte| Address::new_from_array([byte; 32]).to_string())
            .collect();
        let mut answers = Vec::new();
        for (index, address) in addresses.iter().enumerate() {
            answers.push(Answer::from(OTHER_MINT));
            answers.push(Answer::from(address.as_str()));
            answers.push(Answer::from("1"));
            if index < 7 {
                answers.push(Answer::Yes(true));
            }
        }
        let mut ask = Scripted::new(answers);
        let mut curators = fixed;
        let limits = Wizard {
            ask: &mut ask,
            curators: &mut curators,
            localnet: urls(1),
            devnet: urls(2),
        }
        .asset_limits(Target::Localnet)
        .expect("limits");
        assert_eq!(limits.len(), 8);
        assert!(ask.is_drained(), "an eighth pair does not ask for another");

        let mut ask = Scripted::new([
            Answer::from(OTHER_MINT),
            Answer::from(MINT),
            Answer::from("1"),
            Answer::Yes(true),
            Answer::from(OTHER_MINT),
            Answer::from(MINT),
            Answer::from(OTHER_MINT),
            Answer::from(CURATOR.to_string().as_str()),
            Answer::from("2"),
            Answer::Yes(false),
        ]);
        let limits = Wizard {
            ask: &mut ask,
            curators: &mut curators,
            localnet: urls(1),
            devnet: urls(2),
        }
        .asset_limits(Target::Localnet)
        .expect("limits");
        assert_eq!(limits.len(), 2);
        assert_ne!(limits[0].asset, limits[1].asset);
        assert!(ask.is_drained());
    }

    #[test]
    fn a_supplied_policy_skips_policy_questions() {
        let preset = PolicySpec::default();
        let mut ask = Scripted::new(script(&[]));
        let mut curators = fixed;
        let answers = Wizard {
            ask: &mut ask,
            curators: &mut curators,
            localnet: urls(8899),
            devnet: Urls {
                ring_rpc_pubkey: Some(CURATOR.to_string()),
                ..urls(8999)
            },
        }
        .run(Some("demo".to_owned()), Some(preset.clone()))
        .expect("wizard");
        assert!(ask.is_drained());
        assert_eq!(answers.policy, Some(preset));
    }

    #[test]
    fn names_are_kebab_case() {
        for name in ["a", "my-ring", "ring-2"] {
            check_name(name).expect(name);
        }
        for name in ["", "My-Ring", "9ring", "-ring", "a/b", "a_b", "a b"] {
            assert!(check_name(name).is_err(), "{name}");
        }
        let unanswered = run(vec![]).map(|_| ()).expect_err("no answers");
        assert!(unanswered
            .to_string()
            .starts_with("no scripted answer for localnet Solana RPC URL"));
        let mut ask = Scripted::new([]);
        let mut curators = fixed;
        let refused = Wizard {
            ask: &mut ask,
            curators: &mut curators,
            localnet: urls(1),
            devnet: urls(2),
        }
        .run(Some("Bad Name".to_owned()), None)
        .map(|_| ())
        .expect_err("not kebab-case");
        assert!(refused
            .to_string()
            .starts_with("Bad Name is not kebab-case"));
    }

    #[test]
    fn answers_are_checked_before_they_are_taken() {
        assert!(check_url("http://127.0.0.1:8899").is_ok());
        assert!(check_url("https://api.devnet.solana.com").is_ok());
        assert!(check_url("127.0.0.1:8899").is_err());
        assert!(check_url("http:///path").is_err());
        assert!(check_amount("").is_ok());
        assert!(check_amount("10").is_ok());
        assert!(check_amount("0").is_err());
        assert!(check_amount("-1").is_err());
        assert!(check_amount(&u64::MAX.to_string()).is_err());
        assert!(check_mints(&format!("{MINT}, {CURATOR}")).is_ok());
        assert!(check_mints("").is_err());
        assert!(check_mints(&format!("{MINT},")).is_err());
    }
}
