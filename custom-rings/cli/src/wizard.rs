//! The questions `new` asks, in order, through an `Ask`.

use std::{collections::BTreeSet, str::FromStr};

use solana_address::Address;
use thiserror::Error;
use zolana_client::SolanaRpc;
use zolana_interface::pda;
use zolana_transaction::SOL_MINT;

use crate::{
    catalogue::{discover, Catalogue},
    config::{Base58Address, Target, Urls},
    line,
    policy::{
        describe, Alternative, AssetLimitSpec, ListName, PolicyError, PolicySpec, RuleSpec,
        SourceSpec, SubjectName,
    },
    ui::{self, Ask, AskError, Icon, Pick, PickMany, Text},
};

pub trait Curators {
    fn catalogue(&mut self, target: Target, rpc_url: &str) -> Catalogue;
}

pub struct LiveCurators {
    /// A catalogue path or URL, `None` for the bundled file.
    pub source: Option<String>,
}

pub struct Wizard<'a> {
    pub ask: &'a mut dyn Ask,
    pub curators: &'a mut dyn Curators,
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

#[derive(Clone, Copy)]
struct AssetPreset {
    name: &'static str,
    mint: Address,
}

#[derive(Debug, Error)]
pub enum WizardError {
    #[error(transparent)]
    Ask(#[from] AskError),
    #[error(transparent)]
    Policy(#[from] PolicyError),
    #[error("{name} is not kebab-case, use lowercase letters, digits and dashes")]
    Name { name: String },
    #[error("{text} is not a base58 address")]
    Address { text: String },
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
const ASSET_PRESETS: [AssetPreset; 2] = [
    AssetPreset {
        name: "SOL",
        mint: SOL_MINT,
    },
    AssetPreset {
        name: "USDC",
        mint: Address::from_str_const("4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU"),
    },
];

pub fn check_name(name: &str) -> Result<(), String> {
    let mut chars = name.chars();
    let valid = matches!(chars.next(), Some('a'..='z'))
        && chars.all(|c| matches!(c, 'a'..='z' | '0'..='9' | '-'));
    if valid {
        Ok(())
    } else {
        Err("use lowercase letters, digits and dashes, a letter first".to_owned())
    }
}

fn check_url(text: &str) -> Result<(), String> {
    let rest = text
        .strip_prefix("http://")
        .or_else(|| text.strip_prefix("https://"))
        .ok_or_else(|| "a URL starts with http:// or https://".to_owned())?;
    if rest.split(['/', '?']).next().unwrap_or_default().is_empty() {
        return Err("a URL names a host".to_owned());
    }
    Ok(())
}

fn check_address(text: &str) -> Result<(), String> {
    Address::from_str(text)
        .map(drop)
        .map_err(|_| "not a base58 address".to_owned())
}

fn check_amount(text: &str) -> Result<(), String> {
    if text.is_empty() {
        return Ok(());
    }
    match text.parse::<u64>() {
        Ok(amount) if amount != 0 && i64::try_from(amount).is_ok() => Ok(()),
        _ => Err(format!(
            "a positive whole number of base units up to {}",
            i64::MAX
        )),
    }
}

fn check_mints(text: &str) -> Result<(), String> {
    let mut mints = text.split(',').map(str::trim).peekable();
    if mints.peek().is_none_or(|mint| mint.is_empty()) {
        return Err("name at least one mint".to_owned());
    }
    mints.try_for_each(check_address)
}

fn parse_address(text: &str) -> Result<Address, WizardError> {
    Address::from_str(text).map_err(|_| WizardError::Address {
        text: text.to_owned(),
    })
}

fn labels<T: ToString>(items: impl IntoIterator<Item = T>) -> Vec<String> {
    items.into_iter().map(|item| item.to_string()).collect()
}

fn asset_presets(target: Target) -> &'static [AssetPreset] {
    match target {
        Target::Localnet => &ASSET_PRESETS[..1],
        Target::Devnet => &ASSET_PRESETS,
    }
}

fn asset_options(presets: &[AssetPreset], other: &str) -> Vec<String> {
    presets
        .iter()
        .map(|preset| preset.name.to_owned())
        .chain(std::iter::once(other.to_owned()))
        .collect()
}

/// The rows alone, a source no row reads yet is not a refusal mid-loop.
fn rows_only(spec: &PolicySpec) -> PolicySpec {
    PolicySpec {
        sources: Default::default(),
        ..spec.clone()
    }
}

impl Curators for LiveCurators {
    fn catalogue(&mut self, target: Target, rpc_url: &str) -> Catalogue {
        let source = match self.source.as_deref() {
            None => "the bundled catalogue".to_owned(),
            Some(source) if source.starts_with("http://") || source.starts_with("https://") => {
                crate::config::redact_url(source)
            }
            Some(source) => source.to_owned(),
        };
        ui::hint(format!("loading curator definitions from {source}"));
        let mut catalogue = match Catalogue::load(self.source.as_deref()) {
            Ok(catalogue) => {
                line("catalogue", "loaded");
                catalogue
            }
            Err(error) => {
                let error = error.to_string();
                let error = self.source.as_deref().map_or_else(
                    || error.clone(),
                    |location| error.replace(location, &source),
                );
                ui::warn(format!("the catalogue is unreadable, {error}"));
                Catalogue::default()
            }
        };
        let display_rpc_url = crate::config::redact_url(rpc_url);
        ui::hint(format!(
            "discovering policy rings on {} through {display_rpc_url}",
            target.as_str()
        ));
        match discover(&SolanaRpc::new(rpc_url.to_owned())) {
            Ok(found) => {
                let count = found.len();
                catalogue.merge(target, found);
                let rings = match count {
                    0 => "no policy rings".to_owned(),
                    1 => "1 policy ring".to_owned(),
                    _ => format!("{count} policy rings"),
                };
                line("discovered", rings);
            }
            Err(_) => ui::warn(format!(
                "ring discovery failed through {display_rpc_url}. Catalogue and manual choices remain"
            )),
        }
        catalogue
    }
}

impl Wizard<'_> {
    /// A supplied policy skips every policy question.
    pub fn run(
        mut self,
        name: Option<String>,
        preset: Option<PolicySpec>,
    ) -> Result<Answers, WizardError> {
        let name = match name {
            Some(name) => {
                check_name(&name).map_err(|_| WizardError::Name { name: name.clone() })?;
                name
            }
            None => self.text("ring name", None, false, &check_name)?,
        };
        ui::heading(Icon::Wizard, "clusters");
        let localnet = self.urls("localnet", self.localnet.clone())?;
        let devnet = self.urls("devnet", self.devnet.clone())?;
        ui::heading(Icon::Wizard, "target");
        let target = self.target()?;
        let policy = match preset {
            Some(policy) => Some(policy),
            None => {
                let rpc_url = match target {
                    Target::Localnet => localnet.rpc.clone(),
                    Target::Devnet => devnet.rpc.clone(),
                };
                self.policy(target, &rpc_url)?
            }
        };
        Ok(Answers {
            name,
            target,
            localnet,
            devnet,
            policy,
        })
    }

    fn text(
        &mut self,
        prompt: &str,
        default: Option<String>,
        empty: bool,
        check: &dyn Fn(&str) -> Result<(), String>,
    ) -> Result<String, WizardError> {
        Ok(self.ask.text(Text {
            prompt,
            default,
            empty,
            check,
        })?)
    }

    fn pick(
        &mut self,
        prompt: &str,
        items: &[String],
        default: usize,
    ) -> Result<usize, WizardError> {
        Ok(self.ask.pick(Pick {
            prompt,
            items,
            default,
        })?)
    }

    fn pick_many(&mut self, prompt: &str, items: &[String]) -> Result<Vec<usize>, WizardError> {
        Ok(self.ask.pick_many(PickMany { prompt, items })?)
    }

    fn urls(&mut self, cluster: &str, defaults: Urls) -> Result<Urls, WizardError> {
        let url = |wizard: &mut Self, service: &str, default: String| {
            wizard.text(
                &format!("{cluster} {service} URL"),
                Some(default),
                false,
                &check_url,
            )
        };
        let rpc = url(self, "Solana RPC", defaults.rpc)?;
        let indexer = url(self, "Photon indexer", defaults.indexer)?;
        let prover = url(self, "prover", defaults.prover)?;
        let ring_rpc = url(self, "ring RPC", defaults.ring_rpc)?;
        let ring_rpc_pubkey = match defaults.ring_rpc_pubkey {
            Some(key) => self
                .ask
                .confirm(
                    &format!("{cluster} ring RPC service key {key}, accept no other key?"),
                    true,
                )?
                .then_some(key),
            None => None,
        };
        Ok(Urls {
            rpc,
            indexer,
            prover,
            ring_rpc,
            ring_rpc_pubkey,
        })
    }

    fn target(&mut self) -> Result<Target, WizardError> {
        let picked = self.pick("target", &labels(Target::ALL.map(Target::as_str)), 0)?;
        Ok(Target::ALL[picked])
    }

    fn policy(&mut self, target: Target, rpc_url: &str) -> Result<Option<PolicySpec>, WizardError> {
        let mut spec = PolicySpec {
            entries_tree: Some(Base58Address(pda::tree(0))),
            ..Default::default()
        };
        ui::heading(Icon::Policy, "policy options");
        ui::hint("pick no option for an audit-only ring");
        let options = labels(POLICY_OPTIONS);
        loop {
            let option = self.pick("policy option", &options, options.len() - 1)?;
            let rules = match option {
                0 => Some(participant_allowlist()),
                1 => Some(vec![simple_rule(
                    SubjectName::OutputOwner,
                    SourceSpec::Forbid(named_list("block")),
                )]),
                2 => Some(vec![simple_rule(
                    SubjectName::Sender,
                    SourceSpec::Forbid(named_list("frozen")),
                )]),
                3 => Some(vec![simple_rule(
                    SubjectName::Asset,
                    SourceSpec::Forbid(named_list("block")),
                )]),
                4 => Some(vec![self.asset_rule(target, false)?]),
                5 => Some(vec![simple_rule(
                    SubjectName::OutputOwner,
                    SourceSpec::Any(vec![
                        Alternative::Require(named_list("approval")),
                        Alternative::Forbid(named_list("block")),
                    ]),
                )]),
                6 => Some(vec![RuleSpec {
                    subject: SubjectName::OutputOwner,
                    source: SourceSpec::Require(named_list("allow")),
                    above: None,
                    limits: Some(self.asset_limits(target)?),
                }]),
                7 => self.advanced_rule(target, &spec)?,
                8 => {
                    self.remove(&mut spec, target)?;
                    continue;
                }
                9 if spec.rules.is_empty() => return Ok(Some(spec)),
                9 => {
                    ui::refusal("the policy already has rules, choose finish");
                    continue;
                }
                _ => {
                    if spec.rules.is_empty() {
                        return Ok(None);
                    }
                    self.configure_sources(&mut spec, target, rpc_url)?;
                    spec.compile(target)?;
                    return Ok(Some(spec));
                }
            };
            let Some(rules) = rules else {
                ui::hint("the rule was discarded");
                continue;
            };
            self.add_rules(&mut spec, target, rules);
        }
    }

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

    fn configure_sources(
        &mut self,
        spec: &mut PolicySpec,
        target: Target,
        rpc_url: &str,
    ) -> Result<(), WizardError> {
        let referenced: BTreeSet<ListName> = spec
            .rules
            .iter()
            .flat_map(|rule| rule.source.lists())
            .collect();
        if referenced.is_empty() {
            return Ok(());
        }
        ui::heading(Icon::Lists, "list entry sources");
        let tree = spec.entries_tree();
        line("tree", tree);
        ui::hint("a discovered curator is offered only when it serves the list from this tree");
        let catalogue = self.curators.catalogue(target, rpc_url);
        for list in referenced {
            if let Some(curator) = self.source(target, list, tree, &catalogue)? {
                spec.sources
                    .get_mut(target)
                    .insert(list, Base58Address(curator));
            }
        }
        Ok(())
    }

    fn source(
        &mut self,
        target: Target,
        list: ListName,
        tree: Address,
        catalogue: &Catalogue,
    ) -> Result<Option<Address>, WizardError> {
        let curated: Vec<(String, Address)> = catalogue
            .serving(target, list, tree)
            .map(|(name, curator)| {
                let program = curator.program.0;
                let label = if name == program.to_string() {
                    format!("curator {program} manages the entries")
                } else {
                    format!("curator {name} ({program}) manages the entries")
                };
                (label, program)
            })
            .collect();
        let mut items = vec![OWN_ENTRIES.to_owned()];
        items.extend(curated.iter().map(|(label, _)| label.clone()));
        items.push(ANOTHER_CURATOR.to_owned());
        let picked = self.pick(&format!("who manages the {list} list entries?"), &items, 0)?;
        if picked == 0 {
            return Ok(None);
        }
        if let Some((_, program)) = curated.get(picked - 1) {
            return Ok(Some(*program));
        }
        let text = self.text("curator program id", None, false, &check_address)?;
        Ok(Some(parse_address(&text)?))
    }

    /// A removal that leaves the table refused is undone.
    fn remove(&mut self, spec: &mut PolicySpec, target: Target) -> Result<(), WizardError> {
        if spec.rules.is_empty() {
            ui::refusal("no rule to remove");
            return Ok(());
        }
        let rows = spec.rows()?;
        let sentences: Vec<String> = rows.rules.iter().map(describe).collect();
        let items: Vec<String> = sentences
            .iter()
            .enumerate()
            .map(|(index, sentence)| format!("{} {sentence}", index + 1))
            .collect();
        let picked = self.pick("remove a rule", &items, 0)?;
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

    fn advanced_rule(
        &mut self,
        target: Target,
        spec: &PolicySpec,
    ) -> Result<Option<Vec<RuleSpec>>, WizardError> {
        let kinds = labels(ADVANCED_SOURCES);
        let source = self.pick("rule source", &kinds, kinds.len() - 1)?;
        if source == kinds.len() - 1 {
            return Ok(None);
        }
        if source == 3 {
            return Ok(Some(vec![self.asset_rule(target, true)?]));
        }
        let subject = self.subject()?;
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

    fn either_or(&mut self) -> Result<Option<SourceSpec>, WizardError> {
        let kinds = labels(ALTERNATIVE_KINDS);
        let mut alternatives = Vec::new();
        loop {
            let kind = self.pick("alternative", &kinds, kinds.len() - 2)?;
            match kind {
                2 if alternatives.is_empty() => {
                    ui::refusal("an either-or rule needs one alternative, discard it instead");
                    continue;
                }
                2 => break,
                3 => return Ok(None),
                _ => {}
            }
            let list = self.list()?;
            alternatives.push(if kind == 0 {
                Alternative::Require(list)
            } else {
                Alternative::Forbid(list)
            });
        }
        Ok(Some(SourceSpec::Any(alternatives)))
    }

    fn mint(&mut self, target: Target) -> Result<Base58Address, WizardError> {
        let presets = asset_presets(target);
        let options = asset_options(presets, OTHER_MINT);
        let picked = self.pick("mint", &options, 0)?;
        if let Some(preset) = presets.get(picked) {
            return Ok(Base58Address(preset.mint));
        }
        let text = self.text("mint address", None, false, &check_address)?;
        Ok(Base58Address(parse_address(&text)?))
    }

    fn mints(&mut self, target: Target) -> Result<Vec<Base58Address>, WizardError> {
        let presets = asset_presets(target);
        let options = asset_options(presets, OTHER_MINTS);
        loop {
            let picked = self.pick_many("assets", &options)?;
            if picked.is_empty() {
                ui::refusal("select at least one asset");
                continue;
            }
            let mut mints: Vec<Base58Address> = picked
                .iter()
                .filter_map(|index| presets.get(*index))
                .map(|preset| Base58Address(preset.mint))
                .collect();
            if picked.contains(&presets.len()) {
                let text =
                    self.text("mint addresses, comma separated", None, false, &check_mints)?;
                for mint in text.split(',').map(str::trim) {
                    let mint = Base58Address(parse_address(mint)?);
                    if !mints.contains(&mint) {
                        mints.push(mint);
                    }
                }
            }
            return Ok(mints);
        }
    }

    fn asset_rule(&mut self, target: Target, ask_guard: bool) -> Result<RuleSpec, WizardError> {
        let mints = self.mints(target)?;
        let above = if ask_guard && self.pick("amount guard", &labels(OPTIONAL_GUARDS), 0)? == 1 {
            Some(self.amount("amount threshold")?)
        } else {
            None
        };
        Ok(RuleSpec {
            subject: SubjectName::Asset,
            source: SourceSpec::Assets(mints),
            above,
            limits: None,
        })
    }

    fn subject(&mut self) -> Result<SubjectName, WizardError> {
        let picked = self.pick("subject", &labels(SubjectName::ALL), 0)?;
        Ok(SubjectName::ALL[picked])
    }

    fn list(&mut self) -> Result<ListName, WizardError> {
        let picked = self.pick("list", &labels(ListName::ALL), 0)?;
        Ok(ListName::ALL[picked])
    }

    fn guard(
        &mut self,
        target: Target,
        spec: &PolicySpec,
        mut rule: RuleSpec,
    ) -> Result<Vec<RuleSpec>, WizardError> {
        if rule.subject == SubjectName::Sender {
            return Ok(vec![rule]);
        }
        let guards = if rule.subject == SubjectName::OutputOwner {
            &OWNER_GUARDS[..]
        } else {
            &OPTIONAL_GUARDS[..]
        };
        match self.pick("amount guard", &labels(guards), 0)? {
            0 => Ok(vec![rule]),
            1 => {
                rule.above = Some(self.amount("amount threshold")?);
                if rule.subject != SubjectName::OutputOwner {
                    return Ok(vec![rule]);
                }
                let mint = self.mint(target)?;
                let dependency = simple_rule(SubjectName::Asset, SourceSpec::Assets(vec![mint]));
                let already_present = spec.rules.iter().any(|present| present == &dependency);
                if already_present {
                    Ok(vec![rule])
                } else {
                    Ok(vec![dependency, rule])
                }
            }
            _ => {
                rule.limits = Some(self.asset_limits(target)?);
                Ok(vec![rule])
            }
        }
    }

    fn amount(&mut self, prompt: &str) -> Result<u64, WizardError> {
        let text = self.text(prompt, None, false, &check_amount)?;
        Ok(text.parse().expect("a checked amount"))
    }

    fn asset_limits(&mut self, target: Target) -> Result<Vec<AssetLimitSpec>, WizardError> {
        let mut limits = Vec::new();
        loop {
            let asset = loop {
                let asset = self.mint(target)?;
                if limits
                    .iter()
                    .any(|limit: &AssetLimitSpec| limit.asset == asset)
                {
                    ui::refusal("that mint already has a limit");
                    continue;
                }
                break asset;
            };
            let above = self.amount("amount limit")?;
            limits.push(AssetLimitSpec { asset, above });
            if limits.len() == 8 {
                ui::hint("the policy uses all 8 inline asset slots");
                break;
            }
            if !self.ask.confirm("add another mint limit?", false)? {
                break;
            }
        }
        Ok(limits)
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

fn participant_allowlist() -> Vec<RuleSpec> {
    vec![
        simple_rule(
            SubjectName::Sender,
            SourceSpec::Require(named_list("allow")),
        ),
        simple_rule(
            SubjectName::OutputOwner,
            SourceSpec::Require(named_list("allow")),
        ),
        simple_rule(
            SubjectName::Sender,
            SourceSpec::Forbid(named_list("frozen")),
        ),
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
        }
    }

    /// A catalogue serving Block from `CURATOR` on the default tree of both clusters.
    pub(crate) struct Fixed;

    impl Curators for Fixed {
        fn catalogue(&mut self, target: Target, _rpc_url: &str) -> Catalogue {
            let mut catalogue = Catalogue::default();
            catalogue.merge(
                target,
                [Curator {
                    program: Base58Address(CURATOR),
                    lists: vec!["block".parse().expect("list")],
                    entries_tree: Base58Address(pda::tree(0)),
                }],
            );
            catalogue
        }
    }

    /// The URL answers every run shares, defaults accepted.
    fn cluster_answers() -> Vec<Answer> {
        ["", "", "", ""]
            .iter()
            .chain(["", "", "", ""].iter())
            .map(|text| Answer::from(*text))
            .collect()
    }

    pub(crate) fn run(answers: Vec<Answer>) -> Result<Answers, WizardError> {
        let mut ask = Scripted::new(answers);
        let mut curators = Fixed;
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
        assert_eq!(policy.entries_tree, Some(Base58Address(pda::tree(0))));
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
        assert_eq!(compiled.entries_tree, pda::tree(0));
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
        let mut curators = Fixed;
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
        let mut curators = Fixed;
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
        let mut curators = Fixed;
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
        assert!(matches!(
            run(vec![]).map(|_| ()),
            Err(WizardError::Ask(AskError::NoAnswer { .. }))
        ));
        let mut ask = Scripted::new([]);
        let mut curators = Fixed;
        assert!(matches!(
            Wizard {
                ask: &mut ask,
                curators: &mut curators,
                localnet: urls(1),
                devnet: urls(2),
            }
            .run(Some("Bad Name".to_owned()), None),
            Err(WizardError::Name { name }) if name == "Bad Name"
        ));
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
