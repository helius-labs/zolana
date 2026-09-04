//! The questions `new` asks, in order, through an `Ask`.

use std::str::FromStr;

use solana_address::Address;
use thiserror::Error;
use zolana_client::SolanaRpc;
use zolana_interface::pda;

use crate::{
    catalogue::{discover, Catalogue},
    config::{Base58Address, Target, Urls},
    line,
    policy::{
        describe, Alternative, ListName, PolicyError, PolicySpec, RuleSpec, SourceSpec, SubjectName,
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

const RULE_KINDS: [&str; 6] = [
    "require",
    "forbid",
    "either-or",
    "inline assets",
    "remove",
    "finish",
];
const ALTERNATIVE_KINDS: [&str; 4] = ["require", "forbid", "done", "discard"];
const OWN_ENTRIES: &str = "own entries";
const ANOTHER_CURATOR: &str = "another curator";

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
        Ok(amount) if i64::try_from(amount).is_ok() => Ok(()),
        _ => Err(format!("a whole number of base units up to {}", i64::MAX)),
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

/// The rows alone, a source no row reads yet is not a refusal mid-loop.
fn rows_only(spec: &PolicySpec) -> PolicySpec {
    PolicySpec {
        sources: Default::default(),
        ..spec.clone()
    }
}

impl Curators for LiveCurators {
    fn catalogue(&mut self, target: Target, rpc_url: &str) -> Catalogue {
        let mut catalogue = match Catalogue::load(self.source.as_deref()) {
            Ok(catalogue) => catalogue,
            Err(error) => {
                ui::warn(format!("the catalogue is unreadable, {error}"));
                Catalogue::default()
            }
        };
        match discover(&SolanaRpc::new(rpc_url.to_owned())) {
            Ok(found) => catalogue.merge(target, found),
            Err(error) => ui::warn(format!(
                "no rings discovered at {rpc_url}, {}, the catalogue and manual entry remain",
                crate::config::redact_text(&error.to_string())
            )),
        }
        catalogue
    }
}

impl Wizard<'_> {
    /// A preset policy skips the tier and every policy question.
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
                ui::heading(Icon::Wizard, "tier");
                if self.pick("tier", &labels(["audit only", "policy"]), 0)? == 1 {
                    let rpc_url = match target {
                        Target::Localnet => localnet.rpc.clone(),
                        Target::Devnet => devnet.rpc.clone(),
                    };
                    Some(self.policy(target, &rpc_url)?)
                } else {
                    None
                }
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

    fn policy(&mut self, target: Target, rpc_url: &str) -> Result<PolicySpec, WizardError> {
        ui::heading(Icon::Tree, "entries tree");
        let tree = self.text(
            "entries tree",
            Some(pda::tree(0).to_string()),
            false,
            &check_address,
        )?;
        let entries_tree = parse_address(&tree)?;
        ui::heading(Icon::Lists, "lists");
        ui::hint("the lists the rules read, none for an empty table");
        let names = labels(ListName::ALL);
        let picked = self.ask.pick_many(PickMany {
            prompt: "lists",
            items: &names,
        })?;
        let lists: Vec<ListName> = picked
            .into_iter()
            .map(|index| ListName::ALL[index])
            .collect();
        let mut spec = PolicySpec {
            entries_tree: Some(Base58Address(entries_tree)),
            ..Default::default()
        };
        if !lists.is_empty() {
            let catalogue = self.curators.catalogue(target, rpc_url);
            for list in &lists {
                if let Some(curator) = self.source(target, *list, entries_tree, &catalogue)? {
                    spec.sources
                        .get_mut(target)
                        .insert(*list, Base58Address(curator));
                }
            }
        }
        ui::heading(Icon::Policy, "rules");
        ui::hint("every rule must hold, each is checked as soon as it is added");
        self.rules(&mut spec, target, &lists)?;
        Ok(spec)
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
            .map(|(name, curator)| (format!("curator {name}"), curator.program.0))
            .collect();
        let mut items = vec![OWN_ENTRIES.to_owned()];
        items.extend(curated.iter().map(|(label, _)| label.clone()));
        items.push(ANOTHER_CURATOR.to_owned());
        let picked = self.pick(&format!("{list} entries"), &items, 0)?;
        if picked == 0 {
            return Ok(None);
        }
        if let Some((_, program)) = curated.get(picked - 1) {
            return Ok(Some(*program));
        }
        let text = self.text("curator program id", None, false, &check_address)?;
        Ok(Some(parse_address(&text)?))
    }

    fn rules(
        &mut self,
        spec: &mut PolicySpec,
        target: Target,
        lists: &[ListName],
    ) -> Result<(), WizardError> {
        let kinds = labels(RULE_KINDS);
        loop {
            let kind = self.pick("rule", &kinds, kinds.len() - 1)?;
            let rule = match kind {
                0..=2 if lists.is_empty() => {
                    ui::refusal("no list was picked, only an inline asset rule can be added");
                    continue;
                }
                0 => Some(self.single(lists, SourceSpec::Require)?),
                1 => Some(self.single(lists, SourceSpec::Forbid)?),
                2 => self.either_or(lists)?,
                3 => Some(self.assets()?),
                4 => {
                    self.remove(spec, target)?;
                    continue;
                }
                _ => {
                    if self.finish(spec, target)? {
                        return Ok(());
                    }
                    continue;
                }
            };
            let Some(rule) = rule else {
                ui::hint("the rule was discarded");
                continue;
            };
            spec.rules.push(rule);
            match rows_only(spec).compile(target) {
                Ok(policy) => {
                    let index = spec.rules.len();
                    if let Some(row) = policy.rules.rules().last() {
                        line(&format!("rule {index}"), describe(row));
                    }
                }
                Err(error) => {
                    ui::refusal(error);
                    spec.rules.pop();
                }
            }
        }
    }

    /// A removal that leaves the table refused is undone.
    fn remove(&mut self, spec: &mut PolicySpec, target: Target) -> Result<(), WizardError> {
        if spec.rules.is_empty() {
            ui::refusal("no rule to remove");
            return Ok(());
        }
        let (rows, _) = spec.rows()?;
        let sentences: Vec<String> = rows.iter().map(describe).collect();
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

    /// `true` once the sources are consistent, `false` sends the operator back to the loop.
    fn finish(&mut self, spec: &mut PolicySpec, target: Target) -> Result<bool, WizardError> {
        loop {
            match spec.compile(target) {
                Ok(_) => return Ok(true),
                Err(PolicyError::UnreferencedSource { list, .. }) => {
                    ui::refusal(format!("the {list} source serves no rule"));
                    if self
                        .ask
                        .confirm(&format!("drop the {list} source?"), true)?
                    {
                        spec.sources.get_mut(target).remove(&list);
                    } else {
                        return Ok(false);
                    }
                }
                Err(error) => {
                    ui::refusal(error);
                    return Ok(false);
                }
            }
        }
    }

    fn single(
        &mut self,
        lists: &[ListName],
        form: fn(ListName) -> SourceSpec,
    ) -> Result<RuleSpec, WizardError> {
        let subject = self.subject()?;
        let list = self.list(lists)?;
        let above = self.threshold(subject)?;
        Ok(RuleSpec {
            subject,
            source: form(list),
            above,
        })
    }

    /// `None` when the operator discards the rule under construction.
    fn either_or(&mut self, lists: &[ListName]) -> Result<Option<RuleSpec>, WizardError> {
        let subject = self.subject()?;
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
            let list = self.list(lists)?;
            alternatives.push(if kind == 0 {
                Alternative::Require(list)
            } else {
                Alternative::Forbid(list)
            });
        }
        let above = self.threshold(subject)?;
        Ok(Some(RuleSpec {
            subject,
            source: SourceSpec::Any(alternatives),
            above,
        }))
    }

    fn assets(&mut self) -> Result<RuleSpec, WizardError> {
        let text = self.text("mint addresses, comma separated", None, false, &check_mints)?;
        let mints = text
            .split(',')
            .map(|mint| parse_address(mint.trim()).map(Base58Address))
            .collect::<Result<Vec<_>, _>>()?;
        let above = self.threshold(SubjectName::Asset)?;
        Ok(RuleSpec {
            subject: SubjectName::Asset,
            source: SourceSpec::Assets(mints),
            above,
        })
    }

    fn subject(&mut self) -> Result<SubjectName, WizardError> {
        let picked = self.pick("subject", &labels(SubjectName::ALL), 0)?;
        Ok(SubjectName::ALL[picked])
    }

    fn list(&mut self, lists: &[ListName]) -> Result<ListName, WizardError> {
        let picked = self.pick("list", &labels(lists.iter().copied()), 0)?;
        Ok(lists[picked])
    }

    /// A sender has no output amount, the question is skipped for it.
    fn threshold(&mut self, subject: SubjectName) -> Result<Option<u64>, WizardError> {
        if matches!(subject, SubjectName::Sender) {
            return Ok(None);
        }
        let text = self.text(
            "amount threshold, empty for none",
            None,
            true,
            &check_amount,
        )?;
        if text.is_empty() {
            return Ok(None);
        }
        Ok(text.parse().ok())
    }
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
        let mut answers = cluster_answers();
        answers.push(Answer::Yes(true));
        answers.push(Answer::from("localnet"));
        answers.extend_from_slice(policy);
        answers
    }

    #[test]
    fn an_audit_only_ring_records_no_policy() {
        let answers = run(script(&[Answer::from("audit only")])).expect("wizard");
        assert_eq!(answers.name, "demo");
        assert_eq!(answers.target, Target::Localnet);
        assert!(answers.policy.is_none());
        assert_eq!(
            answers.devnet.ring_rpc_pubkey.as_deref(),
            Some(CURATOR.to_string().as_str())
        );
    }

    #[test]
    fn a_ring_with_its_own_blocklist_compiles_one_forbid_row() {
        let answers = run(script(&[
            Answer::from("policy"),
            Answer::from(""),
            Answer::from(["block"]),
            Answer::from("own entries"),
            Answer::from("forbid"),
            Answer::from("output-owner"),
            Answer::from("block"),
            Answer::from(""),
            Answer::from("finish"),
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
    fn a_curated_block_with_an_approval_alternative_records_the_curator_source() {
        let answers = run(script(&[
            Answer::from("policy"),
            Answer::from(""),
            Answer::from(["block", "approval"]),
            Answer::from(&*format!("curator {CURATOR}")),
            Answer::from("own entries"),
            Answer::from("either-or"),
            Answer::from("output-owner"),
            Answer::from("forbid"),
            Answer::from("block"),
            Answer::from("require"),
            Answer::from("approval"),
            Answer::from("done"),
            Answer::from(""),
            Answer::from("finish"),
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
    fn a_refused_rule_is_dropped_and_corrected_in_the_loop() {
        let answers = run(script(&[
            Answer::from("policy"),
            Answer::from(""),
            Answer::from(["allow"]),
            Answer::from("own entries"),
            Answer::from("require"),
            Answer::from("output-owner"),
            Answer::from("allow"),
            Answer::from("5"),
            Answer::from("require"),
            Answer::from("output-owner"),
            Answer::from("allow"),
            Answer::from(""),
            Answer::from("finish"),
        ]))
        .expect("wizard");
        let policy = answers.policy.expect("policy tier");
        assert_eq!(
            policy.rules.len(),
            1,
            "the guarded row was refused and dropped"
        );
        assert_eq!(policy.rules[0].above, None);
    }

    #[test]
    fn an_unreferenced_curated_source_is_refused_until_dropped_or_referenced() {
        let dropped = run(script(&[
            Answer::from("policy"),
            Answer::from(""),
            Answer::from(["block", "frozen"]),
            Answer::from(&*format!("curator {CURATOR}")),
            Answer::from("own entries"),
            Answer::from("forbid"),
            Answer::from("sender"),
            Answer::from("frozen"),
            Answer::from("finish"),
            Answer::Yes(true),
        ]))
        .expect("wizard");
        let policy = dropped.policy.expect("policy tier");
        assert!(policy.sources.is_empty(), "the block source was dropped");
        let referenced = run(script(&[
            Answer::from("policy"),
            Answer::from(""),
            Answer::from(["block", "frozen"]),
            Answer::from(&*format!("curator {CURATOR}")),
            Answer::from("own entries"),
            Answer::from("forbid"),
            Answer::from("sender"),
            Answer::from("frozen"),
            Answer::from("finish"),
            Answer::Yes(false),
            Answer::from("forbid"),
            Answer::from("output-owner"),
            Answer::from("block"),
            Answer::from(""),
            Answer::from("finish"),
        ]))
        .expect("wizard");
        let policy = referenced.policy.expect("policy tier");
        assert_eq!(policy.sources.get(Target::Localnet).len(), 1);
        assert_eq!(policy.rules.len(), 2);
    }

    #[test]
    fn an_asset_allowlist_with_an_owner_threshold_compiles() {
        let answers = run(script(&[
            Answer::from("policy"),
            Answer::from(""),
            Answer::from(["allow"]),
            Answer::from("own entries"),
            Answer::from("inline assets"),
            Answer::from(MINT),
            Answer::from(""),
            Answer::from("require"),
            Answer::from("output-owner"),
            Answer::from("allow"),
            Answer::from("1000000"),
            Answer::from("finish"),
        ]))
        .expect("wizard");
        let policy = answers.policy.expect("policy tier");
        let compiled = policy.compile(Target::Localnet).expect("compiles");
        assert_eq!(compiled.rules.rules().len(), 2);
        assert_eq!(compiled.rules.inline_assets().len(), 1);
    }

    #[test]
    fn an_either_or_rule_can_be_discarded_before_it_is_added() {
        let answers = run(script(&[
            Answer::from("policy"),
            Answer::from(""),
            Answer::from(["allow"]),
            Answer::from("own entries"),
            Answer::from("either-or"),
            Answer::from("output-owner"),
            Answer::from("done"),
            Answer::from("discard"),
            Answer::from("require"),
            Answer::from("output-owner"),
            Answer::from("allow"),
            Answer::from(""),
            Answer::from("finish"),
        ]))
        .expect("wizard");
        let policy = answers.policy.expect("policy tier");
        assert_eq!(
            policy.rules.len(),
            1,
            "done without an alternative is refused, discard drops the rule"
        );
        assert!(matches!(policy.rules[0].source, SourceSpec::Require(_)));
    }

    #[test]
    fn a_rule_can_be_removed_unless_the_table_would_be_refused() {
        let answers = run(script(&[
            Answer::from("policy"),
            Answer::from(""),
            Answer::from(["allow"]),
            Answer::from("own entries"),
            Answer::from("remove"),
            Answer::from("inline assets"),
            Answer::from(MINT),
            Answer::from(""),
            Answer::from("require"),
            Answer::from("output-owner"),
            Answer::from("allow"),
            Answer::from("1000000"),
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
    fn a_preset_policy_skips_the_tier_and_policy_questions() {
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
        assert!(check_amount("-1").is_err());
        assert!(check_amount(&u64::MAX.to_string()).is_err());
        assert!(check_mints(&format!("{MINT}, {CURATOR}")).is_ok());
        assert!(check_mints("").is_err());
        assert!(check_mints(&format!("{MINT},")).is_err());
    }
}
