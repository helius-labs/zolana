//! The `[policy]` table of `ring.toml` and its compilation to the pinned rule table.

use std::{collections::BTreeMap, fmt, str::FromStr};

use custom_ring_sdk::CustomRing;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use solana_address::Address;
use thiserror::Error;
use zolana_interface::DEFAULT_TREE_ADDRESS;
use zolana_ring_policy::{
    Guard, ListId, ListSet, Member, MemberError, Mode, Rule, RuleSource, RuleTable, RuleTableError,
    Subject, Writer, MAX_INLINE_ASSETS, MAX_RULES,
};

use crate::config::{Base58Address, PerCluster, Target};

#[derive(Clone, Debug, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PolicySpec {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub entries_tree: Option<Base58Address>,
    /// Curator program ids by list name, an absent list reads the ring's own entries.
    #[serde(default, skip_serializing_if = "PerCluster::is_empty")]
    pub sources: PerCluster<Sources>,
    /// Every rule must hold, in row order.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub rules: Vec<RuleSpec>,
}

pub type Sources = BTreeMap<ListName, Base58Address>;

/// Exactly one of `require`, `forbid`, `any` or `assets` beside the subject.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(try_from = "RawRule", into = "RawRule")]
pub struct RuleSpec {
    pub subject: SubjectName,
    pub source: SourceSpec,
    pub above: Option<u64>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SourceSpec {
    Require(ListName),
    Forbid(ListName),
    Any(Vec<Alternative>),
    Assets(Vec<Base58Address>),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(try_from = "RawAlternative", into = "RawAlternative")]
pub enum Alternative {
    Require(ListName),
    Forbid(ListName),
}

/// An authority-written list, spelled as in `ring.toml` and on the command line.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ListName(ListId);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SubjectName {
    OutputOwner,
    Sender,
    Asset,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CompiledPolicy {
    pub rules: RuleTable,
    pub entries_tree: Address,
    pub shared_sources: Vec<(ListId, CustomRing)>,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum PolicyError {
    #[error("unknown list {name}")]
    UnknownList { name: String },
    #[error("the {name} list is written by its members, a rule cannot read it")]
    MemberWrittenList { name: String },
    #[error("unknown subject {name}")]
    UnknownSubject { name: String },
    #[error("a rule names no source, give one of require, forbid, any or assets")]
    NoSourceForm,
    #[error("a rule names several sources, give one of require, forbid, any or assets")]
    SeveralSourceForms,
    #[error("any names no alternative")]
    EmptyAny,
    #[error("{count} rules exceed the {MAX_RULES} rows of the table")]
    TooManyRules { count: usize },
    #[error("{count} inline assets exceed the {MAX_INLINE_ASSETS} slots of the table")]
    TooManyAssets { count: usize },
    #[error("the {} source {list} serves no rule", cluster.as_str())]
    UnreferencedSource { list: ListName, cluster: Target },
    #[error("rule {} takes no amount guard, a sender has no output amount", rule + 1)]
    SenderGuard { rule: usize },
    #[error("rule {} threshold {amount} exceeds what a toml integer holds", rule + 1)]
    ThresholdTooLarge { rule: usize, amount: u64 },
    #[error("rule {} asset {mint} derives no member", rule + 1)]
    Asset {
        rule: usize,
        mint: Address,
        #[source]
        source: MemberError,
    },
    #[error("rule {} is refused, {message}", rule + 1)]
    Refused { rule: usize, message: &'static str },
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct RawRule {
    subject: SubjectName,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    require: Option<ListName>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    forbid: Option<ListName>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    any: Option<Vec<Alternative>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    assets: Option<Vec<Base58Address>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    above: Option<u64>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct RawAlternative {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    require: Option<ListName>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    forbid: Option<ListName>,
}

/// Lowercase kebab-case, the one spelling of every list.
pub const fn list_name(list_id: ListId) -> &'static str {
    match list_id {
        ListId::Allow => "allow",
        ListId::Block => "block",
        ListId::Frozen => "frozen",
        ListId::RingViewing => "ring-viewing",
        ListId::Recovery => "recovery",
        ListId::Reader => "reader",
        ListId::Approval => "approval",
        ListId::Escrow => "escrow",
    }
}

const fn authority_written(list_id: ListId) -> bool {
    matches!(list_id.writer(), Writer::Authority)
}

const fn authority_written_count() -> usize {
    let mut count = 0;
    let mut i = 0;
    while i < ListId::ALL.len() {
        if authority_written(ListId::ALL[i]) {
            count += 1;
        }
        i += 1;
    }
    count
}

impl ListName {
    /// In `ListId::ALL` order.
    pub const ALL: [Self; authority_written_count()] = {
        let mut all = [Self(ListId::Allow); authority_written_count()];
        let mut filled = 0;
        let mut i = 0;
        while i < ListId::ALL.len() {
            if authority_written(ListId::ALL[i]) {
                all[filled] = Self(ListId::ALL[i]);
                filled += 1;
            }
            i += 1;
        }
        all
    };

    pub const fn id(self) -> ListId {
        self.0
    }

    pub const fn as_str(self) -> &'static str {
        list_name(self.0)
    }

    pub fn of(list_id: ListId) -> Result<Self, PolicyError> {
        if authority_written(list_id) {
            Ok(Self(list_id))
        } else {
            Err(PolicyError::MemberWrittenList {
                name: list_name(list_id).to_owned(),
            })
        }
    }
}

impl PartialOrd for ListName {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for ListName {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.0.slot().cmp(&other.0.slot())
    }
}

impl FromStr for ListName {
    type Err = PolicyError;

    fn from_str(name: &str) -> Result<Self, PolicyError> {
        let list_id = ListId::ALL
            .into_iter()
            .find(|list_id| list_name(*list_id) == name)
            .ok_or_else(|| PolicyError::UnknownList {
                name: name.to_owned(),
            })?;
        Self::of(list_id)
    }
}

impl fmt::Display for ListName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for ListName {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        String::deserialize(deserializer)?
            .parse()
            .map_err(serde::de::Error::custom)
    }
}

impl Serialize for ListName {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

impl clap::ValueEnum for ListName {
    fn value_variants<'a>() -> &'a [Self] {
        &Self::ALL
    }

    fn to_possible_value(&self) -> Option<clap::builder::PossibleValue> {
        Some(clap::builder::PossibleValue::new(self.as_str()))
    }
}

impl SubjectName {
    pub const ALL: [Self; 3] = [Self::OutputOwner, Self::Sender, Self::Asset];

    pub const fn subject(self) -> Subject {
        match self {
            Self::OutputOwner => Subject::OutputOwner,
            Self::Sender => Subject::Sender,
            Self::Asset => Subject::Asset,
        }
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::OutputOwner => "output-owner",
            Self::Sender => "sender",
            Self::Asset => "asset",
        }
    }
}

impl FromStr for SubjectName {
    type Err = PolicyError;

    fn from_str(name: &str) -> Result<Self, PolicyError> {
        Self::ALL
            .into_iter()
            .find(|subject| subject.as_str() == name)
            .ok_or_else(|| PolicyError::UnknownSubject {
                name: name.to_owned(),
            })
    }
}

impl fmt::Display for SubjectName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for SubjectName {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        String::deserialize(deserializer)?
            .parse()
            .map_err(serde::de::Error::custom)
    }
}

impl Serialize for SubjectName {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

impl TryFrom<RawRule> for RuleSpec {
    type Error = PolicyError;

    fn try_from(raw: RawRule) -> Result<Self, PolicyError> {
        let forms = [
            raw.require.map(SourceSpec::Require),
            raw.forbid.map(SourceSpec::Forbid),
            raw.any.map(SourceSpec::Any),
            raw.assets.map(SourceSpec::Assets),
        ];
        let mut named = forms.into_iter().flatten();
        let source = named.next().ok_or(PolicyError::NoSourceForm)?;
        if named.next().is_some() {
            return Err(PolicyError::SeveralSourceForms);
        }
        if matches!(&source, SourceSpec::Any(alternatives) if alternatives.is_empty()) {
            return Err(PolicyError::EmptyAny);
        }
        Ok(Self {
            subject: raw.subject,
            source,
            above: raw.above,
        })
    }
}

impl From<RuleSpec> for RawRule {
    fn from(rule: RuleSpec) -> Self {
        let mut raw = Self {
            subject: rule.subject,
            require: None,
            forbid: None,
            any: None,
            assets: None,
            above: rule.above,
        };
        match rule.source {
            SourceSpec::Require(list) => raw.require = Some(list),
            SourceSpec::Forbid(list) => raw.forbid = Some(list),
            SourceSpec::Any(alternatives) => raw.any = Some(alternatives),
            SourceSpec::Assets(mints) => raw.assets = Some(mints),
        }
        raw
    }
}

impl TryFrom<RawAlternative> for Alternative {
    type Error = PolicyError;

    fn try_from(raw: RawAlternative) -> Result<Self, PolicyError> {
        match (raw.require, raw.forbid) {
            (Some(list), None) => Ok(Self::Require(list)),
            (None, Some(list)) => Ok(Self::Forbid(list)),
            (None, None) => Err(PolicyError::NoSourceForm),
            (Some(_), Some(_)) => Err(PolicyError::SeveralSourceForms),
        }
    }
}

impl From<Alternative> for RawAlternative {
    fn from(alternative: Alternative) -> Self {
        match alternative {
            Alternative::Require(list) => Self {
                require: Some(list),
                forbid: None,
            },
            Alternative::Forbid(list) => Self {
                require: None,
                forbid: Some(list),
            },
        }
    }
}

impl Alternative {
    pub const fn list(self) -> ListName {
        match self {
            Self::Require(list) | Self::Forbid(list) => list,
        }
    }
}

impl SourceSpec {
    /// The lists the rule reads, none for an asset allowlist.
    pub fn lists(&self) -> Vec<ListName> {
        match self {
            Self::Require(list) | Self::Forbid(list) => vec![*list],
            Self::Any(alternatives) => alternatives.iter().map(|alt| alt.list()).collect(),
            Self::Assets(_) => Vec::new(),
        }
    }
}

impl RuleSpec {
    /// The row of `index`, its inline members appended to `assets`.
    pub fn rule(&self, index: usize, assets: &mut Vec<[u8; 32]>) -> Result<Rule, PolicyError> {
        let subject = self.subject.subject();
        let rule = match &self.source {
            SourceSpec::Require(list) => Rule::require(subject, list.id()),
            SourceSpec::Forbid(list) => Rule::forbid(subject, list.id()),
            SourceSpec::Any(alternatives) => {
                let (present, absent) = alternatives.iter().fold(
                    (ListSet::EMPTY, ListSet::EMPTY),
                    |(present, absent), alternative| match alternative {
                        Alternative::Require(list) => {
                            (present.union(ListSet::single(list.id())), absent)
                        }
                        Alternative::Forbid(list) => {
                            (present, absent.union(ListSet::single(list.id())))
                        }
                    },
                );
                Rule::any_of(subject, present, absent)
            }
            SourceSpec::Assets(mints) => {
                for mint in mints {
                    let member = Member::asset(&mint.0).map_err(|source| PolicyError::Asset {
                        rule: index,
                        mint: mint.0,
                        source,
                    })?;
                    assets.push(*member.as_bytes());
                }
                Rule {
                    subject,
                    source: RuleSource::InlineAssets,
                    guard: Guard::Always,
                }
            }
        };
        match self.above {
            Some(_) if matches!(subject, Subject::Sender) => {
                Err(PolicyError::SenderGuard { rule: index })
            }
            Some(amount) => Ok(rule.above(amount)),
            None => Ok(rule),
        }
    }
}

impl PolicySpec {
    pub fn entries_tree(&self) -> Address {
        self.entries_tree
            .map(|tree| tree.0)
            .unwrap_or_else(|| Address::from_str_const(DEFAULT_TREE_ADDRESS))
    }

    /// The rows and the inline assets the builder gets, in row order.
    pub fn rows(&self) -> Result<(Vec<Rule>, Vec<[u8; 32]>), PolicyError> {
        if self.rules.len() > MAX_RULES {
            return Err(PolicyError::TooManyRules {
                count: self.rules.len(),
            });
        }
        let mut assets = Vec::new();
        let rows = self
            .rules
            .iter()
            .enumerate()
            .map(|(index, rule)| rule.rule(index, &mut assets))
            .collect::<Result<Vec<_>, _>>()?;
        if assets.len() > MAX_INLINE_ASSETS {
            return Err(PolicyError::TooManyAssets {
                count: assets.len(),
            });
        }
        Ok((rows, assets))
    }

    pub fn compile(&self, target: Target) -> Result<CompiledPolicy, PolicyError> {
        let (rows, assets) = self.rows()?;
        let rules = compile_rows(&rows, &assets)?;
        let referenced = rules.referenced();
        let shared_sources = self
            .sources
            .get(target)
            .iter()
            .map(|(list, curator)| {
                if !referenced.contains(list.id()) {
                    return Err(PolicyError::UnreferencedSource {
                        list: *list,
                        cluster: target,
                    });
                }
                Ok((list.id(), CustomRing::new(curator.0)))
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(CompiledPolicy {
            rules,
            entries_tree: self.entries_tree(),
            shared_sources,
        })
    }

    /// Compiles for every cluster, a file is accepted only when each passes.
    pub fn check(&self) -> Result<(), PolicyError> {
        Target::ALL
            .into_iter()
            .try_for_each(|target| self.compile(target).map(drop))
    }
}

impl CompiledPolicy {
    pub fn shared_sources(&self) -> Vec<(ListId, CustomRing)> {
        self.shared_sources.clone()
    }

    /// The curator a referenced list reads, `None` for the ring's own entries.
    pub fn curator(&self, list_id: ListId) -> Option<CustomRing> {
        self.shared_sources
            .iter()
            .find(|(shared, _)| *shared == list_id)
            .map(|(_, curator)| *curator)
    }
}

fn build(rows: &[Rule], assets: &[[u8; 32]]) -> Result<RuleTable, RuleTableError> {
    rows.iter()
        .fold(
            RuleTable::builder().inline_assets(assets),
            |builder, rule| builder.rule(*rule),
        )
        .try_build()
}

/// The builder refusal named with the first row that triggers it.
pub fn compile_rows(rows: &[Rule], assets: &[[u8; 32]]) -> Result<RuleTable, PolicyError> {
    build(rows, assets).map_err(|error| PolicyError::Refused {
        rule: first_refusal(rows, assets, error),
        message: error.message(),
    })
}

fn first_refusal(rows: &[Rule], assets: &[[u8; 32]], error: RuleTableError) -> usize {
    (1..=rows.len())
        .find(|len| build(&rows[..*len], assets) == Err(error))
        .map_or(rows.len().saturating_sub(1), |len| len - 1)
}

/// One sentence per row, the wording every listing shares.
pub fn describe(rule: &Rule) -> String {
    let subject = match rule.subject {
        Subject::OutputOwner => "each output owner",
        Subject::Sender => "the sender",
        Subject::Asset => "each asset",
        Subject::ExitDestination => "each exit destination",
    };
    let condition = match rule.source {
        RuleSource::InlineAssets => "must be one of the listed assets".to_owned(),
        RuleSource::Lists { .. } => rule
            .alternatives()
            .map(|(list_id, mode)| match mode {
                Mode::Present => format!("must be on the {} list", list_name(list_id)),
                Mode::Absent => format!("must not be on the {} list", list_name(list_id)),
            })
            .collect::<Vec<_>>()
            .join(" or "),
    };
    match rule.guard {
        Guard::Always => format!("{subject} {condition}"),
        Guard::AboveAmount(amount) => {
            format!("{subject} {condition} when the amount is above {amount}")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CURATOR: &str = "9vyTbYGyh3cwxkAQpjjFQGXmdJP6p9B6YcQ5pNuXPNbh";
    const MINT: &str = "So11111111111111111111111111111111111111112";

    fn spec(text: &str) -> Result<PolicySpec, toml::de::Error> {
        toml::from_str(text)
    }

    fn compiled(text: &str) -> Result<CompiledPolicy, PolicyError> {
        spec(text).expect("parses").compile(Target::Devnet)
    }

    #[test]
    fn list_names_are_the_authority_written_lists_in_slot_order() {
        assert_eq!(
            ListName::ALL.map(ListName::as_str),
            ["allow", "block", "frozen", "reader", "approval"]
        );
        for name in ListName::ALL {
            assert_eq!(name.as_str().parse::<ListName>(), Ok(name));
        }
        assert!(matches!(
            "escrow".parse::<ListName>(),
            Err(PolicyError::MemberWrittenList { name }) if name == "escrow"
        ));
        assert!(matches!(
            "Allow".parse::<ListName>(),
            Err(PolicyError::UnknownList { name }) if name == "Allow"
        ));
        assert!(ListName(ListId::Allow) < ListName(ListId::Approval));
    }

    #[test]
    fn every_form_parses_and_compiles() {
        let policy = compiled(&format!(
            r#"
entries_tree = "{CURATOR}"

[sources.devnet]
block = "{CURATOR}"

[[rules]]
subject = "output-owner"
any = [{{ forbid = "block" }}, {{ require = "approval" }}]

[[rules]]
subject = "sender"
forbid = "frozen"

[[rules]]
subject = "asset"
assets = ["{MINT}"]

[[rules]]
subject = "output-owner"
require = "allow"
above = 1000000
"#
        ))
        .expect("compiles");
        let rows = policy.rules.rules();
        assert_eq!(rows.len(), 4);
        assert_eq!(
            rows[0],
            Rule::any_of(
                Subject::OutputOwner,
                ListSet::single(ListId::Approval),
                ListSet::single(ListId::Block)
            )
        );
        assert_eq!(rows[1], Rule::forbid(Subject::Sender, ListId::Frozen));
        assert_eq!(rows[2].source, RuleSource::InlineAssets);
        assert_eq!(
            rows[3],
            Rule::require(Subject::OutputOwner, ListId::Allow).above(1_000_000)
        );
        assert_eq!(
            policy.rules.inline_assets(),
            [*Member::asset(&Address::from_str_const(MINT))
                .expect("member")
                .as_bytes()]
        );
        assert_eq!(policy.entries_tree, Address::from_str_const(CURATOR));
        assert_eq!(
            policy.shared_sources,
            vec![(
                ListId::Block,
                CustomRing::new(Address::from_str_const(CURATOR))
            )]
        );
        assert!(policy.curator(ListId::Block).is_some());
        assert!(policy.curator(ListId::Allow).is_none());
    }

    #[test]
    fn an_empty_table_is_a_legal_policy_with_the_default_tree() {
        let policy = compiled("").expect("empty table");
        assert!(policy.rules.is_empty());
        assert_eq!(
            policy.entries_tree,
            Address::from_str_const(DEFAULT_TREE_ADDRESS)
        );
        assert!(policy.shared_sources.is_empty());
    }

    #[test]
    fn a_rule_takes_exactly_one_source_form() {
        let none = spec("[[rules]]\nsubject = \"sender\"\n").expect_err("no form");
        assert!(none
            .to_string()
            .contains(&PolicyError::NoSourceForm.to_string()));
        let several =
            spec("[[rules]]\nsubject = \"sender\"\nrequire = \"allow\"\nforbid = \"block\"\n")
                .expect_err("two forms");
        assert!(several
            .to_string()
            .contains(&PolicyError::SeveralSourceForms.to_string()));
        let empty = spec("[[rules]]\nsubject = \"sender\"\nany = []\n").expect_err("empty any");
        assert!(empty
            .to_string()
            .contains(&PolicyError::EmptyAny.to_string()));
        let both = spec("[[rules]]\nsubject = \"sender\"\nany = [{ require = \"allow\", forbid = \"block\" }]\n")
            .expect_err("two forms in one alternative");
        assert!(both
            .to_string()
            .contains(&PolicyError::SeveralSourceForms.to_string()));
        let unknown = spec("[[rules]]\nsubject = \"sender\"\nrequire = \"escrow\"\n")
            .expect_err("member-written list");
        assert!(unknown.to_string().contains("written by its members"));
        let subject = spec("[[rules]]\nsubject = \"owner\"\nrequire = \"allow\"\n")
            .expect_err("unknown subject");
        assert!(subject.to_string().contains("unknown subject owner"));
        assert!(spec("[[rules]]\nsubject = \"sender\"\nrequire = \"allow\"\nextra = 1\n").is_err());
        assert!(spec("[sources.mainnet]\nblock = \"x\"\n").is_err());
    }

    #[test]
    fn the_named_refusals_carry_their_row() {
        assert_eq!(
            compiled("[[rules]]\nsubject = \"sender\"\nrequire = \"allow\"\nabove = 5\n"),
            Err(PolicyError::SenderGuard { rule: 0 })
        );
        let rows = (0..17)
            .map(|_| "[[rules]]\nsubject = \"sender\"\nrequire = \"allow\"\n")
            .collect::<String>();
        assert_eq!(
            compiled(&rows),
            Err(PolicyError::TooManyRules { count: 17 })
        );
        let mints = (0..9).map(|_| format!("\"{MINT}\"")).collect::<Vec<_>>();
        assert_eq!(
            compiled(&format!(
                "[[rules]]\nsubject = \"asset\"\nassets = [{}]\n",
                mints.join(", ")
            )),
            Err(PolicyError::TooManyAssets { count: 9 })
        );
        assert_eq!(
            compiled(&format!(
                "[sources.devnet]\nblock = \"{CURATOR}\"\n[[rules]]\nsubject = \"sender\"\nrequire = \"allow\"\n"
            )),
            Err(PolicyError::UnreferencedSource {
                list: ListName(ListId::Block),
                cluster: Target::Devnet
            })
        );
        assert_eq!(
            compiled(&format!(
                "[sources.localnet]\nblock = \"{CURATOR}\"\n[[rules]]\nsubject = \"sender\"\nrequire = \"allow\"\n"
            ))
            .map(|policy| policy.shared_sources.len()),
            Ok(0)
        );
    }

    #[test]
    fn a_builder_refusal_names_the_first_row_that_triggers_it() {
        let duplicate = compiled(
            "[[rules]]\nsubject = \"sender\"\nrequire = \"allow\"\n\
             [[rules]]\nsubject = \"output-owner\"\nforbid = \"block\"\n\
             [[rules]]\nsubject = \"sender\"\nrequire = \"allow\"\n",
        );
        assert_eq!(
            duplicate,
            Err(PolicyError::Refused {
                rule: 2,
                message: RuleTableError::DuplicateRule.message()
            })
        );
        let zero =
            compiled("[[rules]]\nsubject = \"output-owner\"\nrequire = \"allow\"\nabove = 0\n");
        assert_eq!(
            zero,
            Err(PolicyError::Refused {
                rule: 0,
                message: RuleTableError::ZeroThreshold.message()
            })
        );
        let guard_without_asset = compiled(
            "[[rules]]\nsubject = \"sender\"\nrequire = \"allow\"\n\
             [[rules]]\nsubject = \"output-owner\"\nrequire = \"allow\"\nabove = 7\n",
        );
        assert_eq!(
            guard_without_asset,
            Err(PolicyError::Refused {
                rule: 1,
                message: RuleTableError::OwnerGuardWithoutInlineAsset.message()
            })
        );
        let inline_on_sender = compiled(&format!(
            "[[rules]]\nsubject = \"sender\"\nassets = [\"{MINT}\"]\n"
        ));
        assert_eq!(
            inline_on_sender,
            Err(PolicyError::Refused {
                rule: 0,
                message: RuleTableError::InlineNotAsset.message()
            })
        );
        assert_eq!(
            PolicyError::Refused {
                rule: 2,
                message: "duplicate rule"
            }
            .to_string(),
            "rule 3 is refused, duplicate rule"
        );
    }

    #[test]
    fn describe_reads_each_row_as_one_sentence() {
        assert_eq!(
            describe(&Rule::require(Subject::OutputOwner, ListId::Allow)),
            "each output owner must be on the allow list"
        );
        assert_eq!(
            describe(&Rule::forbid(Subject::Sender, ListId::Frozen)),
            "the sender must not be on the frozen list"
        );
        assert_eq!(
            describe(&Rule::any_of(
                Subject::OutputOwner,
                ListSet::single(ListId::Approval),
                ListSet::single(ListId::Block)
            )),
            "each output owner must be on the approval list or must not be on the block list"
        );
        assert_eq!(
            describe(&Rule::allow_only_assets()),
            "each asset must be one of the listed assets"
        );
        assert_eq!(
            describe(&Rule::require(Subject::Asset, ListId::Allow).above(1_000_000)),
            "each asset must be on the allow list when the amount is above 1000000"
        );
    }

    #[test]
    fn check_compiles_for_every_cluster() {
        let policy = spec(&format!(
            "[sources.localnet]\nblock = \"{CURATOR}\"\n[[rules]]\nsubject = \"sender\"\nrequire = \"allow\"\n"
        ))
        .expect("parses");
        assert_eq!(
            policy.check(),
            Err(PolicyError::UnreferencedSource {
                list: ListName(ListId::Block),
                cluster: Target::Localnet
            })
        );
    }
}
