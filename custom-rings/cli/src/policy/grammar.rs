//! The `[policy]` table of `ring.toml` and its compilation to the pinned rule table.

use std::{cmp::Ordering, collections::BTreeMap, fmt, str::FromStr};

use custom_ring_sdk::CustomRing;
use serde::{Deserialize, Serialize};
use solana_address::Address;
use thiserror::Error;
use zolana_interface::pda;
use zolana_ring_policy::{
    Guard, ListId, ListSet, Member, MemberError, Mode, OutflowLimit, Rule, RuleSource, RuleTable,
    RuleTableError, Subject, Writer, MAX_INLINE_ASSETS, MAX_OUTFLOW_LIMITS, MAX_RULES,
};

use crate::{
    config::{Base58Address, PerCluster, Target},
    macros::{named_enum, serde_via_str},
};

#[derive(Clone, Debug, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PolicySpec {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub address_tree: Option<Base58Address>,
    /// Curator program ids by list name, an absent list reads the ring's own registry.
    #[serde(default, skip_serializing_if = "PerCluster::is_empty")]
    pub sources: PerCluster<Sources>,
    /// Every rule must hold, in row order.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub rules: Vec<RuleSpec>,
    /// A sender's outflow per mint and transfer, at most one entry per mint.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub limits: Vec<LimitSpec>,
}

pub type Sources = BTreeMap<ListName, Base58Address>;

/// A zero `cap` or `cosign_above` leaves that bound off, one of them is nonzero.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LimitSpec {
    pub asset: Base58Address,
    #[serde(default)]
    pub cap: u64,
    #[serde(default)]
    pub cosign_above: u64,
}

/// Exactly one of `require`, `forbid`, `any` or `assets` beside the subject.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(try_from = "RawRule", into = "RawRule")]
pub struct RuleSpec {
    pub subject: SubjectName,
    pub source: SourceSpec,
    pub above: Option<u64>,
    pub limits: Option<Vec<AssetLimitSpec>>,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AssetLimitSpec {
    pub asset: Base58Address,
    pub above: u64,
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

named_enum! {
    pub enum SubjectName("subject") {
        OutputOwner = "output-owner",
        Sender = "sender",
        Asset = "asset",
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CompiledPolicy {
    pub rules: RuleTable,
    pub address_tree: Address,
    pub shared_sources: Vec<(ListId, CustomRing)>,
}

pub(crate) struct PolicyRows {
    pub rules: Vec<Rule>,
    pub assets: Vec<[u8; 32]>,
    pub limits: Vec<u64>,
    pub outflow: Vec<OutflowLimit>,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum PolicyError {
    #[error("unknown list {name}")]
    UnknownList { name: String },
    #[error("the {name} list is written by its members, a rule cannot read it")]
    MemberWrittenList { name: String },
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
    #[error("a rule names both above and limits, give one amount guard")]
    SeveralGuardForms,
    #[error("rule {} has no per-asset limits", rule + 1)]
    EmptyLimits { rule: usize },
    #[error("rule {} takes per-asset limits only for an output-owner list rule", rule + 1)]
    PerAssetGuard { rule: usize },
    #[error("rule {} defines a different inline asset map", rule + 1)]
    ConflictingAssetMap { rule: usize },
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
    #[error("{count} outflow limits exceed the {MAX_OUTFLOW_LIMITS} slots of the table")]
    TooManyLimits { count: usize },
    #[error("outflow limit {} asset {mint} derives no member", row + 1)]
    LimitAsset {
        row: usize,
        mint: Address,
        #[source]
        source: MemberError,
    },
    #[error("the outflow limits are refused, {message}")]
    LimitsRefused { message: &'static str },
    #[error("outflow limit {} {field} {amount} exceeds what a toml integer holds", row + 1)]
    LimitTooLarge {
        row: usize,
        field: &'static str,
        amount: u64,
    },
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    limits: Option<Vec<AssetLimitSpec>>,
}

#[derive(Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct RawAlternative {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    require: Option<ListName>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    forbid: Option<ListName>,
}

serde_via_str!(ListName);

impl ListName {
    /// The authority-written lists in `ListId::ALL` order, a lib test pins the set.
    pub const ALL: [Self; 5] = [
        Self(ListId::Allow),
        Self(ListId::Block),
        Self(ListId::Frozen),
        Self(ListId::Reader),
        Self(ListId::Approval),
    ];

    pub const fn id(self) -> ListId {
        self.0
    }

    pub const fn as_str(self) -> &'static str {
        self.0.name()
    }

    pub fn of(list_id: ListId) -> Result<Self, PolicyError> {
        match list_id.writer() {
            Writer::Authority => Ok(Self(list_id)),
            _ => Err(PolicyError::MemberWrittenList {
                name: list_id.name().to_owned(),
            }),
        }
    }
}

impl PartialOrd for ListName {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for ListName {
    fn cmp(&self, other: &Self) -> Ordering {
        self.0.slot().cmp(&other.0.slot())
    }
}

impl FromStr for ListName {
    type Err = PolicyError;

    fn from_str(name: &str) -> Result<Self, PolicyError> {
        let list_id = ListId::ALL
            .into_iter()
            .find(|list_id| list_id.name() == name)
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

impl clap::ValueEnum for ListName {
    fn value_variants<'a>() -> &'a [Self] {
        &Self::ALL
    }

    fn to_possible_value(&self) -> Option<clap::builder::PossibleValue> {
        Some(clap::builder::PossibleValue::new(self.as_str()))
    }
}

impl SubjectName {
    pub const fn subject(self) -> Subject {
        match self {
            Self::OutputOwner => Subject::OutputOwner,
            Self::Sender => Subject::Sender,
            Self::Asset => Subject::Asset,
        }
    }
}

impl TryFrom<RawRule> for RuleSpec {
    type Error = PolicyError;

    fn try_from(raw: RawRule) -> Result<Self, PolicyError> {
        if raw.above.is_some() && raw.limits.is_some() {
            return Err(PolicyError::SeveralGuardForms);
        }
        let source = one_form([
            raw.require.map(SourceSpec::Require),
            raw.forbid.map(SourceSpec::Forbid),
            raw.any.map(SourceSpec::Any),
            raw.assets.map(SourceSpec::Assets),
        ])?;
        if matches!(&source, SourceSpec::Any(alternatives) if alternatives.is_empty()) {
            return Err(PolicyError::EmptyAny);
        }
        Ok(Self {
            subject: raw.subject,
            source,
            above: raw.above,
            limits: raw.limits,
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
            limits: rule.limits,
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
        one_form([raw.require.map(Self::Require), raw.forbid.map(Self::Forbid)])
    }
}

fn one_form<T, const N: usize>(forms: [Option<T>; N]) -> Result<T, PolicyError> {
    let mut named = forms.into_iter().flatten();
    let form = named.next().ok_or(PolicyError::NoSourceForm)?;
    match named.next() {
        Some(_) => Err(PolicyError::SeveralSourceForms),
        None => Ok(form),
    }
}

impl From<Alternative> for RawAlternative {
    fn from(alternative: Alternative) -> Self {
        match alternative {
            Alternative::Require(list) => Self {
                require: Some(list),
                ..Self::default()
            },
            Alternative::Forbid(list) => Self {
                forbid: Some(list),
                ..Self::default()
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
    /// The row of `index`, its inline members and limits merged into `assets` and `limits`.
    pub fn rule(
        &self,
        index: usize,
        assets: &mut Vec<[u8; 32]>,
        limits: &mut Vec<u64>,
    ) -> Result<Rule, PolicyError> {
        let subject = self.subject.subject();
        let rule = match &self.source {
            SourceSpec::Require(list) => Rule::require(subject, list.id()),
            SourceSpec::Forbid(list) => Rule::forbid(subject, list.id()),
            SourceSpec::Any(alternatives) => {
                let lists = |require: bool| {
                    let ids: Vec<ListId> = alternatives
                        .iter()
                        .filter(|alt| matches!(alt, Alternative::Require(_)) == require)
                        .map(|alt| alt.list().id())
                        .collect();
                    ListSet::of(&ids)
                };
                Rule::any_of(subject, lists(true), lists(false))
            }
            SourceSpec::Assets(mints) => {
                merge(
                    index,
                    assets,
                    &members(index, mints.iter().map(|mint| mint.0))?,
                )?;
                Rule {
                    subject,
                    source: RuleSource::InlineAssets,
                    guard: Guard::Always,
                }
            }
        };
        if let Some(configured) = &self.limits {
            if configured.is_empty() {
                return Err(PolicyError::EmptyLimits { rule: index });
            }
            if !matches!(subject, Subject::OutputOwner)
                || matches!(&self.source, SourceSpec::Assets(_))
            {
                return Err(PolicyError::PerAssetGuard { rule: index });
            }
            let mints = configured.iter().map(|limit| limit.asset.0);
            merge(index, assets, &members(index, mints)?)?;
            let amounts: Vec<u64> = configured.iter().map(|limit| limit.above).collect();
            merge(index, limits, &amounts)?;
            return Ok(rule.above_by_asset());
        }
        match self.above {
            Some(_) if matches!(subject, Subject::Sender) => {
                Err(PolicyError::SenderGuard { rule: index })
            }
            Some(amount) => Ok(rule.above(amount)),
            None => Ok(rule),
        }
    }
}

fn members(
    rule: usize,
    mints: impl Iterator<Item = Address>,
) -> Result<Vec<[u8; 32]>, PolicyError> {
    let member =
        |mint| Member::asset(&mint).map_err(|source| PolicyError::Asset { rule, mint, source });
    mints.map(|mint| Ok(*member(mint)?.as_bytes())).collect()
}

/// Every inline asset rule and per-asset limit shares one map.
fn merge<T: Clone + PartialEq>(
    rule: usize,
    current: &mut Vec<T>,
    incoming: &[T],
) -> Result<(), PolicyError> {
    if current.is_empty() {
        current.extend_from_slice(incoming);
    } else if current != incoming {
        return Err(PolicyError::ConflictingAssetMap { rule });
    }
    Ok(())
}

impl PolicySpec {
    pub fn address_tree(&self) -> Address {
        self.address_tree.map_or(pda::tree(0), |tree| tree.0)
    }

    pub(crate) fn rows(&self) -> Result<PolicyRows, PolicyError> {
        let count = self.rules.len();
        if count > MAX_RULES {
            return Err(PolicyError::TooManyRules { count });
        }
        let (mut assets, mut limits) = (Vec::new(), Vec::new());
        let rules = self
            .rules
            .iter()
            .enumerate()
            .map(|(index, rule)| rule.rule(index, &mut assets, &mut limits))
            .collect::<Result<Vec<_>, _>>()?;
        let count = assets.len();
        if count > MAX_INLINE_ASSETS {
            return Err(PolicyError::TooManyAssets { count });
        }
        Ok(PolicyRows {
            rules,
            assets,
            limits,
            outflow: self.outflow_limits()?,
        })
    }

    pub fn compile(&self, cluster: Target) -> Result<CompiledPolicy, PolicyError> {
        let rules = compile_rows(&self.rows()?)?;
        let referenced = rules.referenced();
        let shared_sources = self
            .sources
            .get(cluster)
            .iter()
            .map(|(&list, curator)| match referenced.contains(list.id()) {
                true => Ok((list.id(), CustomRing::new(curator.0))),
                false => Err(PolicyError::UnreferencedSource { list, cluster }),
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(CompiledPolicy {
            rules,
            address_tree: self.address_tree(),
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

    /// The curator a referenced list reads, `None` for the ring's own registry.
    pub fn curator(&self, list_id: ListId) -> Option<CustomRing> {
        self.shared_sources
            .iter()
            .find(|(shared, _)| *shared == list_id)
            .map(|(_, curator)| *curator)
    }
}

impl PolicySpec {
    fn outflow_limits(&self) -> Result<Vec<OutflowLimit>, PolicyError> {
        let count = self.limits.len();
        if count > MAX_OUTFLOW_LIMITS {
            return Err(PolicyError::TooManyLimits { count });
        }
        let limit = |(row, spec): (usize, &LimitSpec)| {
            let mint = spec.asset.0;
            let refused = |source| PolicyError::LimitAsset { row, mint, source };
            Ok(OutflowLimit {
                asset: *Member::asset(&mint).map_err(refused)?.as_bytes(),
                cap: spec.cap,
                cosign_above: spec.cosign_above,
            })
        };
        self.limits.iter().enumerate().map(limit).collect()
    }
}

impl PolicyRows {
    fn build(&self, rule_count: usize) -> Result<RuleTable, RuleTableError> {
        let builder = RuleTable::builder()
            .inline_assets(&self.assets)
            .inline_limits(&self.limits)
            .limits(&self.outflow);
        self.rules[..rule_count]
            .iter()
            .fold(builder, |builder, rule| builder.rule(*rule))
            .try_build()
    }
}

/// A refusal names the first row that triggers it, a limit refusal names the limits.
pub(crate) fn compile_rows(rows: &PolicyRows) -> Result<RuleTable, PolicyError> {
    rows.build(rows.rules.len()).map_err(|error| {
        let message = error.message();
        match error {
            RuleTableError::TooManyOutflowLimits
            | RuleTableError::ZeroLimitAsset
            | RuleTableError::DuplicateLimitAsset
            | RuleTableError::LimitWithoutBound => PolicyError::LimitsRefused { message },
            _ => PolicyError::Refused {
                rule: (0..rows.rules.len())
                    .find(|rule| rows.build(rule + 1) == Err(error))
                    .unwrap_or(rows.rules.len().saturating_sub(1)),
                message,
            },
        }
    })
}

/// One sentence per outflow limit, the wording every listing shares.
pub fn describe_limit(limit: &OutflowLimit) -> String {
    let asset = hex::encode(&limit.asset[..4]);
    match (limit.cap, limit.cosign_above) {
        (0, cosign) => format!("asset {asset}.. needs the co-signer above {cosign} per transfer"),
        (cap, 0) => format!("asset {asset}.. is capped at {cap} per transfer"),
        (cap, cosign) => format!(
            "asset {asset}.. is capped at {cap} per transfer and needs the co-signer above {cosign}"
        ),
    }
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
                Mode::Present => format!("must be on the {} list", list_id.name()),
                Mode::Absent => format!("must not be on the {} list", list_id.name()),
            })
            .collect::<Vec<_>>()
            .join(" or "),
    };
    match rule.guard {
        Guard::Always => format!("{subject} {condition}"),
        Guard::AboveAmount(amount) => {
            format!("{subject} {condition} when the amount is above {amount}")
        }
        Guard::AboveAmountByAsset => {
            format!("{subject} {condition} when its per-asset amount is above the limit")
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
    fn limits_bound_each_transfer() {
        let policy = compiled(&format!(
            r#"
address_tree = "{CURATOR}"
limits = [{{ asset = "{MINT}", cap = 1000 }}]
"#
        ))
        .expect("compiles");
        let limits = policy.rules.limits();
        assert_eq!(limits.len(), 1);
        assert_eq!((limits[0].cap, limits[0].cosign_above), (1000, 0));
    }

    #[test]
    fn a_limit_without_a_bound_is_refused() {
        let error = compiled(&format!(
            r#"
address_tree = "{CURATOR}"
limits = [{{ asset = "{MINT}" }}]
"#
        ))
        .expect_err("a limit needs a bound");
        assert!(matches!(
            error,
            PolicyError::LimitsRefused { message }
                if message == "an outflow limit needs a cap or a cosign threshold"
        ));
    }

    #[test]
    fn the_description_names_each_bound() {
        let capped = OutflowLimit {
            asset: [3u8; 32],
            cap: 1000,
            cosign_above: 0,
        };
        assert!(describe_limit(&capped).contains("capped at 1000 per transfer"));
        let cosigned = OutflowLimit {
            cosign_above: 400,
            ..capped
        };
        assert!(describe_limit(&cosigned).contains("co-signer above 400"));
    }

    #[test]
    fn every_form_parses_and_compiles() {
        let policy = compiled(&format!(
            r#"
address_tree = "{CURATOR}"

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
        assert_eq!(policy.address_tree, Address::from_str_const(CURATOR));
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
        assert_eq!(policy.address_tree, pda::tree(0));
        assert!(policy.shared_sources.is_empty());
    }

    #[test]
    fn one_owner_rule_compiles_a_limit_per_asset() {
        let policy = compiled(&format!(
            r#"
[[rules]]
subject = "output-owner"
require = "allow"
limits = [
  {{ asset = "{MINT}", above = 1000000 }},
  {{ asset = "{CURATOR}", above = 2000000 }},
]
"#
        ))
        .expect("per-asset rule");
        assert_eq!(
            policy.rules.rules(),
            &[Rule::require(Subject::OutputOwner, ListId::Allow).above_by_asset()]
        );
        assert_eq!(policy.rules.inline_assets().len(), 2);
        assert_eq!(policy.rules.inline_limits(), &[1_000_000, 2_000_000]);
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
