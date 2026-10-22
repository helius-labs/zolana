use bytemuck::{Pod, Zeroable};
use thiserror::Error;
use wincode::{SchemaRead, SchemaWrite};
use zolana_hasher::{primitives::right_align, Hasher, HasherError, Poseidon};

use crate::{field_u8, ListId, ListSet, Member};

/// Rule slots compiled into the circuit, a new value rotates the proving key.
pub const MAX_RULES: usize = 16;
/// Mint threshold slots per table, a circuit width.
pub const MAX_INLINE_ASSETS: usize = 8;
/// Source slots, one per list the enum can name.
pub const MAX_SOURCES: usize = 8;
/// Curator registries one policy may read lists from, a circuit width.
pub const N_FOREIGN: usize = 1;
/// Outflow limit slots per table, a circuit width.
pub const MAX_OUTFLOW_LIMITS: usize = 8;
/// Enters `policy_hash`, bump it with any change of the encoding below.
pub const POLICY_TABLE_VERSION: u8 = 11;
/// `"CRTB"`, the first field of the table hash, `domain::POLICY_TABLE` of the interface.
pub const POLICY_TABLE_DOMAIN: u32 = 0x4352_5442;
pub const POLICY_TABLE_FIELDS: usize =
    5 + 2 * MAX_SOURCES + MAX_RULES + 2 * MAX_INLINE_ASSETS + 3 * MAX_OUTFLOW_LIMITS;
/// Fields absorbed per Poseidon call beside the accumulator, the 12-input syscall maximum.
pub const POLICY_TABLE_RATE: usize = 11;

const _: () =
    assert!(POLICY_TABLE_FIELDS == 77 && POLICY_TABLE_FIELDS.is_multiple_of(POLICY_TABLE_RATE));

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PolicySource {
    /// Zero marks an empty slot.
    pub list_id: u8,
    /// A curator's `registry_field`, zero for the ring's own.
    pub registry: [u8; 32],
}

/// Positional source map, slot `i` is empty or serves list `i + 1`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SourceMap {
    slots: [PolicySource; MAX_SOURCES],
}

/// A slot violates the positional layout.
#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum SourceMapError {
    #[error("slot breaks the positional layout")]
    NotPositional,
    #[error("list is already mapped")]
    Duplicate,
    #[error("the curator slots name more than {N_FOREIGN} registry")]
    SeveralCurators,
}

#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum PolicyTableError {
    #[error("no source serves a list a rule reads")]
    MissingSource(ListId),
    #[error(transparent)]
    Table(#[from] RuleTableError),
}

macro_rules! rule_errors {
    ($($variant:ident => $message:literal,)*) => {
        /// A table or a row the program refuses.
        #[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
        pub enum RuleTableError {
            $(#[error($message)] $variant,)*
        }

        impl RuleTableError {
            /// Const, a refused `RuleTableBuilder::build` panics with it at compile time.
            pub const fn message(&self) -> &'static str {
                match self {
                    $(Self::$variant => $message,)*
                }
            }
        }
    };
}

rule_errors! {
    TooManyRules => "policy table is full",
    TooManyInlineAssets => "asset thresholds exceed the circuit width",
    ZeroInlineAsset => "zero is the padding value, never a member",
    PoolWithoutInlineRule => "asset thresholds without a per-asset guard",
    EmptyLists => "a group names no list",
    ListInBothSets => "a list is both required and forbidden",
    SenderGuard => "sender rules take no amount guard",
    ExitDestination => "exit destinations are enforced by no plane",
    ZeroThreshold => "a zero threshold is Guard::Always",
    DuplicateRule => "duplicate rule",
    PerAssetGuardNotOwner => "per-asset limits apply to output owners only",
    MissingAssetLimit => "every mint threshold needs a nonzero limit",
    AssetLimitWithoutGuard => "asset limits need a per-asset guard",
    DuplicateInlineAsset => "mint thresholds must name distinct assets",
    UnknownSubject => "unknown subject",
    UnknownMode => "unknown mode",
    UnknownGuardTag => "unknown guard tag",
    ThresholdWithoutGuard => "a threshold without a guard",
    ReservedBytes => "reserved row bytes are not zero",
    NonCanonicalAlternative => "an alternative beside an absent primary",
    NonZeroPadding => "padding past the counts is not zero",
    TooManyOutflowLimits => "outflow limits exceed the circuit width",
    ZeroLimitAsset => "an outflow limit names no mint",
    DuplicateLimitAsset => "outflow limit mints must be unique",
    LimitWithoutBound => "an outflow limit needs a cap or a cosign threshold",
    MemberWrittenList => "a rule reads a list its members write",
}

impl SourceMap {
    pub fn new(entries: &[(ListId, [u8; 32])]) -> Result<Self, SourceMapError> {
        let mut sources = Self::default();
        for (list_id, registry) in entries {
            let slot = &mut sources.slots[list_id.slot()];
            if slot.list_id != 0 {
                return Err(SourceMapError::Duplicate);
            }
            *slot = PolicySource {
                list_id: *list_id as u8,
                registry: *registry,
            };
        }
        sources.check_curators()?;
        Ok(sources)
    }

    /// Validates stored slots instead of re-canonicalizing them.
    pub fn from_slots(slots: [PolicySource; MAX_SOURCES]) -> Result<Self, SourceMapError> {
        for (index, slot) in slots.iter().enumerate() {
            let empty = slot.list_id == 0 && slot.registry == [0u8; 32];
            let positional = slot.list_id as usize == index + 1;
            if !empty && !positional {
                return Err(SourceMapError::NotPositional);
            }
        }
        let map = Self { slots };
        map.check_curators()?;
        Ok(map)
    }

    /// Every curator slot names the one foreign registry the circuit opens.
    fn check_curators(&self) -> Result<(), SourceMapError> {
        let mut curators = self
            .slots
            .iter()
            .map(|slot| slot.registry)
            .filter(|registry| *registry != [0u8; 32]);
        let first = curators.next();
        if curators.any(|registry| Some(registry) != first) {
            return Err(SourceMapError::SeveralCurators);
        }
        Ok(())
    }

    /// The registry serving a list, zero for the ring's own, `None` when unmapped.
    pub fn registry(&self, list_id: ListId) -> Option<&[u8; 32]> {
        let slot = &self.slots[list_id.slot()];
        (slot.list_id != 0).then_some(&slot.registry)
    }

    /// The curator registry a slot names, `None` when every mapped list is the ring's own.
    pub fn curator(&self) -> Option<[u8; 32]> {
        self.slots
            .iter()
            .map(|slot| slot.registry)
            .find(|registry| *registry != [0u8; 32])
    }

    pub const fn slots(&self) -> &[PolicySource; MAX_SOURCES] {
        &self.slots
    }
}

/// Whom a rule screens in the transfer openings.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Subject {
    OutputOwner = 1,
    Sender = 2,
    ExitDestination = 3,
    Asset = 4,
}

/// Present demands a live Active entry, Absent forbids one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Mode {
    Present = 1,
    Absent = 2,
}

/// Amount guards compare output sums in asset base units.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Guard {
    Always,
    AboveAmount(u64),
    AboveAmountByAsset,
}

/// A disjunction over registry lists.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RuleSource {
    Lists { present: ListSet, absent: ListSet },
}

/// One obligation, packed into a single field element for the hash.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Rule {
    pub subject: Subject,
    pub source: RuleSource,
    pub guard: Guard,
}

/// Byte positions are the circuit packed-field weights (Go `ruleShift`), reordering breaks proof verification.
#[derive(Clone, Copy, Pod, Zeroable)]
#[repr(C)]
struct Row {
    reserved: [u8; 19],
    alternative: u8,
    threshold: [u8; 8],
    guard_tag: u8,
    mask: u8,
    mode: u8,
    subject: u8,
}

const _: () = assert!(core::mem::size_of::<Row>() == 32);

impl Rule {
    /// Every live instance of the subject needs a live Active entry.
    pub const fn require(subject: Subject, list_id: ListId) -> Self {
        Self::any_of(subject, ListSet::single(list_id), ListSet::EMPTY)
    }

    /// Every live instance of the subject needs a provable absence.
    pub const fn forbid(subject: Subject, list_id: ListId) -> Self {
        Self::any_of(subject, ListSet::EMPTY, ListSet::single(list_id))
    }

    /// Every live instance must be present in at least one of the lists.
    pub const fn require_any(subject: Subject, lists: ListSet) -> Self {
        Self::any_of(subject, lists, ListSet::EMPTY)
    }

    /// A live instance is refused only when present in every one of the lists.
    pub const fn forbid_all(subject: Subject, lists: ListSet) -> Self {
        Self::any_of(subject, ListSet::EMPTY, lists)
    }

    /// A presence in any of `present` or an absence from any of `absent` passes.
    pub const fn any_of(subject: Subject, present: ListSet, absent: ListSet) -> Self {
        Self {
            subject,
            source: RuleSource::Lists { present, absent },
            guard: Guard::Always,
        }
    }

    /// The rule passes below the threshold without a membership check.
    #[must_use]
    pub const fn above(self, amount: u64) -> Self {
        Self {
            guard: Guard::AboveAmount(amount),
            ..self
        }
    }

    #[must_use]
    pub const fn above_by_asset(self) -> Self {
        Self {
            guard: Guard::AboveAmountByAsset,
            ..self
        }
    }

    pub const fn primary_mode(&self) -> Mode {
        match self.source {
            RuleSource::Lists { present, .. } if present.is_empty() => Mode::Absent,
            RuleSource::Lists { .. } => Mode::Present,
        }
    }

    pub const fn referenced(&self) -> ListSet {
        match self.source {
            RuleSource::Lists { present, absent } => present.union(absent),
        }
    }

    /// Presences first, each in `ListId::ALL` order.
    pub fn alternatives(&self) -> impl Iterator<Item = (ListId, Mode)> {
        let (present, absent) = match self.source {
            RuleSource::Lists { present, absent } => (present, absent),
        };
        present
            .iter()
            .map(|list_id| (list_id, Mode::Present))
            .chain(absent.iter().map(|list_id| (list_id, Mode::Absent)))
    }

    pub fn encoded(&self) -> [u8; 32] {
        let (mask, alternative) = match self.source {
            RuleSource::Lists { present, absent } => match self.primary_mode() {
                Mode::Present => (present, absent),
                Mode::Absent => (absent, ListSet::EMPTY),
            },
        };
        let (guard_tag, threshold) = match self.guard {
            Guard::Always => (0, 0),
            Guard::AboveAmount(amount) => (1, amount),
            Guard::AboveAmountByAsset => (2, 0),
        };
        bytemuck::cast(Row {
            reserved: [0; 19],
            alternative: alternative.bits(),
            threshold: threshold.to_be_bytes(),
            guard_tag,
            mask: mask.bits(),
            mode: self.primary_mode() as u8,
            subject: self.subject as u8,
        })
    }

    /// Refuses every row `encoded` never emits, the circuit equation alone admits them.
    pub fn decode(bytes: &[u8; 32]) -> Result<Self, RuleTableError> {
        let row: &Row = bytemuck::cast_ref(bytes);
        if row.reserved != [0; 19] {
            return Err(RuleTableError::ReservedBytes);
        }
        let subject = match row.subject {
            1 => Subject::OutputOwner,
            2 => Subject::Sender,
            3 => Subject::ExitDestination,
            4 => Subject::Asset,
            _ => return Err(RuleTableError::UnknownSubject),
        };
        let mode = match row.mode {
            1 => Mode::Present,
            2 => Mode::Absent,
            _ => return Err(RuleTableError::UnknownMode),
        };
        let mask = ListSet::from_bits(row.mask);
        let alternative = ListSet::from_bits(row.alternative);
        if mask.is_empty() {
            return Err(RuleTableError::EmptyLists);
        }
        let source = match mode {
            Mode::Present => RuleSource::Lists {
                present: mask,
                absent: alternative,
            },
            Mode::Absent if !alternative.is_empty() => {
                return Err(RuleTableError::NonCanonicalAlternative)
            }
            Mode::Absent => RuleSource::Lists {
                present: ListSet::EMPTY,
                absent: mask,
            },
        };
        let threshold = u64::from_be_bytes(row.threshold);
        let guard = match row.guard_tag {
            0 if threshold != 0 => return Err(RuleTableError::ThresholdWithoutGuard),
            0 => Guard::Always,
            1 => Guard::AboveAmount(threshold),
            2 if threshold == 0 => Guard::AboveAmountByAsset,
            2 => return Err(RuleTableError::ThresholdWithoutGuard),
            _ => return Err(RuleTableError::UnknownGuardTag),
        };
        let rule = Self {
            subject,
            source,
            guard,
        };
        rule.check().map(|()| rule)
    }

    const fn check(&self) -> Result<(), RuleTableError> {
        if matches!(self.subject, Subject::ExitDestination) {
            return Err(RuleTableError::ExitDestination);
        }
        match self.source {
            RuleSource::Lists { present, absent } if present.union(absent).is_empty() => {
                return Err(RuleTableError::EmptyLists)
            }
            RuleSource::Lists { present, absent } if present.intersects(absent) => {
                return Err(RuleTableError::ListInBothSets)
            }
            RuleSource::Lists { .. } => {}
        }
        match self.guard {
            Guard::AboveAmount(_) if matches!(self.subject, Subject::Sender) => {
                Err(RuleTableError::SenderGuard)
            }
            Guard::AboveAmount(0) => Err(RuleTableError::ZeroThreshold),
            Guard::AboveAmountByAsset if !matches!(self.subject, Subject::OutputOwner) => {
                Err(RuleTableError::PerAssetGuardNotOwner)
            }
            Guard::Always | Guard::AboveAmount(_) | Guard::AboveAmountByAsset => Ok(()),
        }
    }

    const fn signature(&self) -> u32 {
        let (present, absent) = match self.source {
            RuleSource::Lists { present, absent } => (present.bits(), absent.bits()),
        };
        ((self.subject as u32) << 16) | ((present as u32) << 8) | absent as u32
    }

    const fn disabled() -> Self {
        Self::require(Subject::OutputOwner, ListId::Allow)
    }
}

/// Bounds one transfer's outflow of `asset`, zero leaves a bound off.
#[derive(Clone, Copy, Debug, PartialEq, Eq, SchemaRead, SchemaWrite)]
pub struct OutflowLimit {
    asset: [u8; 32],
    /// The transfer fails above it.
    pub cap: u64,
    /// The transfer needs the co-signer above it.
    pub cosign_above: u64,
}

impl OutflowLimit {
    pub const EMPTY: Self = Self {
        asset: [0u8; 32],
        cap: 0,
        cosign_above: 0,
    };

    /// Both bounds off.
    pub const fn of(asset: &Member) -> Self {
        Self {
            asset: *asset.as_bytes(),
            cap: 0,
            cosign_above: 0,
        }
    }

    #[must_use]
    pub const fn with_cap(self, cap: u64) -> Self {
        Self { cap, ..self }
    }

    #[must_use]
    pub const fn with_cosign_above(self, cosign_above: u64) -> Self {
        Self {
            cosign_above,
            ..self
        }
    }

    /// The field public slots carry for the asset.
    pub const fn asset(&self) -> &[u8; 32] {
        &self.asset
    }
}

/// The circuit can enforce every instance.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RuleTable {
    rules: [Rule; MAX_RULES],
    len: u8,
    inline_assets: [[u8; 32]; MAX_INLINE_ASSETS],
    inline_limits: [u64; MAX_INLINE_ASSETS],
    inline_len: u8,
    limits: [OutflowLimit; MAX_OUTFLOW_LIMITS],
    limit_len: u8,
}

impl RuleTable {
    pub const fn empty() -> Self {
        Self {
            rules: [Rule::disabled(); MAX_RULES],
            len: 0,
            inline_assets: [[0u8; 32]; MAX_INLINE_ASSETS],
            inline_limits: [0; MAX_INLINE_ASSETS],
            inline_len: 0,
            limits: [OutflowLimit::EMPTY; MAX_OUTFLOW_LIMITS],
            limit_len: 0,
        }
    }

    pub const fn builder() -> RuleTableBuilder {
        RuleTableBuilder {
            table: Self::empty(),
            rule_count: 0,
            member_count: 0,
            limit_count: 0,
            outflow_count: 0,
        }
    }

    pub fn rules(&self) -> &[Rule] {
        &self.rules[..usize::from(self.len)]
    }

    pub fn inline_assets(&self) -> &[[u8; 32]] {
        &self.inline_assets[..usize::from(self.inline_len)]
    }

    pub fn inline_limits(&self) -> &[u64] {
        &self.inline_limits[..usize::from(self.inline_len)]
    }

    pub fn limits(&self) -> &[OutflowLimit] {
        &self.limits[..usize::from(self.limit_len)]
    }

    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub const fn referenced(&self) -> ListSet {
        let mut set = ListSet::EMPTY;
        let mut i = 0;
        while i < self.len as usize {
            set = set.union(self.rules[i].referenced());
            i += 1;
        }
        set
    }

    pub fn encode(&self) -> EncodedRuleTable {
        let mut encoded = EncodedRuleTable {
            rule_count: self.len,
            inline_count: self.inline_len,
            inline_assets: self.inline_assets,
            inline_limits: self.inline_limits.map(u64::to_be_bytes),
            limit_count: self.limit_len,
            ..EncodedRuleTable::default()
        };
        for (row, rule) in encoded.rules.iter_mut().zip(self.rules()) {
            *row = rule.encoded();
        }
        encoded.write_limit_columns(self.limits());
        encoded
    }

    pub fn hash(&self, sources: &SourceMap) -> Result<[u8; 32], HasherError> {
        self.encode().hash(sources)
    }
}

/// Const-evaluable, an illegal table fails the consuming build, never a transaction.
#[derive(Clone, Copy, Debug)]
pub struct RuleTableBuilder {
    table: RuleTable,
    rule_count: usize,
    member_count: usize,
    limit_count: usize,
    outflow_count: usize,
}

impl RuleTableBuilder {
    #[must_use]
    pub const fn rule(mut self, rule: Rule) -> Self {
        push(&mut self.table.rules, &mut self.rule_count, &[rule]);
        self
    }

    #[must_use]
    pub const fn inline_assets(mut self, members: &[[u8; 32]]) -> Self {
        push(
            &mut self.table.inline_assets,
            &mut self.member_count,
            members,
        );
        self
    }

    #[must_use]
    pub const fn inline_limits(mut self, limits: &[u64]) -> Self {
        push(&mut self.table.inline_limits, &mut self.limit_count, limits);
        self
    }

    #[must_use]
    pub const fn limits(mut self, limits: &[OutflowLimit]) -> Self {
        push(&mut self.table.limits, &mut self.outflow_count, limits);
        self
    }

    pub const fn try_build(mut self) -> Result<RuleTable, RuleTableError> {
        if self.rule_count > MAX_RULES {
            return Err(RuleTableError::TooManyRules);
        }
        if self.member_count > MAX_INLINE_ASSETS {
            return Err(RuleTableError::TooManyInlineAssets);
        }
        if self.limit_count > MAX_INLINE_ASSETS {
            return Err(RuleTableError::TooManyInlineAssets);
        }
        if self.outflow_count > MAX_OUTFLOW_LIMITS {
            return Err(RuleTableError::TooManyOutflowLimits);
        }
        self.table.len = self.rule_count as u8;
        self.table.inline_len = self.member_count as u8;
        self.table.limit_len = self.outflow_count as u8;
        let table = self.table;
        let mut m = 0;
        while m < self.member_count {
            if is_zero(&table.inline_assets[m]) {
                return Err(RuleTableError::ZeroInlineAsset);
            }
            m += 1;
        }
        let mut per_asset_guard = false;
        let mut i = 0;
        while i < self.rule_count {
            let rule = table.rules[i];
            if let Err(error) = rule.check() {
                return Err(error);
            }
            let mut j = 0;
            while j < i {
                if table.rules[j].signature() == rule.signature() {
                    return Err(RuleTableError::DuplicateRule);
                }
                j += 1;
            }
            if matches!(rule.guard, Guard::AboveAmountByAsset) {
                per_asset_guard = true;
            }
            i += 1;
        }
        if !per_asset_guard && self.member_count > 0 {
            return Err(RuleTableError::PoolWithoutInlineRule);
        }

        if per_asset_guard {
            if self.member_count == 0 || self.limit_count != self.member_count {
                return Err(RuleTableError::MissingAssetLimit);
            }
            let mut i = 0;
            while i < self.member_count {
                if table.inline_limits[i] == 0 {
                    return Err(RuleTableError::MissingAssetLimit);
                }
                let mut j = 0;
                while j < i {
                    if equal(&table.inline_assets[j], &table.inline_assets[i]) {
                        return Err(RuleTableError::DuplicateInlineAsset);
                    }
                    j += 1;
                }
                i += 1;
            }
        } else if self.limit_count != 0 {
            return Err(RuleTableError::AssetLimitWithoutGuard);
        }
        let mut v = 0;
        while v < self.outflow_count {
            let limit = table.limits[v];
            if is_zero(&limit.asset) {
                return Err(RuleTableError::ZeroLimitAsset);
            }
            if limit.cap == 0 && limit.cosign_above == 0 {
                return Err(RuleTableError::LimitWithoutBound);
            }
            let mut w = 0;
            while w < v {
                if equal(&table.limits[w].asset, &limit.asset) {
                    return Err(RuleTableError::DuplicateLimitAsset);
                }
                w += 1;
            }
            v += 1;
        }
        Ok(table)
    }

    pub const fn build(self) -> RuleTable {
        match self.try_build() {
            Ok(table) => table,
            Err(error) => panic!("{}", error.message()),
        }
    }
}

/// Counts every item and stores those that fit, `try_build` refuses an overflowing count.
const fn push<T: Copy, const N: usize>(slots: &mut [T; N], len: &mut usize, items: &[T]) {
    let mut i = 0;
    while i < items.len() {
        if *len < N {
            slots[*len] = items[i];
        }
        *len += 1;
        i += 1;
    }
}

const fn is_zero(bytes: &[u8; 32]) -> bool {
    equal(bytes, &[0u8; 32])
}

const fn equal(left: &[u8; 32], right: &[u8; 32]) -> bool {
    let mut i = 0;
    while i < left.len() {
        if left[i] != right[i] {
            return false;
        }
        i += 1;
    }
    true
}

/// Rows past `rule_count` and members past `inline_count` stay zero.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Pod, Zeroable)]
#[repr(C)]
pub struct EncodedRuleTable {
    pub rule_count: u8,
    pub rules: [[u8; 32]; MAX_RULES],
    pub inline_count: u8,
    pub inline_assets: [[u8; 32]; MAX_INLINE_ASSETS],
    pub inline_limits: [[u8; 8]; MAX_INLINE_ASSETS],
    pub limit_count: u8,
    pub limit_assets: [[u8; 32]; MAX_OUTFLOW_LIMITS],
    pub limit_caps: [[u8; 8]; MAX_OUTFLOW_LIMITS],
    pub limit_cosign: [[u8; 8]; MAX_OUTFLOW_LIMITS],
}

/// Wire parts of a table, `encode` checks the counts and `decode` the rest.
#[derive(Clone, Copy, Debug)]
pub struct TableParts<'a> {
    pub rows: &'a [[u8; 32]],
    pub inline_assets: &'a [[u8; 32]],
    pub inline_limits: &'a [u64],
    pub limits: &'a [OutflowLimit],
}

impl TableParts<'_> {
    pub fn encode(self) -> Result<EncodedRuleTable, RuleTableError> {
        let Self {
            rows,
            inline_assets: inline,
            inline_limits: limits,
            limits: outflow,
        } = self;
        if rows.len() > MAX_RULES {
            return Err(RuleTableError::TooManyRules);
        }
        if inline.len() > MAX_INLINE_ASSETS || limits.len() > MAX_INLINE_ASSETS {
            return Err(RuleTableError::TooManyInlineAssets);
        }
        if limits.len() != inline.len() {
            return Err(RuleTableError::MissingAssetLimit);
        }
        if outflow.len() > MAX_OUTFLOW_LIMITS {
            return Err(RuleTableError::TooManyOutflowLimits);
        }
        let mut encoded = EncodedRuleTable {
            rule_count: rows.len() as u8,
            inline_count: inline.len() as u8,
            limit_count: outflow.len() as u8,
            ..EncodedRuleTable::default()
        };
        encoded.rules[..rows.len()].copy_from_slice(rows);
        encoded.inline_assets[..inline.len()].copy_from_slice(inline);
        for (dst, limit) in encoded.inline_limits.iter_mut().zip(limits) {
            *dst = limit.to_be_bytes();
        }
        encoded.write_limit_columns(outflow);
        Ok(encoded)
    }
}

impl EncodedRuleTable {
    pub const SIZE: usize = core::mem::size_of::<Self>();

    pub const fn has_limits(&self) -> bool {
        self.limit_count != 0
    }

    pub fn decode(&self) -> Result<RuleTable, RuleTableError> {
        let Counted {
            rows,
            members,
            limits,
        } = self.counted()?;
        if !zero_past(&self.rules, rows.len())
            || !zero_past(&self.inline_assets, members.len())
            || !zero_past(&self.inline_limits, limits.len())
        {
            return Err(RuleTableError::NonZeroPadding);
        }
        let outflow = self.outflow_limits()?;
        let count = outflow.len();
        if !zero_past(&self.limit_assets, count)
            || !zero_past(&self.limit_caps, count)
            || !zero_past(&self.limit_cosign, count)
        {
            return Err(RuleTableError::NonZeroPadding);
        }
        let limits: Vec<u64> = limits.iter().copied().map(u64::from_be_bytes).collect();
        let mut builder = RuleTable::builder().inline_assets(members).limits(&outflow);
        if limits.iter().any(|limit| *limit != 0) {
            builder = builder.inline_limits(&limits);
        }
        for row in rows {
            builder = builder.rule(Rule::decode(row)?);
        }
        builder.try_build()
    }

    pub fn referenced(&self) -> ListSet {
        self.rules
            .iter()
            .take(usize::from(self.rule_count))
            .map(|bytes| {
                let row: &Row = bytemuck::cast_ref(bytes);
                ListSet::from_bits(row.mask | row.alternative)
            })
            .fold(ListSet::EMPTY, ListSet::union)
    }

    /// The table a policy write stores, every check the circuit leaves to the program.
    pub fn validate(&self, sources: &SourceMap) -> Result<RuleTable, PolicyTableError> {
        let table = self.decode()?;
        let referenced = self.referenced();
        if !referenced.is_subset(ListSet::AUTHORITY_WRITES) {
            return Err(RuleTableError::MemberWrittenList.into());
        }
        match referenced
            .iter()
            .find(|list_id| sources.registry(*list_id).is_none())
        {
            Some(list_id) => Err(PolicyTableError::MissingSource(list_id)),
            None => Ok(table),
        }
    }

    /// Every slot past a count enters as stored, `validate` keeps it zero.
    pub fn fields(&self, sources: &SourceMap) -> [[u8; 32]; POLICY_TABLE_FIELDS] {
        let header = [
            right_align(&POLICY_TABLE_DOMAIN.to_be_bytes()),
            field_u8(POLICY_TABLE_VERSION),
        ];
        let counts = [
            field_u8(self.rule_count),
            field_u8(self.inline_count),
            field_u8(self.limit_count),
        ];
        let values = header
            .into_iter()
            .chain(
                sources
                    .slots()
                    .iter()
                    .flat_map(|slot| [field_u8(slot.list_id), slot.registry]),
            )
            .chain(counts)
            .chain(self.rules.iter().copied())
            .chain(self.inline_assets.iter().copied())
            .chain(self.inline_limits.iter().map(right_align))
            .chain(
                self.limit_assets
                    .iter()
                    .zip(&self.limit_caps)
                    .zip(&self.limit_cosign)
                    .flat_map(|((asset, cap), cosign)| {
                        [*asset, right_align(cap), right_align(cosign)]
                    }),
            );
        let mut fields = [[0u8; 32]; POLICY_TABLE_FIELDS];
        for (field, value) in fields.iter_mut().zip(values) {
            *field = value;
        }
        fields
    }

    /// `acc = Poseidon(acc, fields[11c..11c + 11])` from `acc = 0`, mirror
    /// `prover/server/custom_rings/circuits/policy`.
    pub fn hash(&self, sources: &SourceMap) -> Result<[u8; 32], HasherError> {
        let fields = self.fields(sources);
        let mut acc = [0u8; 32];
        for chunk in fields.as_chunks::<POLICY_TABLE_RATE>().0 {
            let mut inputs: [&[u8]; POLICY_TABLE_RATE + 1] = [&[]; POLICY_TABLE_RATE + 1];
            inputs[0] = &acc;
            for (input, field) in inputs[1..].iter_mut().zip(chunk) {
                *input = field;
            }
            acc = Poseidon::hashv(&inputs)?;
        }
        Ok(acc)
    }

    fn counted(&self) -> Result<Counted<'_>, RuleTableError> {
        Ok(Counted {
            rows: self
                .rules
                .get(..usize::from(self.rule_count))
                .ok_or(RuleTableError::TooManyRules)?,
            members: self
                .inline_assets
                .get(..usize::from(self.inline_count))
                .ok_or(RuleTableError::TooManyInlineAssets)?,
            limits: self
                .inline_limits
                .get(..usize::from(self.inline_count))
                .ok_or(RuleTableError::TooManyInlineAssets)?,
        })
    }

    fn outflow_limits(&self) -> Result<Vec<OutflowLimit>, RuleTableError> {
        let assets = self
            .limit_assets
            .get(..usize::from(self.limit_count))
            .ok_or(RuleTableError::TooManyOutflowLimits)?;
        let limits = assets
            .iter()
            .zip(&self.limit_caps)
            .zip(&self.limit_cosign)
            .map(|((asset, cap), cosign)| OutflowLimit {
                asset: *asset,
                cap: u64::from_be_bytes(*cap),
                cosign_above: u64::from_be_bytes(*cosign),
            });
        Ok(limits.collect())
    }

    fn write_limit_columns(&mut self, limits: &[OutflowLimit]) {
        let columns = self
            .limit_assets
            .iter_mut()
            .zip(&mut self.limit_caps)
            .zip(&mut self.limit_cosign);
        for (((asset, cap), cosign), limit) in columns.zip(limits) {
            *asset = limit.asset;
            *cap = limit.cap.to_be_bytes();
            *cosign = limit.cosign_above.to_be_bytes();
        }
    }
}

struct Counted<'a> {
    rows: &'a [[u8; 32]],
    members: &'a [[u8; 32]],
    limits: &'a [[u8; 8]],
}

fn zero_past<const N: usize>(slots: &[[u8; N]], len: usize) -> bool {
    slots[len..].iter().all(|slot| *slot == [0u8; N])
}

const _: () = assert!(EncodedRuleTable::SIZE == 1219);
const _: () = assert!(core::mem::align_of::<EncodedRuleTable>() == 1);

#[cfg(test)]
mod tests {
    use super::*;

    const ASSETS: &[[u8; 32]] = &[[3u8; 32]];
    const POOL: [[u8; 32]; MAX_INLINE_ASSETS] = [
        [1u8; 32], [2u8; 32], [3u8; 32], [4u8; 32], [5u8; 32], [6u8; 32], [7u8; 32], [8u8; 32],
    ];

    const TABLE: RuleTable = RuleTable::builder()
        .rule(Rule::require(Subject::OutputOwner, ListId::Allow))
        .rule(Rule::forbid(Subject::Sender, ListId::Frozen))
        .rule(Rule::require(Subject::Asset, ListId::Allow))
        .build();

    const EMPTY: RuleTable = RuleTable::builder().build();

    const GROUP: RuleTable = RuleTable::builder()
        .rule(Rule::require_any(
            Subject::OutputOwner,
            ListSet::of(&[ListId::Allow, ListId::Frozen]),
        ))
        .build();

    const LIMIT: OutflowLimit = OutflowLimit {
        asset: [3u8; 32],
        cap: 1000,
        cosign_above: 400,
    };
    const LIMITED: RuleTable = RuleTable::builder().limits(&[LIMIT]).build();

    fn outflow_limits(count: u8) -> Vec<OutflowLimit> {
        (1..=count)
            .map(|byte| OutflowLimit {
                asset: [byte; 32],
                ..LIMIT
            })
            .collect()
    }

    fn from_parts(
        rows: &[[u8; 32]],
        inline: &[[u8; 32]],
    ) -> Result<EncodedRuleTable, RuleTableError> {
        let limits = [0; MAX_INLINE_ASSETS];
        from_parts_with_limits(rows, inline, &limits[..inline.len().min(MAX_INLINE_ASSETS)])
    }

    fn from_parts_with_limits(
        rows: &[[u8; 32]],
        inline: &[[u8; 32]],
        limits: &[u64],
    ) -> Result<EncodedRuleTable, RuleTableError> {
        TableParts {
            rows,
            inline_assets: inline,
            inline_limits: limits,
            limits: &[],
        }
        .encode()
    }

    fn sources(entries: &[(ListId, [u8; 32])]) -> SourceMap {
        SourceMap::new(entries).unwrap()
    }

    /// `tail` is `[guard_tag, mask, mode, subject]`.
    fn packed(tail: [u8; 4], threshold: u64, alternative: u8) -> [u8; 32] {
        let mut row = [0u8; 32];
        row[19] = alternative;
        row[20..28].copy_from_slice(&threshold.to_be_bytes());
        row[28..].copy_from_slice(&tail);
        row
    }

    fn sender_rules() -> impl Iterator<Item = Rule> {
        ListId::ALL
            .into_iter()
            .map(|list_id| Rule::require(Subject::Sender, list_id))
            .chain(
                ListId::ALL
                    .into_iter()
                    .map(|list_id| Rule::forbid(Subject::Sender, list_id)),
            )
    }

    fn with_rules(
        mut builder: RuleTableBuilder,
        rules: impl Iterator<Item = Rule>,
    ) -> RuleTableBuilder {
        for rule in rules {
            builder = builder.rule(rule);
        }
        builder
    }

    #[test]
    fn the_table_keeps_declaration_order_and_the_pool() {
        let rules = TABLE.rules();
        assert_eq!(rules.len(), 3);
        assert_eq!(rules[0].subject, Subject::OutputOwner);
        assert_eq!(rules[1].primary_mode(), Mode::Absent);
        assert_eq!(rules[2], Rule::require(Subject::Asset, ListId::Allow));
        assert!(TABLE.inline_assets().is_empty());
        assert_eq!(RuleTable::empty(), EMPTY);
        assert!(EMPTY.is_empty());
        assert_eq!(EMPTY.encode(), EncodedRuleTable::default());
    }

    #[test]
    fn an_own_list_maps_to_the_zero_registry_and_one_curator_serves_the_rest() {
        let map = sources(&[(ListId::Allow, [0u8; 32]), (ListId::Block, [9u8; 32])]);
        assert_eq!(map.registry(ListId::Allow), Some(&[0u8; 32]));
        assert_eq!(map.registry(ListId::Block), Some(&[9u8; 32]));
        assert_eq!(map.registry(ListId::Frozen), None);
        assert_eq!(map.curator(), Some([9u8; 32]));
        assert_eq!(sources(&[(ListId::Allow, [0u8; 32])]).curator(), None);
        assert_eq!(
            SourceMap::new(&[(ListId::Allow, [9u8; 32]), (ListId::Block, [8u8; 32])]),
            Err(SourceMapError::SeveralCurators)
        );
        let mut slots = *map.slots();
        slots[ListId::Frozen.slot()] = PolicySource {
            list_id: ListId::Frozen as u8,
            registry: [8u8; 32],
        };
        assert_eq!(
            SourceMap::from_slots(slots),
            Err(SourceMapError::SeveralCurators)
        );
    }

    #[test]
    fn rows_pack_the_circuit_byte_positions() {
        assert_eq!(
            Rule::require(Subject::OutputOwner, ListId::Allow).encoded(),
            packed([0, 0b0000_0001, 1, 1], 0, 0)
        );
        assert_eq!(
            Rule::forbid(Subject::Sender, ListId::Frozen).encoded(),
            packed([0, 0b0000_0100, 2, 2], 0, 0)
        );
        assert_eq!(
            Rule::require(Subject::OutputOwner, ListId::Approval)
                .above(2000)
                .encoded(),
            packed([1, 0b0100_0000, 1, 1], 2000, 0)
        );
        assert_eq!(
            Rule::require(Subject::Asset, ListId::Allow).encoded(),
            packed([0, 1, 1, 4], 0, 0)
        );
        assert_eq!(
            Rule::any_of(
                Subject::OutputOwner,
                ListSet::single(ListId::Allow),
                ListSet::single(ListId::Block),
            )
            .encoded(),
            packed([0, 0b0000_0001, 1, 1], 0, 0b0000_0010)
        );
        assert_eq!(
            Rule::forbid_all(
                Subject::OutputOwner,
                ListSet::of(&[ListId::Block, ListId::Frozen])
            )
            .encoded(),
            packed([0, 0b0000_0110, 2, 1], 0, 0)
        );
        assert_eq!(
            Rule::require_any(
                Subject::Sender,
                ListSet::of(&[ListId::Allow, ListId::Frozen])
            )
            .encoded(),
            packed([0, 0b0000_0101, 1, 2], 0, 0)
        );
    }

    #[test]
    fn a_group_references_the_union_of_its_lists() {
        assert_eq!(
            Rule::require(Subject::OutputOwner, ListId::Allow)
                .referenced()
                .bits(),
            0b0000_0001
        );
        assert_eq!(
            Rule::any_of(
                Subject::OutputOwner,
                ListSet::single(ListId::Allow),
                ListSet::single(ListId::Frozen),
            )
            .referenced()
            .bits(),
            0b0000_0101
        );
        assert_eq!(
            Rule::forbid_all(
                Subject::OutputOwner,
                ListSet::of(&[ListId::Block, ListId::Frozen])
            )
            .referenced()
            .bits(),
            0b0000_0110
        );
        assert_eq!(
            Rule::require(Subject::Asset, ListId::Allow).referenced(),
            ListSet::single(ListId::Allow)
        );
        assert_eq!(
            TABLE.referenced(),
            ListSet::of(&[ListId::Allow, ListId::Frozen])
        );
        assert_eq!(TABLE.encode().referenced(), TABLE.referenced());
    }

    #[test]
    fn every_constructor_round_trips_through_its_row() {
        let rules = [
            Rule::require(Subject::OutputOwner, ListId::Allow),
            Rule::forbid(Subject::Sender, ListId::Frozen),
            Rule::require_any(
                Subject::Sender,
                ListSet::of(&[ListId::Allow, ListId::Approval]),
            ),
            Rule::forbid_all(
                Subject::OutputOwner,
                ListSet::of(&[ListId::Block, ListId::Frozen]),
            ),
            Rule::any_of(
                Subject::OutputOwner,
                ListSet::single(ListId::Allow),
                ListSet::single(ListId::Block),
            ),
            Rule::require(Subject::Asset, ListId::Allow),
            Rule::require(Subject::OutputOwner, ListId::Approval).above(2000),
            Rule::require(Subject::Asset, ListId::Allow).above(u64::MAX),
        ];
        for rule in rules {
            assert_eq!(Rule::decode(&rule.encoded()), Ok(rule));
        }
    }

    type Tamper = fn(&mut [u8; 32]);

    #[test]
    fn decode_refuses_every_row_encoded_never_emits() {
        let base = Rule::require(Subject::OutputOwner, ListId::Allow);
        let cases: [(Tamper, RuleTableError); 16] = [
            (|row| row[0] = 1, RuleTableError::ReservedBytes),
            (|row| row[18] = 1, RuleTableError::ReservedBytes),
            (|row| row[31] = 0, RuleTableError::UnknownSubject),
            (|row| row[31] = 3, RuleTableError::ExitDestination),
            (|row| row[31] = 5, RuleTableError::UnknownSubject),
            (|row| row[30] = 0, RuleTableError::UnknownMode),
            (|row| row[30] = 3, RuleTableError::UnknownMode),
            (|row| row[19] = 0b0000_0001, RuleTableError::ListInBothSets),
            (
                |row| {
                    row[30] = 2;
                    row[19] = 0b0000_0010;
                },
                RuleTableError::NonCanonicalAlternative,
            ),
            (
                |row| {
                    row[29] = 0;
                    row[19] = 0b0000_0010;
                },
                RuleTableError::EmptyLists,
            ),
            (
                |row| {
                    row[29] = 0;
                    row[30] = 2;
                },
                RuleTableError::EmptyLists,
            ),
            (|row| row[29] = 0, RuleTableError::EmptyLists),
            (|row| row[28] = 3, RuleTableError::UnknownGuardTag),
            (|row| row[27] = 1, RuleTableError::ThresholdWithoutGuard),
            (|row| row[28] = 1, RuleTableError::ZeroThreshold),
            (
                |row| {
                    row[31] = 2;
                    row[28] = 1;
                    row[27] = 1;
                },
                RuleTableError::SenderGuard,
            ),
        ];
        for (edit, expected) in cases {
            let mut row = base.encoded();
            edit(&mut row);
            assert_eq!(Rule::decode(&row), Err(expected), "{expected:?}");
        }
    }

    #[test]
    fn alternatives_list_presences_before_absences_in_slot_order() {
        let rule = Rule::any_of(
            Subject::OutputOwner,
            ListSet::of(&[ListId::Frozen, ListId::Allow]),
            ListSet::of(&[ListId::Escrow, ListId::Block]),
        );
        assert_eq!(
            rule.alternatives().collect::<Vec<_>>(),
            [
                (ListId::Allow, Mode::Present),
                (ListId::Frozen, Mode::Present),
                (ListId::Block, Mode::Absent),
                (ListId::Escrow, Mode::Absent),
            ]
        );
        assert_eq!(rule.primary_mode(), Mode::Present);
        assert_eq!(
            Rule::forbid(Subject::Sender, ListId::Frozen)
                .alternatives()
                .collect::<Vec<_>>(),
            [(ListId::Frozen, Mode::Absent)]
        );
        assert_eq!(
            Rule::require(Subject::Asset, ListId::Allow)
                .alternatives()
                .count(),
            1
        );
    }

    #[test]
    fn validation_needs_a_source_for_every_list_of_a_group() {
        let both = sources(&[(ListId::Allow, [0u8; 32]), (ListId::Frozen, [5u8; 32])]);
        assert_eq!(GROUP.encode().validate(&both), Ok(GROUP));
        let only_one = sources(&[(ListId::Allow, [0u8; 32])]);
        assert_eq!(
            GROUP.encode().validate(&only_one),
            Err(PolicyTableError::MissingSource(ListId::Frozen))
        );
    }

    #[test]
    #[should_panic(expected = "a group names no list")]
    fn an_empty_group_is_rejected() {
        let _ = RuleTable::builder()
            .rule(Rule::require_any(Subject::OutputOwner, ListSet::EMPTY))
            .build();
    }

    #[test]
    fn rule_encoding_is_injective_over_every_field() {
        let base = Rule::require(Subject::OutputOwner, ListId::Allow);
        let variants = [
            base,
            Rule::require(Subject::Sender, ListId::Allow),
            Rule::require(Subject::OutputOwner, ListId::Block),
            Rule::forbid(Subject::OutputOwner, ListId::Allow),
            Rule::any_of(
                Subject::OutputOwner,
                ListSet::single(ListId::Allow),
                ListSet::single(ListId::Block),
            ),
            Rule::require(Subject::OutputOwner, ListId::Allow).above(5),
            Rule::require(Subject::OutputOwner, ListId::Allow).above(6),
            Rule::require(Subject::Asset, ListId::Allow),
        ];
        for (i, a) in variants.iter().enumerate() {
            for b in variants.iter().skip(i + 1) {
                assert_ne!(a.encoded(), b.encoded());
            }
        }
    }

    #[test]
    fn policy_hash_binds_the_sources_and_the_inline_members() {
        let map = sources(&[(ListId::Allow, [0u8; 32]), (ListId::Frozen, [5u8; 32])]);
        let baseline = TABLE.hash(&map).unwrap();
        let other_registry = sources(&[(ListId::Allow, [0u8; 32]), (ListId::Frozen, [6u8; 32])]);
        assert_ne!(baseline, TABLE.hash(&other_registry).unwrap());
        let extra_slot = sources(&[
            (ListId::Allow, [0u8; 32]),
            (ListId::Frozen, [5u8; 32]),
            (ListId::Escrow, [5u8; 32]),
        ]);
        assert_ne!(baseline, TABLE.hash(&extra_slot).unwrap());
        const REORDERED: RuleTable = RuleTable::builder()
            .rule(Rule::forbid(Subject::Sender, ListId::Frozen))
            .rule(Rule::require(Subject::OutputOwner, ListId::Allow))
            .rule(Rule::require(Subject::Asset, ListId::Allow))
            .build();
        assert_ne!(baseline, REORDERED.hash(&map).unwrap());
        const OTHER_ASSETS: RuleTable = RuleTable::builder()
            .rule(Rule::require(Subject::OutputOwner, ListId::Allow))
            .rule(Rule::forbid(Subject::Sender, ListId::Frozen))
            .rule(Rule::forbid(Subject::Asset, ListId::Frozen))
            .build();
        assert_ne!(baseline, OTHER_ASSETS.hash(&map).unwrap());
    }

    #[test]
    fn per_asset_limits_round_trip_and_bind_the_hash() {
        const LIMITS: RuleTable = RuleTable::builder()
            .rule(Rule::require(Subject::OutputOwner, ListId::Allow).above_by_asset())
            .inline_assets(&[[3u8; 32], [4u8; 32]])
            .inline_limits(&[5, 7])
            .build();
        const OTHER: RuleTable = RuleTable::builder()
            .rule(Rule::require(Subject::OutputOwner, ListId::Allow).above_by_asset())
            .inline_assets(&[[3u8; 32], [4u8; 32]])
            .inline_limits(&[5, 8])
            .build();
        let map = sources(&[(ListId::Allow, [4u8; 32])]);
        assert_eq!(LIMITS.inline_limits(), &[5, 7]);
        assert_eq!(LIMITS.encode().decode(), Ok(LIMITS));
        assert_ne!(LIMITS.hash(&map).unwrap(), OTHER.hash(&map).unwrap());
    }

    #[test]
    fn validation_refuses_an_overlong_count_and_a_rule_without_a_source() {
        let map = sources(&[(ListId::Allow, [4u8; 32]), (ListId::Frozen, [4u8; 32])]);
        assert_eq!(TABLE.encode().validate(&map), Ok(TABLE));
        let mut overflowing = TABLE.encode();
        overflowing.rule_count = MAX_RULES as u8 + 1;
        assert_eq!(
            overflowing.validate(&map),
            Err(PolicyTableError::Table(RuleTableError::TooManyRules))
        );
        let allow_only = sources(&[(ListId::Allow, [4u8; 32])]);
        assert_eq!(
            TABLE.encode().validate(&allow_only),
            Err(PolicyTableError::MissingSource(ListId::Frozen))
        );
    }

    #[test]
    fn validation_refuses_a_rule_over_a_list_its_members_write() {
        for list_id in [ListId::RingViewing, ListId::Recovery, ListId::Escrow] {
            let map = sources(&[(ListId::Allow, [0u8; 32]), (list_id, [0u8; 32])]);
            let required = RuleTable::builder()
                .rule(Rule::require(Subject::OutputOwner, list_id))
                .build();
            let alternative = RuleTable::builder()
                .rule(Rule::any_of(
                    Subject::Sender,
                    ListSet::single(ListId::Allow),
                    ListSet::single(list_id),
                ))
                .build();
            for table in [required, alternative] {
                assert_eq!(
                    table.encode().validate(&map),
                    Err(PolicyTableError::Table(RuleTableError::MemberWrittenList)),
                    "{list_id:?}"
                );
            }
        }
    }

    #[test]
    fn table_fields_follow_the_circuit_order() {
        const FULL: RuleTable = RuleTable::builder()
            .rule(Rule::require(Subject::OutputOwner, ListId::Allow).above_by_asset())
            .inline_assets(&[[3u8; 32]])
            .inline_limits(&[9])
            .limits(&[LIMIT])
            .build();
        let map = sources(&[(ListId::Allow, [4u8; 32])]);
        let fields = FULL.encode().fields(&map);
        assert_eq!(fields[0], right_align(b"CRTB"));
        assert_eq!(fields[1], field_u8(POLICY_TABLE_VERSION));
        assert_eq!((fields[2], fields[3]), (field_u8(1), [4u8; 32]));
        assert_eq!(fields[4], [0u8; 32]);
        assert_eq!(fields[18..21], [field_u8(1), field_u8(1), field_u8(1)]);
        assert_eq!(fields[21], FULL.rules()[0].encoded());
        assert_eq!(fields[37], [3u8; 32]);
        assert_eq!(fields[45], right_align(&9u64.to_be_bytes()));
        assert_eq!(
            fields[53..56],
            [
                LIMIT.asset,
                right_align(&1000u64.to_be_bytes()),
                right_align(&400u64.to_be_bytes())
            ]
        );
        assert!(fields[56..].iter().all(|field| *field == [0u8; 32]));
    }

    #[test]
    fn the_hash_absorbs_the_last_source_and_the_last_limit_field() {
        let map = SourceMap::default();
        let baseline = LIMITED.hash(&map).unwrap();
        let last_source = sources(&[(ListId::Escrow, [6u8; 32])]);
        assert_ne!(baseline, LIMITED.hash(&last_source).unwrap());
        let mut last_cosign = LIMITED.encode();
        last_cosign.limit_cosign[MAX_OUTFLOW_LIMITS - 1] = 1u64.to_be_bytes();
        assert_ne!(baseline, last_cosign.hash(&map).unwrap());
    }

    #[test]
    fn an_empty_table_hashes_the_empty_map() {
        let baseline = EMPTY.hash(&SourceMap::default()).unwrap();
        let with_slot = sources(&[(ListId::Allow, [4u8; 32])]);
        assert_ne!(baseline, EMPTY.hash(&with_slot).unwrap());
    }

    #[test]
    fn the_source_map_is_positional_and_rejects_duplicates() {
        assert_eq!(
            SourceMap::new(&[(ListId::Allow, [4u8; 32]), (ListId::Allow, [5u8; 32]),]),
            Err(SourceMapError::Duplicate)
        );
        let map = sources(&[(ListId::Frozen, [5u8; 32])]);
        assert_eq!(SourceMap::from_slots(*map.slots()), Ok(map));
        let mut slots = *map.slots();
        slots.swap(0, 2);
        assert_eq!(
            SourceMap::from_slots(slots),
            Err(SourceMapError::NotPositional)
        );
        let mut empty_with_registry = *map.slots();
        empty_with_registry[0].registry = [6u8; 32];
        assert_eq!(
            SourceMap::from_slots(empty_with_registry),
            Err(SourceMapError::NotPositional)
        );
    }

    #[test]
    fn a_full_image_round_trips() {
        let table = with_rules(
            RuleTable::builder()
                .rule(Rule::require(Subject::OutputOwner, ListId::Allow).above_by_asset())
                .inline_assets(&POOL)
                .inline_limits(&[1; MAX_INLINE_ASSETS]),
            sender_rules().take(MAX_RULES - 1),
        )
        .build();
        let encoded = table.encode();
        assert_eq!(usize::from(encoded.rule_count), MAX_RULES);
        assert_eq!(usize::from(encoded.inline_count), MAX_INLINE_ASSETS);
        assert_eq!(encoded.decode(), Ok(table));
        assert_eq!(encoded.referenced(), ListSet::from_bits(u8::MAX));
        let rows: Vec<[u8; 32]> = table.rules().iter().map(Rule::encoded).collect();
        assert_eq!(
            from_parts_with_limits(&rows, &POOL, &[1; MAX_INLINE_ASSETS]),
            Ok(encoded)
        );
        let seventeen: Vec<[u8; 32]> = rows.iter().chain(&rows[..1]).copied().collect();
        assert_eq!(
            from_parts(&seventeen, &POOL),
            Err(RuleTableError::TooManyRules)
        );
        let nine: Vec<[u8; 32]> = POOL.iter().chain(&POOL[..1]).copied().collect();
        assert_eq!(
            from_parts(&rows, &nine),
            Err(RuleTableError::TooManyInlineAssets)
        );
        assert_eq!(
            from_parts_with_limits(&rows, &POOL, &[1]),
            Err(RuleTableError::MissingAssetLimit)
        );
    }

    #[test]
    fn padding_past_the_counts_must_be_zero() {
        let mut row_padding = TABLE.encode();
        row_padding.rules[3][0] = 1;
        assert_eq!(row_padding.decode(), Err(RuleTableError::NonZeroPadding));
        let mut member_padding = TABLE.encode();
        member_padding.inline_assets[1][31] = 1;
        assert_eq!(member_padding.decode(), Err(RuleTableError::NonZeroPadding));
        let mut limit_padding = TABLE.encode();
        limit_padding.inline_limits[1][7] = 1;
        assert_eq!(limit_padding.decode(), Err(RuleTableError::NonZeroPadding));
        let mut rule_count = TABLE.encode();
        rule_count.rule_count = MAX_RULES as u8 + 1;
        assert_eq!(rule_count.decode(), Err(RuleTableError::TooManyRules));
        let mut inline_count = TABLE.encode();
        inline_count.inline_count = MAX_INLINE_ASSETS as u8 + 1;
        assert_eq!(
            inline_count.decode(),
            Err(RuleTableError::TooManyInlineAssets)
        );
        let mut row = TABLE.encode();
        row.rules[1][31] = 3;
        assert_eq!(row.decode(), Err(RuleTableError::ExitDestination));
    }

    #[test]
    fn try_build_names_each_refusal_and_build_panics_with_its_message() {
        let inline = RuleTable::builder()
            .rule(Rule::require(Subject::Asset, ListId::Allow))
            .inline_assets(ASSETS);
        let cases = [
            (
                with_rules(
                    RuleTable::builder(),
                    sender_rules().chain([Rule::require(Subject::Asset, ListId::Allow)]),
                ),
                RuleTableError::TooManyRules,
            ),
            (
                RuleTable::builder()
                    .rule(Rule::require(Subject::Asset, ListId::Allow))
                    .inline_assets(&POOL)
                    .inline_assets(ASSETS),
                RuleTableError::TooManyInlineAssets,
            ),
            (
                RuleTable::builder()
                    .rule(Rule::require(Subject::Asset, ListId::Allow))
                    .inline_assets(&[[0u8; 32]]),
                RuleTableError::ZeroInlineAsset,
            ),
            (
                RuleTable::builder()
                    .rule(Rule {
                        subject: Subject::Sender,
                        source: RuleSource::Lists {
                            present: ListSet::EMPTY,
                            absent: ListSet::EMPTY,
                        },
                        guard: Guard::Always,
                    })
                    .inline_assets(ASSETS),
                RuleTableError::EmptyLists,
            ),
            (
                RuleTable::builder().rule(Rule::require_any(Subject::Asset, ListSet::EMPTY)),
                RuleTableError::EmptyLists,
            ),
            (
                RuleTable::builder()
                    .rule(Rule::require(Subject::OutputOwner, ListId::Allow))
                    .inline_assets(ASSETS),
                RuleTableError::PoolWithoutInlineRule,
            ),
            (
                RuleTable::builder().rule(Rule::forbid_all(Subject::Sender, ListSet::EMPTY)),
                RuleTableError::EmptyLists,
            ),
            (
                RuleTable::builder().rule(Rule::any_of(
                    Subject::OutputOwner,
                    ListSet::single(ListId::Allow),
                    ListSet::of(&[ListId::Allow, ListId::Block]),
                )),
                RuleTableError::ListInBothSets,
            ),
            (
                RuleTable::builder().rule(Rule::forbid(Subject::Sender, ListId::Frozen).above(10)),
                RuleTableError::SenderGuard,
            ),
            (
                RuleTable::builder().rule(Rule::require(Subject::ExitDestination, ListId::Allow)),
                RuleTableError::ExitDestination,
            ),
            (
                RuleTable::builder()
                    .rule(Rule::require(Subject::OutputOwner, ListId::Approval).above(0)),
                RuleTableError::ZeroThreshold,
            ),
            (
                RuleTable::builder()
                    .rule(Rule::require(Subject::Asset, ListId::Approval).above_by_asset()),
                RuleTableError::PerAssetGuardNotOwner,
            ),
            (
                RuleTable::builder()
                    .rule(Rule::require(Subject::OutputOwner, ListId::Allow))
                    .rule(Rule::require(Subject::OutputOwner, ListId::Allow).above(10)),
                RuleTableError::DuplicateRule,
            ),
            (
                inline
                    .rule(Rule::require(Subject::OutputOwner, ListId::Allow).above(7))
                    .inline_assets(&[[4u8; 32]]),
                RuleTableError::PoolWithoutInlineRule,
            ),
            (
                RuleTable::builder().limits(&outflow_limits(MAX_OUTFLOW_LIMITS as u8 + 1)),
                RuleTableError::TooManyOutflowLimits,
            ),
            (
                RuleTable::builder().limits(&[OutflowLimit {
                    asset: [0u8; 32],
                    ..LIMIT
                }]),
                RuleTableError::ZeroLimitAsset,
            ),
            (
                RuleTable::builder().limits(&[OutflowLimit {
                    cap: 0,
                    cosign_above: 0,
                    ..LIMIT
                }]),
                RuleTableError::LimitWithoutBound,
            ),
            (
                RuleTable::builder().limits(&[LIMIT, LIMIT]),
                RuleTableError::DuplicateLimitAsset,
            ),
        ];
        for (builder, expected) in cases {
            assert_eq!(builder.try_build(), Err(expected), "{expected:?}");
            let payload = std::panic::catch_unwind(|| builder.build()).unwrap_err();
            assert_eq!(
                payload.downcast_ref::<String>().map(String::as_str),
                Some(expected.message()),
                "{expected:?}"
            );
        }
    }

    #[test]
    fn outflow_limits_round_trip_and_bind_the_hash() {
        let map = SourceMap::default();
        assert_eq!(LIMITED.limits(), &[LIMIT]);
        assert_eq!(LIMITED.encode().decode(), Ok(LIMITED));
        assert!(LIMITED.encode().has_limits());
        assert!(!EMPTY.encode().has_limits());
        let eight = outflow_limits(MAX_OUTFLOW_LIMITS as u8);
        let full = RuleTable::builder().limits(&eight).build();
        assert_eq!(full.limits(), eight.as_slice());
        assert_eq!(full.encode().decode(), Ok(full));
        let baseline = LIMITED.hash(&map).unwrap();
        let other_cap = RuleTable::builder()
            .limits(&[OutflowLimit { cap: 1001, ..LIMIT }])
            .build();
        let other_cosign = RuleTable::builder()
            .limits(&[OutflowLimit {
                cosign_above: 401,
                ..LIMIT
            }])
            .build();
        let other_asset = RuleTable::builder()
            .limits(&[OutflowLimit {
                asset: [4u8; 32],
                ..LIMIT
            }])
            .build();
        for other in [other_cap, other_cosign, other_asset, EMPTY] {
            assert_ne!(baseline, other.hash(&map).unwrap());
        }
    }

    #[test]
    fn limit_padding_past_the_count_must_be_zero() {
        let map = SourceMap::default();
        let mut asset_padding = LIMITED.encode();
        asset_padding.limit_assets[1][31] = 1;
        assert_eq!(asset_padding.decode(), Err(RuleTableError::NonZeroPadding));
        let mut cap_padding = LIMITED.encode();
        cap_padding.limit_caps[1][7] = 1;
        assert_eq!(cap_padding.decode(), Err(RuleTableError::NonZeroPadding));
        let mut cosign_padding = LIMITED.encode();
        cosign_padding.limit_cosign[1][7] = 1;
        assert_eq!(cosign_padding.decode(), Err(RuleTableError::NonZeroPadding));
        let mut limit_count = LIMITED.encode();
        limit_count.limit_count = MAX_OUTFLOW_LIMITS as u8 + 1;
        assert_eq!(
            limit_count.validate(&map),
            Err(PolicyTableError::Table(
                RuleTableError::TooManyOutflowLimits
            ))
        );
    }

    #[test]
    fn table_parts_pack_the_limit_section_and_check_its_width() {
        let parts = TableParts {
            rows: &[],
            inline_assets: &[],
            inline_limits: &[],
            limits: &[LIMIT],
        };
        assert_eq!(parts.encode(), Ok(LIMITED.encode()));
        assert_eq!(
            TableParts {
                limits: &outflow_limits(MAX_OUTFLOW_LIMITS as u8 + 1),
                ..parts
            }
            .encode(),
            Err(RuleTableError::TooManyOutflowLimits)
        );
    }

    #[test]
    fn signatures_ignore_the_guard_and_bind_both_sets() {
        let mixed = Rule::any_of(
            Subject::OutputOwner,
            ListSet::single(ListId::Allow),
            ListSet::single(ListId::Block),
        );
        assert_eq!(
            RuleTable::builder()
                .rule(mixed)
                .rule(mixed.above(5))
                .try_build(),
            Err(RuleTableError::DuplicateRule)
        );
        let distinct = RuleTable::builder()
            .rule(Rule::require_any(
                Subject::OutputOwner,
                ListSet::single(ListId::Allow),
            ))
            .rule(mixed)
            .try_build()
            .unwrap();
        assert_eq!(distinct.rules().len(), 2);
    }

    #[test]
    fn per_asset_limits_fail_closed_when_incomplete_or_ambiguous() {
        let rule = Rule::require(Subject::OutputOwner, ListId::Allow).above_by_asset();
        assert_eq!(
            RuleTable::builder().rule(rule).try_build(),
            Err(RuleTableError::MissingAssetLimit)
        );
        assert_eq!(
            RuleTable::builder()
                .rule(rule)
                .inline_assets(&[[3u8; 32]])
                .inline_limits(&[0])
                .try_build(),
            Err(RuleTableError::MissingAssetLimit)
        );
        assert_eq!(
            RuleTable::builder()
                .rule(rule)
                .inline_assets(&[[3u8; 32], [3u8; 32]])
                .inline_limits(&[5, 7])
                .try_build(),
            Err(RuleTableError::DuplicateInlineAsset)
        );
        assert_eq!(
            RuleTable::builder()
                .rule(Rule::require(Subject::Sender, ListId::Allow).above_by_asset())
                .inline_assets(&[[3u8; 32]])
                .inline_limits(&[5])
                .try_build(),
            Err(RuleTableError::PerAssetGuardNotOwner)
        );
        assert_eq!(
            RuleTable::builder()
                .rule(Rule::require(Subject::Asset, ListId::Allow))
                .inline_assets(&[[3u8; 32]])
                .inline_limits(&[5])
                .try_build(),
            Err(RuleTableError::PoolWithoutInlineRule)
        );
    }

    #[test]
    #[should_panic(expected = "duplicate rule")]
    fn duplicate_rules_are_rejected() {
        let _ = RuleTable::builder()
            .rule(Rule::require(Subject::OutputOwner, ListId::Allow))
            .rule(Rule::require(Subject::OutputOwner, ListId::Allow).above(10))
            .build();
    }

    #[test]
    #[should_panic(expected = "sender rules take no amount guard")]
    fn sender_guards_are_rejected() {
        let _ = RuleTable::builder()
            .rule(Rule::forbid(Subject::Sender, ListId::Frozen).above(10))
            .build();
    }

    #[test]
    #[should_panic(expected = "zero is the padding value")]
    fn zero_inline_members_are_rejected() {
        let _ = RuleTable::builder()
            .rule(Rule::require(Subject::Asset, ListId::Allow))
            .inline_assets(&[[0u8; 32]])
            .build();
    }

    #[test]
    fn an_owner_guard_needs_no_inline_membership() {
        let table = RuleTable::builder()
            .rule(Rule::require(Subject::OutputOwner, ListId::Allow).above(7))
            .build();
        assert_eq!(table.rules().len(), 1);
    }

    #[test]
    fn owner_and_asset_list_guards_can_coexist() {
        let table = RuleTable::builder()
            .rule(Rule::require(Subject::OutputOwner, ListId::Allow).above(7))
            .rule(Rule::require(Subject::Asset, ListId::Allow).above(9))
            .build();
        assert_eq!(table.rules().len(), 2);
    }

    #[test]
    fn an_asset_rule_reads_lists_and_refuses_an_empty_mask() {
        let rule = Rule::require(Subject::Asset, ListId::Approval).above(7);
        let table = RuleTable::builder().rule(rule).build();
        assert_eq!(table.rules(), &[rule]);
        assert_eq!(Rule::decode(&rule.encoded()), Ok(rule));
        assert_eq!(
            Rule::decode(&packed([0, 0, 1, 4], 0, 0)),
            Err(RuleTableError::EmptyLists)
        );
        let forbid = Rule::forbid(Subject::Asset, ListId::Block);
        assert_eq!(Rule::decode(&forbid.encoded()), Ok(forbid));
    }
}
