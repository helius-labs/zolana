use thiserror::Error;
use zolana_hasher::hash_chain::create_hash_chain_from_slice;

use crate::{field_u8, ListId, POLICY_TABLE_DOMAIN};

pub const MAX_RULES: usize = 16;
pub const MAX_INLINE_ASSETS: usize = 8;
pub const MAX_SOURCES: usize = 8;
/// Enters `policy_hash`, bump it with any change of the encoding below.
pub const POLICY_VERSION: u8 = 2;

/// One list and owner pair, list id 0 marks an empty slot with a zero hash.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SourceOwner {
    pub list_id: u8,
    pub owner_hash: [u8; 32],
}

/// Positional source map, slot `i` is empty or serves list `i + 1`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SourceMap {
    slots: [SourceOwner; MAX_SOURCES],
}

#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum SourceMapError {
    #[error("slot breaks the positional layout")]
    NotPositional,
    #[error("list is already mapped")]
    Duplicate,
    #[error("owner hash is zero")]
    ZeroOwner,
}

#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum PolicyHashError {
    #[error("hashing failed")]
    Hashing,
    #[error("no source for the list")]
    MissingSource(ListId),
}

impl SourceMap {
    pub const fn empty() -> Self {
        Self {
            slots: [SourceOwner {
                list_id: 0,
                owner_hash: [0u8; 32],
            }; MAX_SOURCES],
        }
    }

    pub fn new(entries: &[(ListId, [u8; 32])]) -> Result<Self, SourceMapError> {
        let mut sources = Self::empty();
        for (list_id, owner_hash) in entries {
            if *owner_hash == [0u8; 32] {
                return Err(SourceMapError::ZeroOwner);
            }
            let slot = &mut sources.slots[*list_id as usize - 1];
            if slot.list_id != 0 {
                return Err(SourceMapError::Duplicate);
            }
            *slot = SourceOwner {
                list_id: *list_id as u8,
                owner_hash: *owner_hash,
            };
        }
        Ok(sources)
    }

    /// Validates stored slots instead of re-canonicalizing them.
    pub fn from_slots(slots: [SourceOwner; MAX_SOURCES]) -> Result<Self, SourceMapError> {
        for (index, slot) in slots.iter().enumerate() {
            let empty = slot.list_id == 0 && slot.owner_hash == [0u8; 32];
            let positional = slot.list_id as usize == index + 1 && slot.owner_hash != [0u8; 32];
            if !empty && !positional {
                return Err(SourceMapError::NotPositional);
            }
        }
        Ok(Self { slots })
    }

    pub fn owner_hash(&self, list_id: ListId) -> Option<&[u8; 32]> {
        let slot = &self.slots[list_id as usize - 1];
        (slot.list_id != 0).then_some(&slot.owner_hash)
    }

    pub const fn slots(&self) -> &[SourceOwner; MAX_SOURCES] {
        &self.slots
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Subject {
    OutputOwner = 1,
    Sender = 2,
    ExitDestination = 3,
    Asset = 4,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Mode {
    Present = 1,
    Absent = 2,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Guard {
    Always,
    AboveAmount(u64),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RuleSource {
    List(ListId),
    InlineAssets(&'static [[u8; 32]]),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Rule {
    pub subject: Subject,
    pub mode: Mode,
    pub source: RuleSource,
    pub guard: Guard,
}

impl Rule {
    pub const fn require(subject: Subject, list_id: ListId) -> Self {
        Self {
            subject,
            mode: Mode::Present,
            source: RuleSource::List(list_id),
            guard: Guard::Always,
        }
    }

    pub const fn forbid(subject: Subject, list_id: ListId) -> Self {
        Self {
            subject,
            mode: Mode::Absent,
            source: RuleSource::List(list_id),
            guard: Guard::Always,
        }
    }

    pub const fn allow_only_assets(members: &'static [[u8; 32]]) -> Self {
        Self {
            subject: Subject::Asset,
            mode: Mode::Present,
            source: RuleSource::InlineAssets(members),
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

    /// Injective over every rule field, byte 29 is zero exactly for inline
    /// sources.
    pub fn encoded(&self) -> [u8; 32] {
        let mut field = [0u8; 32];
        let (guard_tag, threshold) = match self.guard {
            Guard::Always => (0u8, 0u64),
            Guard::AboveAmount(amount) => (1u8, amount),
        };
        field[20..28].copy_from_slice(&threshold.to_be_bytes());
        field[28] = guard_tag;
        field[29] = match self.source {
            RuleSource::List(list_id) => list_id as u8,
            RuleSource::InlineAssets(_) => 0,
        };
        field[30] = self.mode as u8;
        field[31] = self.subject as u8;
        field
    }

    const fn signature(&self) -> u32 {
        let list_id = match self.source {
            RuleSource::List(list_id) => list_id as u8,
            RuleSource::InlineAssets(_) => 0,
        };
        ((self.subject as u32) << 16) | ((self.mode as u32) << 8) | list_id as u32
    }

    const fn disabled() -> Self {
        Self::require(Subject::OutputOwner, ListId::Allow)
    }
}

/// The builder panics at compile time on a table the circuit cannot enforce.
#[derive(Clone, Copy, Debug)]
pub struct RuleTable {
    rules: [Rule; MAX_RULES],
    len: usize,
}

impl RuleTable {
    pub const fn builder() -> RuleTableBuilder {
        RuleTableBuilder {
            rules: [Rule::disabled(); MAX_RULES],
            len: 0,
        }
    }

    pub fn rules(&self) -> &[Rule] {
        &self.rules[..self.len]
    }

    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// The map binds each referenced list to one namespace, an uncovered
    /// rule fails closed.
    pub fn hash(&self, sources: &SourceMap) -> Result<[u8; 32], PolicyHashError> {
        for rule in self.rules() {
            if let RuleSource::List(list_id) = rule.source {
                if sources.owner_hash(list_id).is_none() {
                    return Err(PolicyHashError::MissingSource(list_id));
                }
            }
        }
        let mut elements = Vec::with_capacity(3 + 2 * MAX_SOURCES + self.len + MAX_INLINE_ASSETS);
        elements.push(POLICY_TABLE_DOMAIN);
        elements.push(field_u8(POLICY_VERSION));
        for slot in sources.slots() {
            elements.push(field_u8(slot.list_id));
            elements.push(slot.owner_hash);
        }
        elements.push(field_u8(self.len as u8));
        for rule in self.rules() {
            elements.push(rule.encoded());
        }
        for rule in self.rules() {
            if let RuleSource::InlineAssets(members) = rule.source {
                elements.extend_from_slice(members);
            }
        }
        create_hash_chain_from_slice(&elements).map_err(|_| PolicyHashError::Hashing)
    }
}

#[derive(Clone, Copy, Debug)]
pub struct RuleTableBuilder {
    rules: [Rule; MAX_RULES],
    len: usize,
}

impl RuleTableBuilder {
    #[must_use]
    pub const fn rule(mut self, rule: Rule) -> Self {
        assert!(self.len < MAX_RULES, "policy table is full");
        self.rules[self.len] = rule;
        self.len += 1;
        self
    }

    #[must_use]
    pub const fn rule_if(self, enabled: bool, rule: Rule) -> Self {
        if enabled {
            self.rule(rule)
        } else {
            self
        }
    }

    pub const fn build(self) -> RuleTable {
        let mut i = 0;
        while i < self.len {
            let rule = self.rules[i];
            match rule.source {
                RuleSource::InlineAssets(members) => {
                    assert!(
                        matches!(rule.subject, Subject::Asset),
                        "inline members serve asset rules only"
                    );
                    assert!(
                        matches!(rule.mode, Mode::Present),
                        "inline members express an allowlist only"
                    );
                    assert!(!members.is_empty(), "inline asset list is empty");
                    assert!(
                        members.len() <= MAX_INLINE_ASSETS,
                        "inline asset list exceeds the circuit width"
                    );
                    let mut m = 0;
                    while m < members.len() {
                        let mut nonzero = false;
                        let mut b = 0;
                        while b < 32 {
                            if members[m][b] != 0 {
                                nonzero = true;
                            }
                            b += 1;
                        }
                        assert!(nonzero, "zero is the padding value, never a member");
                        m += 1;
                    }
                }
                RuleSource::List(_) => {}
            }
            assert!(
                !(matches!(rule.subject, Subject::Sender)
                    && matches!(rule.guard, Guard::AboveAmount(_))),
                "sender rules take no amount guard"
            );
            assert!(
                !matches!(rule.subject, Subject::ExitDestination),
                "exit destinations are enforced by no plane yet"
            );
            if let Guard::AboveAmount(amount) = rule.guard {
                assert!(amount > 0, "a zero threshold is Guard::Always");
            }
            let mut j = 0;
            while j < i {
                assert!(
                    self.rules[j].signature() != rule.signature(),
                    "duplicate rule"
                );
                j += 1;
            }
            i += 1;
        }
        RuleTable {
            rules: self.rules,
            len: self.len,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ASSETS: &[[u8; 32]] = &[[3u8; 32]];

    const TABLE: RuleTable = RuleTable::builder()
        .rule(Rule::require(Subject::OutputOwner, ListId::Allow))
        .rule(Rule::forbid(Subject::Sender, ListId::Frozen))
        .rule(Rule::allow_only_assets(ASSETS))
        .rule_if(false, Rule::forbid(Subject::OutputOwner, ListId::Block))
        .build();

    #[test]
    fn the_table_keeps_declaration_order_and_skips_disabled_rules() {
        let rules = TABLE.rules();
        assert_eq!(rules.len(), 3);
        assert_eq!(rules[0].subject, Subject::OutputOwner);
        assert_eq!(rules[1].mode, Mode::Absent);
        assert!(matches!(rules[2].source, RuleSource::InlineAssets(_)));
    }

    #[test]
    fn rule_encoding_is_injective_over_every_field() {
        let base = Rule::require(Subject::OutputOwner, ListId::Allow);
        let variants = [
            base,
            Rule::require(Subject::Sender, ListId::Allow),
            Rule::require(Subject::OutputOwner, ListId::Block),
            Rule::forbid(Subject::OutputOwner, ListId::Allow),
            Rule::require(Subject::OutputOwner, ListId::Allow).above(5),
            Rule::require(Subject::OutputOwner, ListId::Allow).above(6),
            Rule::allow_only_assets(ASSETS),
        ];
        for (i, a) in variants.iter().enumerate() {
            for b in variants.iter().skip(i + 1) {
                assert_ne!(a.encoded(), b.encoded());
            }
        }
    }

    fn sources(entries: &[(ListId, [u8; 32])]) -> SourceMap {
        SourceMap::new(entries).unwrap()
    }

    #[test]
    fn policy_hash_binds_the_sources_and_the_inline_members() {
        let map = sources(&[(ListId::Allow, [4u8; 32]), (ListId::Frozen, [5u8; 32])]);
        let baseline = TABLE.hash(&map).unwrap();
        let other_owner = sources(&[(ListId::Allow, [4u8; 32]), (ListId::Frozen, [6u8; 32])]);
        assert_ne!(baseline, TABLE.hash(&other_owner).unwrap());
        let extra_slot = sources(&[
            (ListId::Allow, [4u8; 32]),
            (ListId::Frozen, [5u8; 32]),
            (ListId::Escrow, [7u8; 32]),
        ]);
        assert_ne!(baseline, TABLE.hash(&extra_slot).unwrap());
        const REORDERED: RuleTable = RuleTable::builder()
            .rule(Rule::forbid(Subject::Sender, ListId::Frozen))
            .rule(Rule::require(Subject::OutputOwner, ListId::Allow))
            .rule(Rule::allow_only_assets(ASSETS))
            .build();
        assert_ne!(baseline, REORDERED.hash(&map).unwrap());
        const OTHER_ASSETS: RuleTable = RuleTable::builder()
            .rule(Rule::require(Subject::OutputOwner, ListId::Allow))
            .rule(Rule::forbid(Subject::Sender, ListId::Frozen))
            .rule(Rule::allow_only_assets(&[[6u8; 32]]))
            .build();
        assert_ne!(baseline, OTHER_ASSETS.hash(&map).unwrap());
    }

    #[test]
    fn a_records_rule_without_a_source_fails_closed() {
        let map = sources(&[(ListId::Allow, [4u8; 32])]);
        assert_eq!(
            TABLE.hash(&map),
            Err(PolicyHashError::MissingSource(ListId::Frozen))
        );
    }

    #[test]
    fn an_empty_table_hashes_the_empty_map() {
        const EMPTY: RuleTable = RuleTable::builder().build();
        let baseline = EMPTY.hash(&SourceMap::empty()).unwrap();
        let with_slot = sources(&[(ListId::Allow, [4u8; 32])]);
        assert_ne!(baseline, EMPTY.hash(&with_slot).unwrap());
    }

    #[test]
    fn the_source_map_is_positional_and_rejects_duplicates() {
        assert_eq!(
            SourceMap::new(&[(ListId::Allow, [4u8; 32]), (ListId::Allow, [5u8; 32]),]),
            Err(SourceMapError::Duplicate)
        );
        assert_eq!(
            SourceMap::new(&[(ListId::Allow, [0u8; 32])]),
            Err(SourceMapError::ZeroOwner)
        );
        let map = sources(&[(ListId::Frozen, [5u8; 32])]);
        assert_eq!(SourceMap::from_slots(*map.slots()), Ok(map));
        let mut slots = *map.slots();
        slots.swap(0, 2);
        assert_eq!(
            SourceMap::from_slots(slots),
            Err(SourceMapError::NotPositional)
        );
        let mut zero_owner = *map.slots();
        zero_owner[2].owner_hash = [0u8; 32];
        assert_eq!(
            SourceMap::from_slots(zero_owner),
            Err(SourceMapError::NotPositional)
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
            .rule(Rule::allow_only_assets(&[[0u8; 32]]))
            .build();
    }
}
