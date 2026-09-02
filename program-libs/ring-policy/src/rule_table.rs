use thiserror::Error;
use zolana_hasher::hash_chain::create_hash_chain_from_slice;

use crate::{field_u8, ListId, POLICY_TABLE_DOMAIN};

/// Rule slots compiled into the circuit, a new value rotates the proving key.
pub const MAX_RULES: usize = 16;
/// Inline asset slots per table, a circuit width.
pub const MAX_INLINE_ASSETS: usize = 8;
/// Source slots, one per list the enum can name.
pub const MAX_SOURCES: usize = 8;
/// Answer slots per transfer, a circuit width.
pub const ANSWER_SLOTS: usize = 10;
/// Input slots the policy opens per transfer, a circuit width.
pub const POLICY_INPUT_SLOTS: usize = 5;
/// Output slots the policy opens per transfer, a circuit width.
pub const POLICY_OUTPUT_SLOTS: usize = 4;
/// Enters `policy_hash`, bump it with any change of the encoding below.
pub const POLICY_VERSION: u8 = 3;

/// Distinct sender keys and live outputs of one transfer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AnswerLoad {
    pub senders: usize,
    pub outputs: usize,
}

/// A one-key spend at the output width, every table answers it in one transfer.
pub const GUARANTEED_LOAD: AnswerLoad = AnswerLoad {
    senders: 1,
    outputs: POLICY_OUTPUT_SLOTS,
};

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

/// A slot violates the positional layout.
#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum SourceMapError {
    #[error("slot breaks the positional layout")]
    NotPositional,
    #[error("list is already mapped")]
    Duplicate,
    #[error("owner hash is zero")]
    ZeroOwner,
}

/// Hashing failed or a referenced list has no source.
#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum PolicyHashError {
    #[error("hashing failed")]
    Hashing,
    #[error("no source for the list")]
    MissingSource(ListId),
}

/// The slots break the positional layout, or an owner hash could not be derived.
#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum SourceMapOwnerError<E> {
    #[error(transparent)]
    Map(SourceMapError),
    #[error("owner hash derivation failed")]
    Owner(E),
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
            let slot = &mut sources.slots[list_id.slot()];
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

    /// The map a `PolicyConfig`'s stored `(list_id, namespace)` slots resolve to,
    /// each namespace address hashed to its owner. An empty slot is `list_id` 0.
    pub fn from_namespaces<E>(
        slots: &[(u8, [u8; 32]); MAX_SOURCES],
        owner_hash: impl Fn(&[u8; 32]) -> Result<[u8; 32], E>,
    ) -> Result<Self, SourceMapOwnerError<E>> {
        let mut out = [SourceOwner::default(); MAX_SOURCES];
        for (dst, (list_id, namespace)) in out.iter_mut().zip(slots) {
            if *list_id == 0 {
                continue;
            }
            *dst = SourceOwner {
                list_id: *list_id,
                owner_hash: owner_hash(namespace).map_err(SourceMapOwnerError::Owner)?,
            };
        }
        Self::from_slots(out).map_err(SourceMapOwnerError::Map)
    }

    /// The owner serving a list, `None` when unmapped.
    pub fn owner_hash(&self, list_id: ListId) -> Option<&[u8; 32]> {
        let slot = &self.slots[list_id.slot()];
        (slot.list_id != 0).then_some(&slot.owner_hash)
    }

    pub const fn slots(&self) -> &[SourceOwner; MAX_SOURCES] {
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

/// AboveAmount exempts an instance whose summed output amount is at or below
/// the threshold, in base units of the output asset.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Guard {
    Always,
    AboveAmount(u64),
}

/// A list of entries or assets carried inline by the table.
///
/// `AnyOf` is a disjunction, the rule is satisfied by an answer for any one of
/// the lists, a `Present` group is a union allowlist and an `Absent` group an
/// intersection blocklist.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RuleSource {
    List(ListId),
    AnyOf(&'static [ListId]),
    InlineAssets(&'static [[u8; 32]]),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
/// One compiled obligation, packed into a single field element for the hash.
pub struct Rule {
    pub subject: Subject,
    pub mode: Mode,
    pub source: RuleSource,
    pub guard: Guard,
}

impl Rule {
    /// Every live instance of the subject needs a live Active entry.
    pub const fn require(subject: Subject, list_id: ListId) -> Self {
        Self {
            subject,
            mode: Mode::Present,
            source: RuleSource::List(list_id),
            guard: Guard::Always,
        }
    }

    /// Every live instance of the subject needs a provable absence.
    pub const fn forbid(subject: Subject, list_id: ListId) -> Self {
        Self {
            subject,
            mode: Mode::Absent,
            source: RuleSource::List(list_id),
            guard: Guard::Always,
        }
    }

    /// Every live instance must be present in at least one of the lists.
    pub const fn require_any(subject: Subject, lists: &'static [ListId]) -> Self {
        Self {
            subject,
            mode: Mode::Present,
            source: RuleSource::AnyOf(lists),
            guard: Guard::Always,
        }
    }

    /// A live instance is refused only when present in every one of the lists.
    pub const fn forbid_all(subject: Subject, lists: &'static [ListId]) -> Self {
        Self {
            subject,
            mode: Mode::Absent,
            source: RuleSource::AnyOf(lists),
            guard: Guard::Always,
        }
    }

    /// Restricts assets to members the table itself carries, no entries involved.
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

    /// Bit `i` set means list `i + 1` is referenced, zero marks the inline source.
    pub const fn list_mask(&self) -> u8 {
        match self.source {
            RuleSource::List(list_id) => list_id.mask_bit(),
            RuleSource::AnyOf(lists) => {
                let mut mask = 0u8;
                let mut i = 0;
                while i < lists.len() {
                    mask |= lists[i].mask_bit();
                    i += 1;
                }
                mask
            }
            RuleSource::InlineAssets(_) => 0,
        }
    }

    /// The lists the rule consults, empty for an inline source.
    pub fn referenced_lists(&self) -> impl Iterator<Item = ListId> + '_ {
        let mask = self.list_mask();
        ListId::ALL
            .into_iter()
            .filter(move |list_id| mask & list_id.mask_bit() != 0)
    }

    /// Byte positions are the circuit packed-field weights (Go ruleShift), reordering breaks proof verification.
    pub fn encoded(&self) -> [u8; 32] {
        let mut field = [0u8; 32];
        let (guard_tag, threshold) = match self.guard {
            Guard::Always => (0u8, 0u64),
            Guard::AboveAmount(amount) => (1u8, amount),
        };
        field[20..28].copy_from_slice(&threshold.to_be_bytes());
        field[28] = guard_tag;
        field[29] = self.list_mask();
        field[30] = self.mode as u8;
        field[31] = self.subject as u8;
        field
    }

    const fn signature(&self) -> u32 {
        ((self.subject as u32) << 16) | ((self.mode as u32) << 8) | self.list_mask() as u32
    }

    const fn max_answers(&self, load: AnswerLoad) -> usize {
        match self.source {
            RuleSource::InlineAssets(_) => 0,
            RuleSource::List(_) | RuleSource::AnyOf(_) => match self.subject {
                Subject::Sender => load.senders,
                Subject::OutputOwner | Subject::Asset => load.outputs,
                Subject::ExitDestination => 0,
            },
        }
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

    /// Upper bound on answer triples, reached with members disjoint across subjects.
    pub const fn max_answers(&self, load: AnswerLoad) -> usize {
        assert!(
            load.senders <= POLICY_INPUT_SLOTS && load.outputs <= POLICY_OUTPUT_SLOTS,
            "answer load exceeds the policy openings"
        );
        let mut total = 0;
        let mut i = 0;
        while i < self.len {
            total += self.rules[i].max_answers(load);
            i += 1;
        }
        total
    }

    /// The map binds each referenced list to one namespace, an uncovered
    /// rule fails closed.
    pub fn hash(&self, sources: &SourceMap) -> Result<[u8; 32], PolicyHashError> {
        for rule in self.rules() {
            for list_id in rule.referenced_lists() {
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

/// Const-evaluable, an illegal table fails the consuming build, never a transaction.
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
        let mut owner_guard = false;
        let mut single_unguarded_inline = false;
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
                    single_unguarded_inline =
                        members.len() == 1 && matches!(rule.guard, Guard::Always);
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
                RuleSource::AnyOf(lists) => {
                    assert!(!lists.is_empty(), "a group names no list");
                    assert!(
                        lists.len() <= MAX_SOURCES,
                        "a group exceeds the source width"
                    );
                    let mut a = 0;
                    while a < lists.len() {
                        let mut b = a + 1;
                        while b < lists.len() {
                            assert!(lists[a] as u8 != lists[b] as u8, "a group repeats a list");
                            b += 1;
                        }
                        a += 1;
                    }
                }
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
                owner_guard = owner_guard || matches!(rule.subject, Subject::OutputOwner);
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
        assert!(
            !owner_guard || single_unguarded_inline,
            "an owner amount guard needs a single unguarded inline asset"
        );
        let table = RuleTable {
            rules: self.rules,
            len: self.len,
        };
        assert!(
            table.max_answers(GUARANTEED_LOAD) <= ANSWER_SLOTS,
            "a one-key spend at the output width exceeds the answer slots"
        );
        table
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
    fn from_namespaces_resolves_and_validates_positionally() {
        let mut slots = [(0u8, [0u8; 32]); MAX_SOURCES];
        slots[0] = (1, [9u8; 32]);
        let map =
            SourceMap::from_namespaces(&slots, |ns| Ok::<_, ()>(*ns)).expect("positional owners");
        assert_eq!(map.owner_hash(ListId::Allow), Some(&[9u8; 32]));
        let mut misplaced = [(0u8, [0u8; 32]); MAX_SOURCES];
        misplaced[1] = (1, [9u8; 32]);
        assert!(matches!(
            SourceMap::from_namespaces(&misplaced, |ns| Ok::<_, ()>(*ns)),
            Err(SourceMapOwnerError::Map(SourceMapError::NotPositional))
        ));
    }

    #[test]
    fn a_group_encodes_the_union_mask() {
        assert_eq!(
            Rule::require(Subject::OutputOwner, ListId::Allow).list_mask(),
            0b0000_0001
        );
        assert_eq!(
            Rule::require_any(Subject::OutputOwner, &[ListId::Allow, ListId::Frozen]).list_mask(),
            0b0000_0101
        );
        assert_eq!(
            Rule::forbid_all(Subject::OutputOwner, &[ListId::Block, ListId::Frozen]).list_mask(),
            0b0000_0110
        );
        assert_eq!(Rule::allow_only_assets(ASSETS).list_mask(), 0);
    }

    #[test]
    fn a_group_hash_binds_every_listed_source() {
        const GROUP: RuleTable = RuleTable::builder()
            .rule(Rule::require_any(
                Subject::OutputOwner,
                &[ListId::Allow, ListId::Frozen],
            ))
            .build();
        let both = sources(&[(ListId::Allow, [4u8; 32]), (ListId::Frozen, [5u8; 32])]);
        assert!(GROUP.hash(&both).is_ok());
        let only_one = sources(&[(ListId::Allow, [4u8; 32])]);
        assert_eq!(
            GROUP.hash(&only_one),
            Err(PolicyHashError::MissingSource(ListId::Frozen))
        );
    }

    #[test]
    #[should_panic(expected = "a group names no list")]
    fn an_empty_group_is_rejected() {
        let _ = RuleTable::builder()
            .rule(Rule::require_any(Subject::OutputOwner, &[]))
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

    const RELEASED: RuleTable = RuleTable::builder()
        .rule(Rule::require(Subject::OutputOwner, ListId::Allow))
        .rule(Rule::require(Subject::Sender, ListId::Allow))
        .rule(Rule::forbid(Subject::OutputOwner, ListId::Block))
        .rule(Rule::forbid(Subject::Sender, ListId::Frozen))
        .build();

    #[test]
    fn answers_scale_with_senders_and_outputs_per_subject() {
        let load = |senders, outputs| AnswerLoad { senders, outputs };
        assert_eq!(RELEASED.max_answers(GUARANTEED_LOAD), 10);
        assert_eq!(RELEASED.max_answers(load(2, 4)), 12);
        assert_eq!(RELEASED.max_answers(load(5, 4)), 18);
    }

    #[test]
    #[should_panic(expected = "answer load exceeds the policy openings")]
    fn a_load_above_the_openings_is_refused() {
        let _ = RELEASED.max_answers(AnswerLoad {
            senders: POLICY_INPUT_SLOTS + 1,
            outputs: POLICY_OUTPUT_SLOTS,
        });
    }

    #[test]
    fn an_inline_asset_rule_answers_nothing() {
        const WITH_INLINE: RuleTable = RuleTable::builder()
            .rule(Rule::require(Subject::Sender, ListId::Allow))
            .rule(Rule::allow_only_assets(ASSETS))
            .build();
        assert_eq!(WITH_INLINE.max_answers(GUARANTEED_LOAD), 1);
    }

    #[test]
    fn a_guard_does_not_lower_the_answer_bound() {
        const UNGUARDED: RuleTable = RuleTable::builder()
            .rule(Rule::require(Subject::OutputOwner, ListId::Allow))
            .rule(Rule::allow_only_assets(ASSETS))
            .build();
        const GUARDED: RuleTable = RuleTable::builder()
            .rule(Rule::require(Subject::OutputOwner, ListId::Allow).above(7))
            .rule(Rule::allow_only_assets(ASSETS))
            .build();
        assert_eq!(
            GUARDED.max_answers(GUARANTEED_LOAD),
            UNGUARDED.max_answers(GUARANTEED_LOAD)
        );
    }

    #[test]
    #[should_panic(expected = "exceeds the answer slots")]
    fn a_table_no_one_key_spend_can_answer_is_rejected() {
        let _ = RuleTable::builder()
            .rule(Rule::require(Subject::OutputOwner, ListId::Allow))
            .rule(Rule::forbid(Subject::OutputOwner, ListId::Block))
            .rule(Rule::require(Subject::OutputOwner, ListId::Approval))
            .build();
    }

    #[test]
    #[should_panic(expected = "an owner amount guard needs a single unguarded inline asset")]
    fn an_owner_guard_without_an_inline_asset_is_rejected() {
        let _ = RuleTable::builder()
            .rule(Rule::require(Subject::OutputOwner, ListId::Allow).above(7))
            .build();
    }

    #[test]
    #[should_panic(expected = "an owner amount guard needs a single unguarded inline asset")]
    fn an_owner_guard_beside_two_inline_assets_is_rejected() {
        let _ = RuleTable::builder()
            .rule(Rule::require(Subject::OutputOwner, ListId::Allow).above(7))
            .rule(Rule::allow_only_assets(&[[3u8; 32], [4u8; 32]]))
            .build();
    }

    #[test]
    #[should_panic(expected = "an owner amount guard needs a single unguarded inline asset")]
    fn an_owner_guard_beside_a_guarded_inline_asset_is_rejected() {
        let _ = RuleTable::builder()
            .rule(Rule::require(Subject::OutputOwner, ListId::Allow).above(7))
            .rule(Rule::allow_only_assets(ASSETS).above(9))
            .build();
    }

    #[test]
    fn an_asset_guard_needs_no_inline_asset() {
        const ASSET_GUARD: RuleTable = RuleTable::builder()
            .rule(Rule::require(Subject::Asset, ListId::Approval).above(7))
            .build();
        const BESIDE_INLINE: RuleTable = RuleTable::builder()
            .rule(Rule::require(Subject::Asset, ListId::Approval).above(7))
            .rule(Rule::allow_only_assets(ASSETS))
            .build();
        assert_eq!(ASSET_GUARD.rules().len(), 1);
        assert_eq!(BESIDE_INLINE.rules().len(), 2);
    }
}
