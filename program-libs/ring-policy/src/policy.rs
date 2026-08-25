use zolana_hasher::{hash_chain::create_hash_chain_from_slice, HasherError};

use crate::{field_u8, POLICY_TABLE_DOMAIN};

pub const MAX_RULES: usize = 16;
pub const MAX_INLINE_ASSETS: usize = 8;
/// Enters `policy_hash`, bump it with any change of the encoding below.
pub const POLICY_VERSION: u8 = 1;

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
#[repr(u8)]
pub enum RecordKind {
    Allow = 1,
    Block = 2,
    Frozen = 3,
    RingViewing = 4,
    Recovery = 5,
    Reader = 6,
    Approval = 7,
    Escrow = 8,
}

impl RecordKind {
    /// A held kind is mutated by the member, any other kind by the ring
    /// authority.
    pub const fn held_by_member(self) -> bool {
        matches!(self, Self::RingViewing | Self::Recovery | Self::Escrow)
    }
}

impl TryFrom<u8> for RecordKind {
    type Error = ();

    fn try_from(value: u8) -> Result<Self, ()> {
        Ok(match value {
            1 => Self::Allow,
            2 => Self::Block,
            3 => Self::Frozen,
            4 => Self::RingViewing,
            5 => Self::Recovery,
            6 => Self::Reader,
            7 => Self::Approval,
            8 => Self::Escrow,
            _ => return Err(()),
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RuleSource {
    Records(RecordKind),
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
    pub const fn require(subject: Subject, kind: RecordKind) -> Self {
        Self {
            subject,
            mode: Mode::Present,
            source: RuleSource::Records(kind),
            guard: Guard::Always,
        }
    }

    pub const fn forbid(subject: Subject, kind: RecordKind) -> Self {
        Self {
            subject,
            mode: Mode::Absent,
            source: RuleSource::Records(kind),
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
    pub(crate) fn encode(&self) -> [u8; 32] {
        let mut field = [0u8; 32];
        let (guard_tag, threshold) = match self.guard {
            Guard::Always => (0u8, 0u64),
            Guard::AboveAmount(amount) => (1u8, amount),
        };
        field[20..28].copy_from_slice(&threshold.to_be_bytes());
        field[28] = guard_tag;
        field[29] = match self.source {
            RuleSource::Records(kind) => kind as u8,
            RuleSource::InlineAssets(_) => 0,
        };
        field[30] = self.mode as u8;
        field[31] = self.subject as u8;
        field
    }

    const fn signature(&self) -> u32 {
        let kind = match self.source {
            RuleSource::Records(kind) => kind as u8,
            RuleSource::InlineAssets(_) => 0,
        };
        ((self.subject as u32) << 16) | ((self.mode as u32) << 8) | kind as u32
    }

    const fn disabled() -> Self {
        Self::require(Subject::OutputOwner, RecordKind::Allow)
    }
}

/// The builder panics at compile time on a table the circuit cannot enforce.
#[derive(Clone, Copy, Debug)]
pub struct Policy {
    rules: [Rule; MAX_RULES],
    len: usize,
}

impl Policy {
    pub const fn builder() -> PolicyBuilder {
        PolicyBuilder {
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

    /// The owner hash binds the table to one ring's records.
    pub fn hash(&self, records_owner_hash: &[u8; 32]) -> Result<[u8; 32], HasherError> {
        let mut elements = Vec::with_capacity(4 + self.len + MAX_INLINE_ASSETS);
        elements.push(POLICY_TABLE_DOMAIN);
        elements.push(field_u8(POLICY_VERSION));
        elements.push(*records_owner_hash);
        elements.push(field_u8(self.len as u8));
        for rule in self.rules() {
            elements.push(rule.encode());
        }
        for rule in self.rules() {
            if let RuleSource::InlineAssets(members) = rule.source {
                elements.extend_from_slice(members);
            }
        }
        create_hash_chain_from_slice(&elements)
    }
}

#[derive(Clone, Copy, Debug)]
pub struct PolicyBuilder {
    rules: [Rule; MAX_RULES],
    len: usize,
}

impl PolicyBuilder {
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

    pub const fn build(self) -> Policy {
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
                RuleSource::Records(_) => {}
            }
            assert!(
                !(matches!(rule.subject, Subject::Sender)
                    && matches!(rule.guard, Guard::AboveAmount(_))),
                "sender rules take no amount guard"
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
        Policy {
            rules: self.rules,
            len: self.len,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ASSETS: &[[u8; 32]] = &[[3u8; 32]];

    const TABLE: Policy = Policy::builder()
        .rule(Rule::require(Subject::OutputOwner, RecordKind::Allow))
        .rule(Rule::forbid(Subject::Sender, RecordKind::Frozen))
        .rule(Rule::allow_only_assets(ASSETS))
        .rule_if(false, Rule::forbid(Subject::OutputOwner, RecordKind::Block))
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
        let base = Rule::require(Subject::OutputOwner, RecordKind::Allow);
        let variants = [
            base,
            Rule::require(Subject::Sender, RecordKind::Allow),
            Rule::require(Subject::OutputOwner, RecordKind::Block),
            Rule::forbid(Subject::OutputOwner, RecordKind::Allow),
            Rule::require(Subject::OutputOwner, RecordKind::Allow).above(5),
            Rule::require(Subject::OutputOwner, RecordKind::Allow).above(6),
            Rule::allow_only_assets(ASSETS),
        ];
        for (i, a) in variants.iter().enumerate() {
            for b in variants.iter().skip(i + 1) {
                assert_ne!(a.encode(), b.encode());
            }
        }
    }

    #[test]
    fn policy_hash_binds_the_owner_and_the_inline_members() {
        let owner = [4u8; 32];
        let baseline = TABLE.hash(&owner).unwrap();
        assert_ne!(baseline, TABLE.hash(&[5u8; 32]).unwrap());
        const REORDERED: Policy = Policy::builder()
            .rule(Rule::forbid(Subject::Sender, RecordKind::Frozen))
            .rule(Rule::require(Subject::OutputOwner, RecordKind::Allow))
            .rule(Rule::allow_only_assets(ASSETS))
            .build();
        assert_ne!(baseline, REORDERED.hash(&owner).unwrap());
        const OTHER_ASSETS: Policy = Policy::builder()
            .rule(Rule::require(Subject::OutputOwner, RecordKind::Allow))
            .rule(Rule::forbid(Subject::Sender, RecordKind::Frozen))
            .rule(Rule::allow_only_assets(&[[6u8; 32]]))
            .build();
        assert_ne!(baseline, OTHER_ASSETS.hash(&owner).unwrap());
    }

    #[test]
    #[should_panic(expected = "duplicate rule")]
    fn duplicate_rules_are_rejected() {
        let _ = Policy::builder()
            .rule(Rule::require(Subject::OutputOwner, RecordKind::Allow))
            .rule(Rule::require(Subject::OutputOwner, RecordKind::Allow).above(10))
            .build();
    }

    #[test]
    #[should_panic(expected = "sender rules take no amount guard")]
    fn sender_guards_are_rejected() {
        let _ = Policy::builder()
            .rule(Rule::forbid(Subject::Sender, RecordKind::Frozen).above(10))
            .build();
    }

    #[test]
    #[should_panic(expected = "zero is the padding value")]
    fn zero_inline_members_are_rejected() {
        let _ = Policy::builder()
            .rule(Rule::allow_only_assets(&[[0u8; 32]]))
            .build();
    }
}
