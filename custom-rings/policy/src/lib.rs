//! Ring member lists, one bit each in a member registry record, and the rule table over them.

mod list;
mod member;
mod rule_table;
mod rules;

pub use list::{ListChange, ListId, ListSet, ListWrite, ListWriteError, Writer};
pub use member::{Member, MemberError};
pub use rule_table::{
    EncodedRuleTable, Guard, Mode, OutflowLimit, PolicySource, PolicyTableError, Rule, RuleSource,
    RuleTable, RuleTableBuilder, RuleTableError, SourceMap, SourceMapError, Subject, TableParts,
    MAX_INLINE_ASSETS, MAX_OUTFLOW_LIMITS, MAX_RULES, MAX_SOURCES, N_FOREIGN, POLICY_TABLE_DOMAIN,
    POLICY_TABLE_FIELDS, POLICY_TABLE_VERSION,
};
pub use rules::{OutputSubjects, RecordLists, RuleRefusal, TransferSubject, TransferSubjects};

/// The ring id field a UTXO inside the ring carries.
pub fn ring_id_field(program_id: &[u8; 32]) -> Result<[u8; 32], zolana_hasher::HasherError> {
    zolana_hasher::primitives::hash_bytes(program_id)
}

/// The source slot field of a curator's member registry, an address can exceed the modulus.
pub fn registry_field(registry: &[u8; 32]) -> Result<[u8; 32], zolana_hasher::HasherError> {
    zolana_hasher::primitives::hash_bytes(registry)
}

pub(crate) fn field_u8(value: u8) -> [u8; 32] {
    zolana_hasher::primitives::right_align(&[value])
}
