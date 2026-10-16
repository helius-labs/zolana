//! Member lists of custom rings and the rule table compiled over them. A member's
//! record in the ring's member registry carries one bit per list.

mod list;
mod member;
mod rule_table;

pub use list::{ListId, ListNamespace, ListSet, Writer, NAMESPACE_PDA_SEED, ZERO_NULLIFIER_PK};
pub use member::{Member, MemberError};
pub use rule_table::{
    EncodedRuleTable, Guard, Mode, OutflowLimit, PolicyHashError, PolicySource, Rule, RuleSource,
    RuleTable, RuleTableBuilder, RuleTableError, SourceMap, SourceMapError, Subject, TableParts,
    MAX_INLINE_ASSETS, MAX_OUTFLOW_LIMITS, MAX_RULES, MAX_SOURCES, N_FOREIGN, POLICY_INPUT_SLOTS,
    POLICY_OUTPUT_SLOTS, POLICY_VERSION,
};

/// At most 31 bytes keeps the packed value below the field modulus.
const fn packed_ascii<const N: usize>(bytes: &[u8; N]) -> [u8; 32] {
    assert!(N <= 31);
    let mut field = [0u8; 32];
    let mut i = 0;
    while i < N {
        field[32 - N + i] = bytes[i];
        i += 1;
    }
    field
}

/// Separates policy hashes, frozen with every pinned config.
pub const POLICY_TABLE_DOMAIN: [u8; 32] = packed_ascii(b"zolana:ring-policy:policy:v1");

/// The ring id field a UTXO inside the ring carries.
pub fn ring_id_field(program_id: &[u8; 32]) -> Result<[u8; 32], zolana_hasher::HasherError> {
    zolana_hasher::primitives::hash_bytes(program_id)
}

/// The source slot field of a curator's member registry root, an address exceeds the modulus.
pub fn registry_field(registry: &[u8; 32]) -> Result<[u8; 32], zolana_hasher::HasherError> {
    zolana_hasher::primitives::hash_bytes(registry)
}

pub(crate) fn field_u8(value: u8) -> [u8; 32] {
    zolana_hasher::primitives::right_align(&[value])
}

pub(crate) fn field_u64(value: u64) -> [u8; 32] {
    zolana_hasher::primitives::right_align(&value.to_be_bytes())
}
