//! The entry-list primitive for custom rings and the rule table compiled over
//! it.
//!
//! One entry per `(list_id, member)` lives as a zero-amount data UTXO in the SPP
//! state tree, owned by the ring's namespace PDA, present or absent provably
//! against SPP's own roots. [`ListId`] names each list, [`ListNamespace`]
//! keys it, and [`ListEntry`] carries it on the wire. [`RuleTable`] compiles a rule
//! table over these lists, and [`schema`] types the content of each.

mod entry;
mod member;
mod rule_table;
pub mod schema;

pub use entry::{
    entry_nullifier, entry_seed, mutation_private_tx_hash, EntryState, ListEntry, ListId,
    ListNamespace, ListSet, Writer, ENTRY_OUTPUT_DATA_LEN, LIST_ENTRY_LEN, NAMESPACE_PDA_SEED,
};
pub use member::{Member, MemberError};
pub use rule_table::{
    AnswerLoad, EncodedRuleTable, Guard, Mode, PolicyHashError, Rule, RuleSource, RuleTable,
    RuleTableBuilder, RuleTableError, SourceMap, SourceMapError, SourceMapOwnerError, SourceOwner,
    Subject, ANSWER_SLOTS, GUARANTEED_LOAD, MAX_INLINE_ASSETS, MAX_RULES, MAX_SOURCES,
    POLICY_INPUT_SLOTS, POLICY_OUTPUT_SLOTS, POLICY_VERSION,
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

/// Separates address seeds, frozen with every derived address.
pub const POLICY_ADDRESS_DOMAIN: [u8; 32] = packed_ascii(b"zolana:ring-policy:address:v1");
/// Separates entry leaves, frozen with every published entry.
pub const POLICY_RECORD_DOMAIN: [u8; 32] = packed_ascii(b"zolana:ring-policy:record:v1");
/// Separates policy hashes, frozen with every pinned config.
pub const POLICY_TABLE_DOMAIN: [u8; 32] = packed_ascii(b"zolana:ring-policy:policy:v1");

pub(crate) fn field_u8(value: u8) -> [u8; 32] {
    zolana_hasher::primitives::right_align(&[value])
}

pub(crate) fn field_u16(value: u16) -> [u8; 32] {
    zolana_hasher::primitives::right_align(&value.to_be_bytes())
}

pub(crate) fn field_u64(value: u64) -> [u8; 32] {
    zolana_hasher::primitives::right_align(&value.to_be_bytes())
}
