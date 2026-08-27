//! The entry-list primitive for custom rings and the compiled rule table that
//! is one consumer of it.
//!
//! One entry per `(list_id, member)` lives as a zero-amount data UTXO in the SPP
//! state tree, owned by the ring's entries PDA, present or absent provably
//! against SPP's own roots. [`ListId`] names each list, [`ListNamespace`]
//! keys it, and [`ListEntry`] carries it on the wire. [`RuleTable`] compiles a rule
//! table over these lists, and [`schema`] is the typed extension point where a new
//! list (a roster of auditors or co-signers) is one trait impl.

mod entry;
mod member;
mod rule_table;
pub mod schema;

pub use entry::{
    entry_nullifier, entry_seed, mutation_private_tx_hash, EntryState, ListEntry, ListId,
    ListNamespace, Writer, ENTRY_OUTPUT_DATA_LEN, LIST_ENTRY_LEN, NAMESPACE_PDA_SEED,
};
pub use member::{Member, MemberError};
pub use rule_table::{
    Guard, Mode, PolicyHashError, Rule, RuleSource, RuleTable, RuleTableBuilder, SourceMap,
    SourceMapError, SourceOwner, Subject, MAX_INLINE_ASSETS, MAX_RULES, MAX_SOURCES,
    POLICY_VERSION,
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

pub const POLICY_ADDRESS_DOMAIN: [u8; 32] = packed_ascii(b"zolana:ring-policy:address:v1");
pub const POLICY_RECORD_DOMAIN: [u8; 32] = packed_ascii(b"zolana:ring-policy:record:v1");
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
