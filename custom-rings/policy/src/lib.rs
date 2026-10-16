//! Entry lists of custom rings and the rule table compiled over them. One entry per
//! `(list_id, member)` is a zero-amount data UTXO owned by the ring's namespace PDA.

mod entry;
mod member;
mod rule_table;

pub use entry::{
    entry_nullifier, entry_seed, mutation_private_tx_hash, EntryState, ListEntry, ListId,
    ListNamespace, ListSet, Writer, ENTRY_OUTPUT_DATA_LEN, LIST_ENTRY_LEN, NAMESPACE_PDA_SEED,
    ZERO_NULLIFIER_PK,
};
pub use member::{Member, MemberError};
pub use rule_table::{
    EncodedRuleTable, Guard, Mode, OutflowLimit, PolicyHashError, Rule, RuleSource, RuleTable,
    RuleTableBuilder, RuleTableError, SourceMap, SourceMapError, SourceMapOwnerError, SourceOwner,
    Subject, TableParts, ANSWER_SLOTS, MAX_INLINE_ASSETS, MAX_OUTFLOW_LIMITS, MAX_RULES,
    MAX_SOURCES, POLICY_INPUT_SLOTS, POLICY_OUTPUT_SLOTS, POLICY_VERSION,
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

/// The ring id field a UTXO inside the ring carries.
pub fn ring_id_field(program_id: &[u8; 32]) -> Result<[u8; 32], zolana_hasher::HasherError> {
    zolana_hasher::primitives::hash_bytes(program_id)
}

pub(crate) fn field_u8(value: u8) -> [u8; 32] {
    zolana_hasher::primitives::right_align(&[value])
}

pub(crate) fn field_u16(value: u16) -> [u8; 32] {
    zolana_hasher::primitives::right_align(&value.to_be_bytes())
}

pub(crate) fn field_u64(value: u64) -> [u8; 32] {
    zolana_hasher::primitives::right_align(&value.to_be_bytes())
}

pub(crate) const PLAINTEXT_ENVELOPE_LEN: usize = 5;

/// Scheme byte zero then the little endian content length.
pub(crate) fn seal_plaintext<const N: usize, const M: usize>(content: [u8; N]) -> [u8; M] {
    const { assert!(M == PLAINTEXT_ENVELOPE_LEN + N) }
    let mut out = [0u8; M];
    out[1..PLAINTEXT_ENVELOPE_LEN].copy_from_slice(&(N as u32).to_le_bytes());
    out[PLAINTEXT_ENVELOPE_LEN..].copy_from_slice(&content);
    out
}
