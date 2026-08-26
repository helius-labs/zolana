//! The record-list primitive for custom rings and the compiled rule table that
//! is one consumer of it.
//!
//! One record per `(kind, member)` lives as a zero-amount data UTXO in the SPP
//! state tree, owned by the ring's records PDA, present or absent provably
//! against SPP's own roots. [`RecordKind`] names each list, [`RecordsOwner`]
//! keys it, and [`Record`] carries it on the wire. [`Policy`] compiles a rule
//! table over these lists, and [`list`] is the typed extension point where a new
//! list (a roster of auditors or co-signers) is one trait impl.

pub mod list;
mod member;
mod policy;
mod record;

pub use member::{Member, MemberError};
pub use policy::{
    Guard, Mode, Policy, PolicyBuilder, Rule, RuleSource, Subject, MAX_INLINE_ASSETS, MAX_RULES,
    POLICY_VERSION,
};
pub use record::{
    mutation_private_tx_hash, record_nullifier, record_seed, Holder, Record, RecordKind,
    RecordState, RecordsOwner, POLICY_RECORDS_PDA_SEED, RECORD_OUTPUT_DATA_LEN, RECORD_PAYLOAD_LEN,
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
