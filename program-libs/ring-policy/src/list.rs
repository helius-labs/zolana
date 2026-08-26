//! The typed extension point over the record primitive.
//!
//! A record list is a namespace of `(kind, member)` records, each a zero-amount
//! data UTXO in the SPP state tree owned by the ring's records PDA, present or
//! absent provably against SPP's own roots (see [`crate::record`]). The `Policy`
//! rule table is one consumer, a list of auditors or co-signers is another.
//!
//! # Adding a list
//!
//! 1. Add a [`RecordKind`] variant with any unused `u8` (never `0`, the circuit
//!    reserves it as the inline-asset sentinel) and its `TryFrom<u8>` arm.
//! 2. Place the variant in [`RecordKind::holder`]. The total match makes the
//!    compiler demand it.
//! 3. Pick a [`Payload`] (`()` when the member is the whole record, [`ViewingKey`]
//!    or a new type when a value is committed beside it).
//! 4. Declare a zero-sized type and `impl List` for it. `HOLDER` derives itself.
//!
//! The keying, the 74-byte envelope, the present-absent membership proofs, the
//! `create_record` and `update_record` instructions, and the circuit are reused
//! unchanged. Only a rule that consults the list touches the `Policy` table. The
//! circuit proves membership, never who mutated. Authorization stays here in
//! [`RecordKind::holder`], never crossing the CPI or reaching Go or TypeScript.

use crate::record::{Holder, Record, RecordKind, RecordState};
use crate::Member;

mod sealed {
    pub trait Sealed {}
}

/// Sealed, the set of record lists stays closed and auditable in the crate.
pub trait List: sealed::Sealed {
    /// The on-chain discriminant written into every record of the list.
    const KIND: RecordKind;
    /// The value committed into the record's `payload_hash`.
    type Payload: Payload;
    /// Derived from [`RecordKind::holder`], never set to diverge from it.
    const HOLDER: Holder = Self::KIND.holder();
}

/// Compresses into a record's 32-byte `payload_hash`.
pub trait Payload: Copy {
    fn commit(&self) -> [u8; 32];
}

/// A payload the on-chain 32 bytes recover exactly, unlike a hashed one.
pub trait InlinePayload: Payload {
    fn from_commit(commit: [u8; 32]) -> Option<Self>
    where
        Self: Sized;
}

impl Payload for () {
    fn commit(&self) -> [u8; 32] {
        [0u8; 32]
    }
}

impl InlinePayload for () {
    fn from_commit(commit: [u8; 32]) -> Option<Self> {
        (commit == [0u8; 32]).then_some(())
    }
}

/// A compressed viewing key stored by identity.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ViewingKey(pub [u8; 32]);

impl Payload for ViewingKey {
    fn commit(&self) -> [u8; 32] {
        self.0
    }
}

impl InlinePayload for ViewingKey {
    fn from_commit(commit: [u8; 32]) -> Option<Self> {
        Some(Self(commit))
    }
}

/// A co-signer key stored by identity.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CoSignerKey(pub [u8; 32]);

impl Payload for CoSignerKey {
    fn commit(&self) -> [u8; 32] {
        self.0
    }
}

impl InlinePayload for CoSignerKey {
    fn from_commit(commit: [u8; 32]) -> Option<Self> {
        Some(Self(commit))
    }
}

macro_rules! list_kind {
    ($name:ident, $kind:expr, $payload:ty) => {
        pub struct $name;
        impl sealed::Sealed for $name {}
        impl List for $name {
            const KIND: RecordKind = $kind;
            type Payload = $payload;
        }
    };
}

list_kind!(Allow, RecordKind::Allow, ());
list_kind!(Block, RecordKind::Block, ());
list_kind!(Frozen, RecordKind::Frozen, ());
list_kind!(RingViewing, RecordKind::RingViewing, ());
list_kind!(Recovery, RecordKind::Recovery, ());
list_kind!(Reader, RecordKind::Reader, ());
list_kind!(Approval, RecordKind::Approval, ());
list_kind!(Escrow, RecordKind::Escrow, ());

/// A record built through its list type, the payload type cannot mismatch the kind.
#[derive(Clone, Copy, Debug)]
pub struct Typed<L: List> {
    pub member: Member,
    pub state: RecordState,
    pub version: u64,
    pub payload: L::Payload,
}

impl<L: List> Typed<L> {
    pub fn erase(&self) -> Record {
        Record {
            kind: L::KIND,
            member: self.member,
            state: self.state,
            version: self.version,
            payload_hash: self.payload.commit(),
        }
    }
}

impl<L: List> Typed<L>
where
    L::Payload: InlinePayload,
{
    /// The typed view of a record, `None` for a different kind or a commitment
    /// no payload recovers.
    pub fn from_record(record: &Record) -> Option<Self> {
        if record.kind != L::KIND {
            return None;
        }
        Some(Self {
            member: record.member,
            state: record.state,
            version: record.version,
            payload: L::Payload::from_commit(record.payload_hash)?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn member(byte: u8) -> Member {
        Member::owner_tag(&[byte; 32]).unwrap()
    }

    #[test]
    fn holder_derives_from_the_kind_for_every_list() {
        assert_eq!(Allow::HOLDER, RecordKind::Allow.holder());
        assert_eq!(Allow::HOLDER, Holder::Authority);
        assert_eq!(RingViewing::HOLDER, Holder::Member);
        assert_eq!(Escrow::HOLDER, Holder::Member);
        assert_eq!(Reader::HOLDER, Holder::Authority);
    }

    #[test]
    fn a_typed_record_erases_to_its_kind_and_recovers() {
        let typed = Typed::<Allow> {
            member: member(1),
            state: RecordState::Active,
            version: 3,
            payload: (),
        };
        let record = typed.erase();
        assert_eq!(record.kind, RecordKind::Allow);
        assert_eq!(record.payload_hash, [0u8; 32]);
        let back = Typed::<Allow>::from_record(&record).expect("same kind");
        assert_eq!(back.member, typed.member);
        assert_eq!(back.version, typed.version);
        assert!(Typed::<Block>::from_record(&record).is_none());
    }

    #[test]
    fn inline_payloads_round_trip_through_the_commitment() {
        let key = ViewingKey([7u8; 32]);
        assert_eq!(ViewingKey::from_commit(key.commit()), Some(key));
        let cosigner = CoSignerKey([9u8; 32]);
        assert_eq!(CoSignerKey::from_commit(cosigner.commit()), Some(cosigner));
    }
}
