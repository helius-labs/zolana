//! The typed extension point over the entry primitive.
//!
//! An entry list is a namespace of `(list_id, member)` entries, each a zero-amount
//! data UTXO in the SPP state tree owned by the ring's namespace PDA, present or
//! absent provably against SPP's own roots (see [`crate::entry`]). The
//! [`crate::RuleTable`] is one consumer, a list of auditors or co-signers is another.
//!
//! # Adding a list
//!
//! 1. Add a [`ListId`] variant with any unused `u8` (never `0`, the circuit
//!    reserves it as the inline-asset sentinel) and its `TryFrom<u8>` arm.
//! 2. Place the variant in [`ListId::writer`]. The total match makes the
//!    compiler demand it.
//! 3. Pick an [`EntryContent`] (`()` when the member is the whole entry, [`CoSignerKey`]
//!    or a new type when a value is committed beside it, a value above 32 bytes
//!    hashes in `commit` and implements only [`EntryContent`]).
//! 4. Declare a zero-sized type and `impl ListSchema` for it. `WRITER` derives itself.
//!
//! The keying, the 74-byte envelope, the present-absent membership proofs, the
//! `create_entry` and `update_entry` instructions, and the circuit are reused
//! unchanged. Only a rule that consults the list touches the [`crate::RuleTable`]. The
//! circuit proves membership, never who mutated. Authorization stays here in
//! [`ListId::writer`], never crossing the CPI or reaching Go or TypeScript.

use crate::entry::{EntryState, ListEntry, ListId, Writer};
use crate::Member;

mod sealed {
    pub trait Sealed {}
}

/// Sealed, the set of entry lists stays closed and auditable in the crate.
pub trait ListSchema: sealed::Sealed {
    /// The on-chain discriminant written into every entry of the list.
    const ID: ListId;
    /// The value committed into the entry's `content_hash`.
    type EntryContent: EntryContent;
    /// Derived from [`ListId::writer`], never set to diverge from it.
    const WRITER: Writer = Self::ID.writer();
}

/// Compresses into an entry's 32-byte `content_hash`.
pub trait EntryContent: Copy {
    fn commit(&self) -> [u8; 32];
}

/// Content the on-chain 32 bytes recover exactly, unlike a hashed one.
pub trait InlineContent: EntryContent {
    fn from_commit(commit: [u8; 32]) -> Option<Self>
    where
        Self: Sized;
}

impl EntryContent for () {
    fn commit(&self) -> [u8; 32] {
        [0u8; 32]
    }
}

impl InlineContent for () {
    fn from_commit(commit: [u8; 32]) -> Option<Self> {
        (commit == [0u8; 32]).then_some(())
    }
}

/// A co-signer key stored by identity.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CoSignerKey(pub [u8; 32]);

impl EntryContent for CoSignerKey {
    fn commit(&self) -> [u8; 32] {
        self.0
    }
}

impl InlineContent for CoSignerKey {
    fn from_commit(commit: [u8; 32]) -> Option<Self> {
        Some(Self(commit))
    }
}

macro_rules! list_schema {
    ($name:ident, $list_id:expr, $content:ty) => {
        #[derive(Clone, Copy, Debug)]
        pub struct $name;
        impl sealed::Sealed for $name {}
        impl ListSchema for $name {
            const ID: ListId = $list_id;
            type EntryContent = $content;
        }
        // Zero is the circuit's inline-asset sentinel, never a list id.
        const _: () = assert!($list_id as u8 != 0);
    };
}

list_schema!(Allow, ListId::Allow, ());
list_schema!(Block, ListId::Block, ());
list_schema!(Frozen, ListId::Frozen, ());
list_schema!(RingViewing, ListId::RingViewing, ());
list_schema!(Recovery, ListId::Recovery, ());
list_schema!(Reader, ListId::Reader, ());
list_schema!(Approval, ListId::Approval, ());
list_schema!(Escrow, ListId::Escrow, ());

/// An entry built through its list type, the content type cannot mismatch the list.
#[derive(Clone, Copy, Debug)]
pub struct Typed<L: ListSchema> {
    pub member: Member,
    pub state: EntryState,
    pub version: u64,
    pub content: L::EntryContent,
}

impl<L: ListSchema> Typed<L> {
    pub fn erase(&self) -> ListEntry {
        ListEntry {
            list_id: L::ID,
            member: self.member,
            state: self.state,
            version: self.version,
            content_hash: self.content.commit(),
        }
    }
}

impl<L: ListSchema> Typed<L>
where
    L::EntryContent: InlineContent,
{
    /// The typed view of an entry, `None` for a different list or a commitment
    /// no content recovers.
    pub fn from_entry(entry: &ListEntry) -> Option<Self> {
        if entry.list_id != L::ID {
            return None;
        }
        Some(Self {
            member: entry.member,
            state: entry.state,
            version: entry.version,
            content: L::EntryContent::from_commit(entry.content_hash)?,
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
        assert_eq!(Allow::WRITER, Writer::Authority);
        assert_eq!(Block::WRITER, Writer::Authority);
        assert_eq!(Frozen::WRITER, Writer::Authority);
        assert_eq!(RingViewing::WRITER, Writer::Member);
        assert_eq!(Recovery::WRITER, Writer::Member);
        assert_eq!(Reader::WRITER, Writer::Authority);
        assert_eq!(Approval::WRITER, Writer::Authority);
        assert_eq!(Escrow::WRITER, Writer::Member);
        assert_eq!(Allow::WRITER, ListId::Allow.writer());
        assert_eq!(Escrow::WRITER, ListId::Escrow.writer());
    }

    #[test]
    fn a_typed_record_erases_to_its_kind_and_recovers() {
        let typed = Typed::<Allow> {
            member: member(1),
            state: EntryState::Active,
            version: 3,
            content: (),
        };
        let entry = typed.erase();
        assert_eq!(entry.list_id, ListId::Allow);
        assert_eq!(entry.content_hash, [0u8; 32]);
        let back = Typed::<Allow>::from_entry(&entry).expect("same list_id");
        assert_eq!(back.member, typed.member);
        assert_eq!(back.version, typed.version);
        assert!(Typed::<Block>::from_entry(&entry).is_none());
    }

    #[test]
    fn inline_payloads_round_trip_through_the_commitment() {
        let cosigner = CoSignerKey([9u8; 32]);
        assert_eq!(CoSignerKey::from_commit(cosigner.commit()), Some(cosigner));
    }

    #[test]
    fn a_nonzero_commitment_on_a_unit_payload_list_reads_back_as_none() {
        let typed = Typed::<Allow> {
            member: member(2),
            state: EntryState::Active,
            version: 0,
            content: (),
        };
        let copied = typed;
        let mut entry = copied.erase();
        entry.content_hash = [1u8; 32];
        assert!(Typed::<Allow>::from_entry(&entry).is_none());
        assert!(Typed::<Allow>::from_entry(&typed.erase()).is_some());
    }
}
