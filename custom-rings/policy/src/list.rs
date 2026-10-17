use zolana_hasher::{primitives::solana_owner_identity, Hasher, HasherError, Poseidon};

use crate::MAX_SOURCES;

/// Who may change a member's bit of a list, the sole authorization axis the program gates on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Writer {
    Authority,
    Member,
}

macro_rules! lists {
    ($($variant:ident = $id:literal, $name:literal => $writer:ident,)*) => {
        /// The on-chain discriminant of a list, never the unused source slot `0`.
        #[derive(Clone, Copy, Debug, PartialEq, Eq)]
        #[repr(u8)]
        pub enum ListId {
            $($variant = $id,)*
        }

        impl ListId {
            /// Source-slot order, the id of `ALL[i]` is `i + 1`.
            pub const ALL: [Self; MAX_SOURCES] = [$(Self::$variant,)*];

            /// The program's only authorization axis for list writes.
            pub const fn writer(self) -> Writer {
                match self {
                    $(Self::$variant => Writer::$writer,)*
                }
            }

            /// Lowercase kebab-case, the one spelling of the list.
            pub const fn name(self) -> &'static str {
                match self {
                    $(Self::$variant => $name,)*
                }
            }
        }
    };
}

lists! {
    Allow = 1, "allow" => Authority,
    Block = 2, "block" => Authority,
    Frozen = 3, "frozen" => Authority,
    RingViewing = 4, "ring-viewing" => Member,
    Recovery = 5, "recovery" => Member,
    Reader = 6, "reader" => Authority,
    Approval = 7, "approval" => Authority,
    Escrow = 8, "escrow" => Member,
}

impl ListId {
    /// Index into the source map and into `ALL`.
    pub const fn slot(self) -> usize {
        self as usize - 1
    }

    const fn mask_bit(self) -> u8 {
        1 << self.slot()
    }

    /// The bit of a member record's `lists` bitmap.
    pub const fn record_bit(self) -> u64 {
        1 << self.slot()
    }

    /// The list of record bit `bit`, `None` past the lists the enum names.
    pub fn of_record_bit(bit: u32) -> Option<Self> {
        u8::try_from(bit)
            .ok()
            .and_then(|bit| Self::try_from(bit.checked_add(1)?).ok())
    }
}

/// A set of lists, bit `i` is list `i + 1`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ListSet(u8);

impl ListSet {
    pub const EMPTY: Self = Self(0);

    pub const fn of(lists: &[ListId]) -> Self {
        let mut set = Self::EMPTY;
        let mut i = 0;
        while i < lists.len() {
            set = set.union(Self::single(lists[i]));
            i += 1;
        }
        set
    }

    pub const fn single(list_id: ListId) -> Self {
        Self(list_id.mask_bit())
    }

    pub const fn from_bits(bits: u8) -> Self {
        Self(bits)
    }

    pub const fn bits(self) -> u8 {
        self.0
    }

    /// The low byte of a record's `lists` bitmap, the bits a `ListId` names.
    pub const fn record_bits(self) -> u64 {
        self.0 as u64
    }

    pub const fn contains(self, list_id: ListId) -> bool {
        self.0 & list_id.mask_bit() != 0
    }

    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    pub const fn intersects(self, other: Self) -> bool {
        self.0 & other.0 != 0
    }

    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }

    pub const fn len(self) -> usize {
        self.0.count_ones() as usize
    }

    /// In `ALL` order.
    pub fn iter(self) -> impl Iterator<Item = ListId> {
        ListId::ALL
            .into_iter()
            .filter(move |list_id| self.contains(*list_id))
    }
}

/// Every bit of a `ListSet` names a list.
const _: () = {
    assert!(MAX_SOURCES == u8::BITS as usize);
    let mut i = 0;
    while i < MAX_SOURCES {
        assert!(ListId::ALL[i].slot() == i);
        i += 1;
    }
};

impl TryFrom<u8> for ListId {
    type Error = ();

    fn try_from(value: u8) -> Result<Self, ()> {
        usize::from(value)
            .checked_sub(1)
            .and_then(|slot| Self::ALL.get(slot).copied())
            .ok_or(())
    }
}

/// Seed of the dataless PDA whose owner hash the policy statement binds.
pub const NAMESPACE_PDA_SEED: &[u8] = b"policy_records";

/// `Poseidon(0)`, the nullifier public key of the zero secret.
pub const ZERO_NULLIFIER_PK: [u8; 32] = [
    0x2a, 0x09, 0xa9, 0xfd, 0x93, 0xc5, 0x90, 0xc2, 0x6b, 0x91, 0xef, 0xfb, 0xb2, 0x49, 0x9f, 0x07,
    0xe8, 0xf7, 0xaa, 0x12, 0xe2, 0xb4, 0x94, 0x0a, 0x3a, 0xed, 0x24, 0x11, 0xcb, 0x65, 0xe1, 0x1c,
];

/// The shielded owner no transfer slot may open to, derived from the ring's namespace PDA.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ListNamespace {
    pub owner_hash: [u8; 32],
}

impl ListNamespace {
    pub fn new(pda: &[u8; 32]) -> Result<Self, HasherError> {
        let owner_pk_field = solana_owner_identity(pda)?;
        let owner_hash = Poseidon::hashv(&[&owner_pk_field, &ZERO_NULLIFIER_PK])?;
        Ok(Self { owner_hash })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zero_nullifier_pk_is_the_poseidon_of_zero() {
        assert_eq!(Poseidon::hashv(&[&[0u8; 32]]).unwrap(), ZERO_NULLIFIER_PK);
    }

    #[test]
    fn the_writer_of_every_list_is_pinned() {
        use Writer::{Authority, Member};
        assert_eq!(
            ListId::ALL.map(ListId::writer),
            [Authority, Authority, Authority, Member, Member, Authority, Authority, Member]
        );
    }

    #[test]
    fn every_slot_of_all_parses_and_nothing_else_does() {
        for (slot, list_id) in ListId::ALL.into_iter().enumerate() {
            assert_eq!(ListId::try_from(slot as u8 + 1), Ok(list_id));
            assert_eq!(list_id.slot(), slot);
            assert_eq!(list_id.record_bit(), 1 << slot);
            assert_eq!(ListId::of_record_bit(slot as u32), Some(list_id));
        }
        assert_eq!(ListId::try_from(0), Err(()));
        assert_eq!(ListId::try_from(MAX_SOURCES as u8 + 1), Err(()));
        assert_eq!(ListId::of_record_bit(MAX_SOURCES as u32), None);
        assert_eq!(ListId::of_record_bit(63), None);
    }

    #[test]
    fn a_list_set_iterates_in_slot_order_and_ignores_repeats() {
        let set = ListSet::of(&[ListId::Frozen, ListId::Allow, ListId::Frozen]);
        assert_eq!(
            set.iter().collect::<Vec<_>>(),
            [ListId::Allow, ListId::Frozen]
        );
        assert_eq!(set.len(), 2);
        assert_eq!(set.bits(), 0b0000_0101);
        assert_eq!(set.record_bits(), 0b0000_0101);
        assert!(set.contains(ListId::Frozen));
        assert!(!set.contains(ListId::Block));
        assert!(set.intersects(ListSet::single(ListId::Allow)));
        assert!(!set.intersects(ListSet::of(&[ListId::Block, ListId::Escrow])));
        assert_eq!(
            set.union(ListSet::single(ListId::Escrow)).bits(),
            0b1000_0101
        );
        assert!(ListSet::EMPTY.is_empty());
        assert_eq!(ListSet::from_bits(u8::MAX).len(), MAX_SOURCES);
    }
}
