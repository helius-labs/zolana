use thiserror::Error;

use crate::MAX_SOURCES;

/// The sole axis the program authorizes a list write on.
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
        ListSet::single(self).record_bits()
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
    /// A member's own record write, its escrow bit comes only from a registered key.
    pub const MEMBER_WRITES: Self =
        Self::written_by(Writer::Member).difference(Self::single(ListId::Escrow));
    pub const AUTHORITY_WRITES: Self = Self::written_by(Writer::Authority);

    pub const fn written_by(writer: Writer) -> Self {
        let mut set = Self::EMPTY;
        let mut i = 0;
        while i < MAX_SOURCES {
            if ListId::ALL[i].writer() as u8 == writer as u8 {
                set = set.union(Self::single(ListId::ALL[i]));
            }
            i += 1;
        }
        set
    }

    /// `None` when a record bit at or above 8 is set, no list owns it.
    pub const fn from_record_bits(bits: u64) -> Option<Self> {
        if bits > u8::MAX as u64 {
            return None;
        }
        Some(Self(bits as u8))
    }

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

    pub const fn difference(self, other: Self) -> Self {
        Self(self.0 & !other.0)
    }

    pub const fn is_subset(self, other: Self) -> bool {
        self.0 & !other.0 == 0
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ListWrite {
    set: ListSet,
    clear: ListSet,
}

#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum ListWriteError {
    #[error("a list write changes no list")]
    Empty,
    #[error("a list is both set and cleared")]
    SetAndCleared,
}

impl ListWrite {
    pub const fn new(set: ListSet, clear: ListSet) -> Result<Self, ListWriteError> {
        if set.union(clear).is_empty() {
            return Err(ListWriteError::Empty);
        }
        if set.intersects(clear) {
            return Err(ListWriteError::SetAndCleared);
        }
        Ok(Self { set, clear })
    }

    pub const fn set(self) -> ListSet {
        self.set
    }

    pub const fn clear(self) -> ListSet {
        self.clear
    }

    pub const fn mask(self) -> u64 {
        self.set.union(self.clear).record_bits()
    }

    pub const fn value(self) -> u64 {
        self.set.record_bits()
    }

    /// The signer every touched list admits, `None` across both writers or for the escrow bit.
    pub const fn writer(self) -> Option<Writer> {
        let lists = self.set.union(self.clear);
        if lists.is_subset(ListSet::MEMBER_WRITES) {
            Some(Writer::Member)
        } else if lists.is_subset(ListSet::AUTHORITY_WRITES) {
            Some(Writer::Authority)
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn record_writes_split_the_lists_between_the_member_and_the_authority() {
        assert_eq!(
            ListSet::MEMBER_WRITES,
            ListSet::of(&[ListId::RingViewing, ListId::Recovery])
        );
        assert_eq!(
            ListSet::AUTHORITY_WRITES,
            ListSet::of(&[
                ListId::Allow,
                ListId::Block,
                ListId::Frozen,
                ListId::Reader,
                ListId::Approval,
            ])
        );
        assert!(!ListSet::MEMBER_WRITES.intersects(ListSet::AUTHORITY_WRITES));
        assert!(!ListSet::MEMBER_WRITES
            .union(ListSet::AUTHORITY_WRITES)
            .contains(ListId::Escrow));
    }

    #[test]
    fn a_list_write_masks_both_sets_and_values_only_the_set() {
        let write = ListWrite::new(
            ListSet::single(ListId::Allow),
            ListSet::single(ListId::Block),
        )
        .unwrap();
        assert_eq!((write.mask(), write.value()), (0b11, 0b01));
        assert_eq!(write.writer(), Some(Writer::Authority));
        let member = ListWrite::new(ListSet::EMPTY, ListSet::single(ListId::Recovery)).unwrap();
        assert_eq!((member.mask(), member.value()), (0b1_0000, 0));
        assert_eq!(member.writer(), Some(Writer::Member));
    }

    #[test]
    fn a_list_write_refuses_no_list_both_sets_and_mixed_or_escrow_writers() {
        assert_eq!(
            ListWrite::new(ListSet::EMPTY, ListSet::EMPTY),
            Err(ListWriteError::Empty)
        );
        let allow = ListSet::single(ListId::Allow);
        assert_eq!(
            ListWrite::new(allow, allow),
            Err(ListWriteError::SetAndCleared)
        );
        let mixed = ListWrite::new(allow, ListSet::single(ListId::Recovery)).unwrap();
        assert_eq!(mixed.writer(), None);
        let escrow = ListWrite::new(ListSet::single(ListId::Escrow), ListSet::EMPTY).unwrap();
        assert_eq!(escrow.writer(), None);
    }

    #[test]
    fn record_bits_past_the_named_lists_have_no_set() {
        assert_eq!(
            ListSet::from_record_bits(0xff),
            Some(ListSet::from_bits(0xff))
        );
        assert_eq!(ListSet::from_record_bits(0x100), None);
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
