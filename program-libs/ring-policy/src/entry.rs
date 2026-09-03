use zolana_hasher::{
    hash_chain::create_hash_chain_from_slice, primitives::hash_bytes, Hasher, HasherError, Poseidon,
};
use zolana_interface::{ADDRESS_DOMAIN, SOL_ASSET_FIELD, UTXO_DOMAIN};

use crate::{
    field_u16, field_u64, field_u8, Member, MAX_SOURCES, POLICY_ADDRESS_DOMAIN,
    POLICY_RECORD_DOMAIN,
};

/// The on-chain discriminant of a list, never `0` (the circuit reserves it as the inline-asset sentinel).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum ListId {
    Allow = 1,
    Block = 2,
    Frozen = 3,
    RingViewing = 4,
    Recovery = 5,
    Reader = 6,
    Approval = 7,
    Escrow = 8,
}

/// Who may mutate a list, the sole authorization axis the program gates on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Writer {
    Authority,
    Member,
}

impl ListId {
    /// Source-slot order, the id of `ALL[i]` is `i + 1`.
    pub const ALL: [Self; MAX_SOURCES] = [
        Self::Allow,
        Self::Block,
        Self::Frozen,
        Self::RingViewing,
        Self::Recovery,
        Self::Reader,
        Self::Approval,
        Self::Escrow,
    ];

    /// The single source of truth the program and every `ListSchema` impl read.
    /// Exhaustive on purpose, a new list must declare its writer to compile.
    pub const fn writer(self) -> Writer {
        match self {
            Self::RingViewing | Self::Recovery | Self::Escrow => Writer::Member,
            Self::Allow | Self::Block | Self::Frozen | Self::Reader | Self::Approval => {
                Writer::Authority
            }
        }
    }

    /// Index into the source map and into `ALL`.
    pub const fn slot(self) -> usize {
        self as usize - 1
    }

    const fn mask_bit(self) -> u8 {
        1 << self.slot()
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

/// Seed of the dataless PDA whose signature owns every entry of the ring.
pub const NAMESPACE_PDA_SEED: &[u8] = b"policy_records";

/// Published entry length, the complete preimage of its hashes.
pub const LIST_ENTRY_LEN: usize = 74;
/// The plaintext output-data envelope, tag byte and `u32` length before the
/// content.
pub const ENTRY_OUTPUT_DATA_LEN: usize = 5 + LIST_ENTRY_LEN;

/// Active or Cleared, removal writes Cleared, no version is ever deleted.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum EntryState {
    Active = 1,
    Cleared = 2,
}

impl TryFrom<u8> for EntryState {
    type Error = ();

    fn try_from(value: u8) -> Result<Self, ()> {
        Ok(match value {
            1 => Self::Active,
            2 => Self::Cleared,
            _ => return Err(()),
        })
    }
}

/// The zero nullifier secret makes every entry nullifier publicly computable,
/// spending still needs the PDA signature.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ListNamespace {
    pub owner_hash: [u8; 32],
}

impl ListNamespace {
    pub fn new(pda: &[u8; 32]) -> Result<Self, HasherError> {
        let owner_pk_field = hash_bytes(pda)?;
        let nullifier_pk = Poseidon::hashv(&[&[0u8; 32]])?;
        let owner_hash = Poseidon::hashv(&[&owner_pk_field, &nullifier_pk])?;
        Ok(Self { owner_hash })
    }

    /// The address slot commitment, its blinding is the entry seed.
    pub fn address_utxo_hash(&self, seed: &[u8; 32]) -> Result<[u8; 32], HasherError> {
        let zero = [0u8; 32];
        let ring_hash = Poseidon::hashv(&[&zero, &zero])?;
        let owner_utxo_hash = Poseidon::hashv(&[&self.owner_hash, seed])?;
        Poseidon::hashv(&[
            &field_u16(ADDRESS_DOMAIN),
            &zero,
            &zero,
            &zero,
            &ring_hash,
            &owner_utxo_hash,
        ])
    }

    /// Deterministic, the nullifier tree admits one entry lineage per
    /// `(list_id, member)`.
    pub fn address(&self, list_id: ListId, member: &Member) -> Result<[u8; 32], HasherError> {
        let seed = entry_seed(list_id, member)?;
        entry_nullifier(&self.address_utxo_hash(&seed)?, &seed)
    }
}

/// One address lineage per `(list_id, member)` pair under one namespace.
pub fn entry_seed(list_id: ListId, member: &Member) -> Result<[u8; 32], HasherError> {
    Poseidon::hashv(&[
        &POLICY_ADDRESS_DOMAIN,
        &field_u8(list_id as u8),
        member.as_bytes(),
    ])
}

/// The blinding is the version, a re-added member never repeats a commitment
/// or a nullifier.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ListEntry {
    pub list_id: ListId,
    pub member: Member,
    pub state: EntryState,
    pub version: u64,
    pub content_hash: [u8; 32],
}

impl ListEntry {
    /// The leaf preimage, binds the entry to its derived address.
    pub fn data_hash(&self, address: &[u8; 32]) -> Result<[u8; 32], HasherError> {
        Poseidon::hashv(&[
            &POLICY_RECORD_DOMAIN,
            address,
            &field_u8(self.list_id as u8),
            self.member.as_bytes(),
            &field_u8(self.state as u8),
            &field_u64(self.version),
            &self.content_hash,
        ])
    }

    pub fn blinding(&self) -> [u8; 32] {
        field_u64(self.version)
    }

    /// Takes the content of [`ListEntry::to_output_data`], without its envelope.
    pub fn from_entry_bytes(content: &[u8]) -> Option<Self> {
        let content: &[u8; LIST_ENTRY_LEN] = content.try_into().ok()?;
        Some(Self {
            list_id: ListId::try_from(content[0]).ok()?,
            member: Member::from_bytes(content[1..33].try_into().ok()?).ok()?,
            state: EntryState::try_from(content[33]).ok()?,
            version: u64::from_le_bytes(content[34..42].try_into().ok()?),
            content_hash: content[42..74].try_into().ok()?,
        })
    }

    /// The published plaintext content, discovery re-derives `data_hash` from
    /// it and compares against the on-chain leaf before trusting it.
    pub fn to_output_data(&self) -> [u8; ENTRY_OUTPUT_DATA_LEN] {
        let mut content = [0u8; ENTRY_OUTPUT_DATA_LEN];
        content[1..5].copy_from_slice(&(LIST_ENTRY_LEN as u32).to_le_bytes());
        content[5] = self.list_id as u8;
        content[6..38].copy_from_slice(self.member.as_bytes());
        content[38] = self.state as u8;
        content[39..47].copy_from_slice(&self.version.to_le_bytes());
        content[47..79].copy_from_slice(&self.content_hash);
        content
    }

    /// The canonical SPP UTXO hash, entries are indistinguishable from value UTXOs.
    pub fn utxo_hash(
        &self,
        owner: &ListNamespace,
        address: &[u8; 32],
    ) -> Result<[u8; 32], HasherError> {
        let zero = [0u8; 32];
        let ring_hash = Poseidon::hashv(&[&zero, &zero])?;
        let owner_utxo_hash = Poseidon::hashv(&[&owner.owner_hash, &self.blinding()])?;
        Poseidon::hashv(&[
            &field_u16(UTXO_DOMAIN),
            &SOL_ASSET_FIELD,
            &zero,
            &self.data_hash(address)?,
            &ring_hash,
            &owner_utxo_hash,
        ])
    }
}

/// Publicly computable, the nullifier secret is zero for every entry.
pub fn entry_nullifier(utxo_hash: &[u8; 32], blinding: &[u8; 32]) -> Result<[u8; 32], HasherError> {
    Poseidon::hashv(&[utxo_hash, blinding, &[0u8; 32]])
}

/// `private_tx_hash` of an entry mutation, one input slot and one output slot.
pub fn mutation_private_tx_hash(
    input_hash: [u8; 32],
    output_hash: [u8; 32],
    address_hash: [u8; 32],
    external_data_hash: &[u8; 32],
) -> Result<[u8; 32], HasherError> {
    let input_chain = create_hash_chain_from_slice(&[input_hash])?;
    let output_chain = create_hash_chain_from_slice(&[output_hash])?;
    let address_chain = create_hash_chain_from_slice(&[address_hash])?;
    Poseidon::hashv(&[
        &input_chain,
        &output_chain,
        &address_chain,
        external_data_hash,
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn owner() -> ListNamespace {
        ListNamespace::new(&[11u8; 32]).unwrap()
    }

    fn member(byte: u8) -> Member {
        Member::owner_tag(&[byte; 32]).unwrap()
    }

    #[test]
    fn every_slot_of_all_parses_and_nothing_else_does() {
        for (slot, list_id) in ListId::ALL.into_iter().enumerate() {
            assert_eq!(ListId::try_from(slot as u8 + 1), Ok(list_id));
            assert_eq!(list_id.slot(), slot);
        }
        assert_eq!(ListId::try_from(0), Err(()));
        assert_eq!(ListId::try_from(MAX_SOURCES as u8 + 1), Err(()));
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

    #[test]
    fn the_address_is_deterministic_in_kind_and_member() {
        let owner = owner();
        let a = owner.address(ListId::Block, &member(1)).unwrap();
        assert_eq!(a, owner.address(ListId::Block, &member(1)).unwrap());
        assert_ne!(a, owner.address(ListId::Frozen, &member(1)).unwrap());
        assert_ne!(a, owner.address(ListId::Block, &member(2)).unwrap());
        assert_ne!(
            a,
            ListNamespace::new(&[12u8; 32])
                .unwrap()
                .address(ListId::Block, &member(1))
                .unwrap()
        );
    }

    #[test]
    fn state_and_version_move_the_commitment_but_not_the_address() {
        let owner = owner();
        let entry = ListEntry {
            list_id: ListId::Block,
            member: member(1),
            state: EntryState::Active,
            version: 0,
            content_hash: [0u8; 32],
        };
        let address = owner.address(entry.list_id, &entry.member).unwrap();
        let active = entry.utxo_hash(&owner, &address).unwrap();
        let cleared = ListEntry {
            state: EntryState::Cleared,
            version: 1,
            ..entry
        };
        assert_ne!(active, cleared.utxo_hash(&owner, &address).unwrap());
        assert_eq!(
            address,
            owner.address(cleared.list_id, &cleared.member).unwrap()
        );
    }

    #[test]
    fn the_payload_round_trips_through_the_published_envelope() {
        let entry = ListEntry {
            list_id: ListId::Frozen,
            member: member(5),
            state: EntryState::Cleared,
            version: 7,
            content_hash: [4u8; 32],
        };
        let encoded = entry.to_output_data();
        assert_eq!(ListEntry::from_entry_bytes(&encoded[5..]), Some(entry));
        assert_eq!(ListEntry::from_entry_bytes(&encoded), None);
    }

    #[test]
    fn version_uniqueness_separates_nullifiers_of_equal_states() {
        let owner = owner();
        let entry = ListEntry {
            list_id: ListId::Allow,
            member: member(3),
            state: EntryState::Active,
            version: 0,
            content_hash: [0u8; 32],
        };
        let address = owner.address(entry.list_id, &entry.member).unwrap();
        let re_added = ListEntry {
            version: 2,
            ..entry
        };
        let first = entry.utxo_hash(&owner, &address).unwrap();
        let second = re_added.utxo_hash(&owner, &address).unwrap();
        assert_ne!(
            entry_nullifier(&first, &entry.blinding()).unwrap(),
            entry_nullifier(&second, &re_added.blinding()).unwrap()
        );
    }
}
